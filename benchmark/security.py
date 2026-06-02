"""Security benchmark orchestrator.

Layout under ``benchmark/scenarios/security/`` — one directory per test:

    <test_id>/
        meta.toml      # category, severity, CVE, server config
        payload/       # files served by evil_server.py in static mode
        oracle.py      # optional; default oracle just checks for /canary/PWNED_<id>
        build.py       # optional; regenerates payload/ from scratch

For each test we start a fresh ``evil_server.py`` subprocess on a fixed
port, run each tool's docker image with an extra ``/canary`` volume
mount, then call the oracle to decide PASS/FAIL/TIMEOUT/ERROR.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import logging
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from benchmark import config
from benchmark.config import (
    BENCHMARK_DIR,
    PROJECT_ROOT,
    load_tools,
)
from benchmark.docker import build_image, get_tool_version

logger = logging.getLogger(__name__)

SCENARIOS_DIR = BENCHMARK_DIR / 'scenarios' / 'security'
RESULTS_PATH = BENCHMARK_DIR / 'results' / 'security.json'
DISCLOSURES_PATH = BENCHMARK_DIR / 'disclosures.toml'
PUBLIC_DATA_PATH = PROJECT_ROOT / 'docs' / 'public' / 'data' / 'security.json'
EVIL_SERVER_PORT = 8080
EVIL_SERVER_HOST = '127.0.0.1'


class Verdict(StrEnum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    TIMEOUT = 'TIMEOUT'
    ERROR = 'ERROR'


@dataclass
class TestMeta:
    __test__ = False  # don't collect as a pytest test class

    id: str
    category: str  # "RCE" | "AFW" | "Info" | "CVE"
    severity: str  # "H" | "M" | "L"
    description: str
    cve: str | None = None
    server_mode: str = 'static'  # "static" | "redirect"
    redirect_to: str | None = None
    # When set, a second evil_server runs in callback mode on this port
    # for the duration of the test. Used by C3 (SSRF): the primary
    # server redirects to http://127.0.0.1:<callback_port>/, and a hit
    # on the callback port writes the canary.
    callback_port: int | None = None
    callback_canary: str | None = None  # filename under canary_dir

    # Files to plant in canary_dir before each tool run.  Used by tests
    # whose primitive is "read-side": the malicious server can coerce
    # the pillager into reading these files (via path traversal etc.),
    # so we plant the bait beforehand.  Keys are filenames under
    # canary_dir; values are the bait content.
    seed_files: dict = field(default_factory=dict)

    # When set, the primary static evil_server gets ``--watch-regex`` and
    # ``--watch-canary`` flags so any incoming request whose URL path
    # matches the regex creates ``canary_dir/<watch_canary>`` — turning
    # a side-channel HTTP request into a canary the default oracle can
    # detect.  Used by D1: pillager reads bait, extracts hex, emits a
    # GET for that hex's object path, regex matches, canary appears.
    watch_regex: str | None = None
    watch_canary: str | None = None


@dataclass
class ToolRunResult:
    verdict: Verdict
    evidence: str = ''
    duration: float = 0.0
    exit_code: int | None = None
    stderr_tail: str = ''


@dataclass
class TestResult:
    __test__ = False

    meta: TestMeta
    runs: dict[str, ToolRunResult] = field(default_factory=dict)


@dataclass
class SecurityReport:
    generated_at: str
    git_commit: str
    tools: dict[str, dict[str, str]]  # tool_id -> {name, url, version}
    tests: list[TestResult]

    def to_dict(self) -> dict:
        return {
            'schema_version': 1,
            'generated_at': self.generated_at,
            'git_commit': self.git_commit,
            'tools': self.tools,
            'tests': [
                {
                    'id': t.meta.id,
                    'category': t.meta.category,
                    'severity': t.meta.severity,
                    'description': t.meta.description,
                    'cve': t.meta.cve,
                    'results': {
                        tid: dataclasses.asdict(r) | {'verdict': r.verdict.value}
                        for tid, r in t.runs.items()
                    },
                }
                for t in self.tests
            ],
        }


# ---------------------------------------------------------------------------
# Discovery & payload preparation
# ---------------------------------------------------------------------------


def discover_tests(
    filter_ids: list[str] | None = None, filter_category: str | None = None
) -> list[TestMeta]:
    tests: list[TestMeta] = []
    if not SCENARIOS_DIR.is_dir():
        return tests
    for child in sorted(SCENARIOS_DIR.iterdir()):
        if not child.is_dir() or child.name.startswith('_'):
            continue
        meta_path = child / 'meta.toml'
        if not meta_path.exists():
            logger.warning('Skipping %s — no meta.toml', child.name)
            continue
        with open(meta_path, 'rb') as f:
            raw = tomllib.load(f)
        meta = TestMeta(
            id=child.name,
            category=raw.get('category', 'RCE'),
            severity=raw.get('severity', 'M'),
            description=raw.get('description', ''),
            cve=raw.get('cve'),
            server_mode=raw.get('server_mode', 'static'),
            redirect_to=raw.get('redirect_to'),
            callback_port=raw.get('callback_port'),
            callback_canary=raw.get('callback_canary'),
            seed_files=raw.get('seed_files', {}) or {},
            watch_regex=raw.get('watch_regex'),
            watch_canary=raw.get('watch_canary'),
        )
        if filter_ids and meta.id not in filter_ids:
            continue
        if filter_category and meta.category != filter_category:
            continue
        tests.append(meta)
    return tests


def ensure_payload(test_id: str) -> Path:
    """Run build.py if present and payload/.git is missing.

    Returns the absolute payload directory path.
    """
    test_dir = SCENARIOS_DIR / test_id
    payload = test_dir / 'payload'
    build = test_dir / 'build.py'
    needs_build = build.exists() and not any(payload.rglob('*'))
    if needs_build:
        logger.info('Building payload for %s', test_id)
        subprocess.run(
            [sys.executable, str(build)],
            cwd=test_dir,
            check=True,
        )
    return payload


# ---------------------------------------------------------------------------
# Evil server lifecycle
# ---------------------------------------------------------------------------


def _wait_port(port: int, host: str = EVIL_SERVER_HOST, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _wait_port_release(port: int, host: str = EVIL_SERVER_HOST, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                time.sleep(0.1)
        except OSError:
            return


def start_evil_server(
    meta: TestMeta,
    payload: Path,
    *,
    access_log: Path | None = None,
    watch_canary: Path | None = None,
) -> subprocess.Popen:
    cmd = [
        sys.executable,
        str(BENCHMARK_DIR / 'evil_server.py'),
        '--mode',
        meta.server_mode,
        '--host',
        EVIL_SERVER_HOST,
        '--port',
        str(EVIL_SERVER_PORT),
    ]
    if meta.server_mode == 'static':
        cmd.extend(['--payload', str(payload.resolve())])
        if access_log:
            cmd.extend(['--access-log', str(access_log.resolve())])
        if meta.watch_regex and watch_canary:
            cmd.extend(
                [
                    '--watch-regex',
                    meta.watch_regex,
                    '--watch-canary',
                    str(watch_canary.resolve()),
                ]
            )
    elif meta.server_mode == 'redirect':
        if not meta.redirect_to:
            raise ValueError(f'{meta.id}: redirect mode requires redirect_to')
        cmd.extend(['--redirect-to', meta.redirect_to])

    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if not _wait_port(EVIL_SERVER_PORT):
        proc.terminate()
        proc.wait(timeout=2)
        raise RuntimeError(f'evil-server failed to bind {EVIL_SERVER_HOST}:{EVIL_SERVER_PORT}')
    return proc


def seed_canary_dir(meta: TestMeta, canary_dir: Path) -> None:
    """Plant bait files for read-side tests into canary_dir.

    Each ``seed_files[name] = text`` entry creates ``canary_dir/<name>``
    with that text content before the pillager runs.  Existing files
    are overwritten so every tool gets identical bait.
    """
    for name, content in meta.seed_files.items():
        path = canary_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def stop_evil_server(proc: subprocess.Popen, port: int = EVIL_SERVER_PORT) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    _wait_port_release(port)


def start_callback_server(port: int, canary_file: Path) -> subprocess.Popen:
    """Start a sidecar callback listener. Used by SSRF-style tests."""
    cmd = [
        sys.executable,
        str(BENCHMARK_DIR / 'evil_server.py'),
        '--mode',
        'callback',
        '--host',
        EVIL_SERVER_HOST,
        '--port',
        str(port),
        '--canary-file',
        str(canary_file.resolve()),
    ]
    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if not _wait_port(port):
        proc.terminate()
        proc.wait(timeout=2)
        raise RuntimeError(f'callback server failed to bind {EVIL_SERVER_HOST}:{port}')
    return proc


# ---------------------------------------------------------------------------
# Oracle (custom or default)
# ---------------------------------------------------------------------------


def _load_oracle(test_id: str):
    """Return a check(output_dir, canary_dir, proc) -> Verdict, evidence."""
    custom = SCENARIOS_DIR / test_id / 'oracle.py'
    if custom.exists():
        spec = importlib.util.spec_from_file_location(f'oracle_{test_id}', custom)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'check'):
            return mod.check
    return _default_oracle(test_id)


def _default_oracle(test_id: str):
    """Canary-file oracle: FAIL iff /canary/PWNED_<test_id> exists."""
    canary_name = f'PWNED_{test_id.split("_", 1)[0]}'

    def check(output_dir: Path, canary_dir: Path, proc) -> tuple[Verdict, str]:
        canary = canary_dir / canary_name
        if canary.exists():
            return Verdict.FAIL, f'{canary_name} created in canary dir'
        return Verdict.PASS, ''

    return check


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------


def run_tool_on_test(
    tool_id: str,
    meta: TestMeta,
    url: str,
    output_dir: Path,
    canary_dir: Path,
) -> ToolRunResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    canary_dir.mkdir(parents=True, exist_ok=True)
    image = f'benchmark-{tool_id}'
    cmd = [
        'docker',
        'run',
        '--rm',
        '--network',
        'host',
        '-v',
        f'{output_dir.resolve()}:/output',
        '-v',
        f'{canary_dir.resolve()}:/canary',
        image,
        url,
        '/output',
    ]
    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            timeout=config.TOOL_TIMEOUT,
            capture_output=True,
            text=True,
        )
        duration = round(time.monotonic() - start, 2)
        oracle = _load_oracle(meta.id)
        verdict, evidence = oracle(output_dir, canary_dir, proc)
        return ToolRunResult(
            verdict=verdict,
            evidence=evidence,
            duration=duration,
            exit_code=proc.returncode,
            stderr_tail='\n'.join((proc.stderr or '').splitlines()[-5:]),
        )
    except subprocess.TimeoutExpired:
        duration = round(time.monotonic() - start, 2)
        return ToolRunResult(
            verdict=Verdict.TIMEOUT,
            evidence=f'Exceeded {config.TOOL_TIMEOUT}s',
            duration=duration,
            exit_code=-1,
        )
    except Exception as exc:
        duration = round(time.monotonic() - start, 2)
        return ToolRunResult(
            verdict=Verdict.ERROR,
            evidence=repr(exc),
            duration=duration,
            exit_code=-1,
        )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_security_suite(
    tool_ids: list[str] | None = None,
    test_ids: list[str] | None = None,
    category: str | None = None,
) -> SecurityReport:
    all_tools = load_tools()
    tools = {tid: t for tid, t in all_tools.items() if (not tool_ids or tid in tool_ids)}
    if not tools:
        raise SystemExit('No matching tools (after --tools filter)')

    logger.info('Building tool images ...')
    for tid in list(tools):
        try:
            build_image(tid)
            tools[tid].version = get_tool_version(tid)
        except FileNotFoundError:
            logger.warning('  %s: no Dockerfile, skipping', tid)
            del tools[tid]

    tests = discover_tests(filter_ids=test_ids, filter_category=category)
    if not tests:
        raise SystemExit('No matching tests')
    logger.info('Discovered %d tests: %s', len(tests), [t.id for t in tests])

    results: list[TestResult] = []
    playground = PROJECT_ROOT / 'playground' / 'security'
    if playground.exists():
        shutil.rmtree(playground)

    for meta in tests:
        logger.info('=' * 60)
        logger.info('Test: %s (%s, severity=%s)', meta.id, meta.category, meta.severity)
        logger.info('=' * 60)
        try:
            payload = ensure_payload(meta.id)
        except subprocess.CalledProcessError as exc:
            logger.error('  build.py failed for %s: %s', meta.id, exc)
            runs = {
                tid: ToolRunResult(Verdict.ERROR, evidence=f'payload build failed: {exc}')
                for tid in tools
            }
            results.append(TestResult(meta=meta, runs=runs))
            continue

        # evil_server is restarted per tool so that per-tool state
        # (watch canary, access log) lives under each tool's canary_dir.
        # Cost is ~100ms per tool — negligible vs the per-tool runtime.
        runs: dict[str, ToolRunResult] = {}
        for tid in tools:
            output_dir = playground / meta.id / tid / 'output'
            canary_dir = playground / meta.id / tid / 'canary'
            canary_dir.mkdir(parents=True, exist_ok=True)
            seed_canary_dir(meta, canary_dir)
            logger.info('  %s ...', tid)
            watch_canary_path = canary_dir / meta.watch_canary if meta.watch_canary else None
            access_log_path = canary_dir / 'access.log'
            access_log_path.write_text('')
            server = start_evil_server(
                meta,
                payload,
                access_log=access_log_path,
                watch_canary=watch_canary_path,
            )
            try:
                # Per-tool callback sidecar (for SSRF tests like C3).
                callback = None
                if meta.callback_port and meta.callback_canary:
                    callback = start_callback_server(
                        meta.callback_port,
                        canary_dir / meta.callback_canary,
                    )
                try:
                    run = run_tool_on_test(
                        tid,
                        meta,
                        url=f'http://{EVIL_SERVER_HOST}:{EVIL_SERVER_PORT}/',
                        output_dir=output_dir,
                        canary_dir=canary_dir,
                    )
                finally:
                    if callback:
                        stop_evil_server(callback, port=meta.callback_port)
                logger.info('    -> %s (%s)', run.verdict.value, run.evidence or run.duration)
                runs[tid] = run
            finally:
                stop_evil_server(server)

        results.append(TestResult(meta=meta, runs=runs))

    return SecurityReport(
        generated_at=datetime.now(UTC).isoformat(timespec='seconds'),
        git_commit=_git_commit(),
        tools={
            tid: {'name': t.name, 'url': t.url, 'version': t.version} for tid, t in tools.items()
        },
        tests=results,
    )


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'],
            cwd=PROJECT_ROOT,
            text=True,
        )
        return out.strip()
    except Exception:
        return 'unknown'


def write_report(report: SecurityReport, path: Path = RESULTS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report.to_dict(), f, indent=2, sort_keys=False)


def _load_disclosures(path: Path = DISCLOSURES_PATH) -> dict:
    """Read the disclosure tracker. Returns {} if the file is missing,
    so the orchestrator works for fresh checkouts without one."""
    import tomllib

    if not path.exists():
        return {'label': {}, 'finding': []}
    with open(path, 'rb') as f:
        return tomllib.load(f)


def redact_for_publication(report: SecurityReport | dict, disclosures: dict) -> dict:
    """Build the JSON that goes to docs/public/data/security.json.

    The only redaction applied is *tool-name* anonymization: any tool
    listed in disclosures' [label] table is renamed to its opaque label
    (Tool A, Tool B, ...) and its URL / version are stripped before
    publication. GitHacker (the project under test) is never redacted.

    Per-test verdicts (PASS / FAIL) are published in full. The test
    corpus itself is public information (justinsteven 2022, Driver Tom
    2021, Git CVE feed), so hiding which test a tool failed leaks no
    additional vulnerability detail — the tool-name anonymization is
    the actual protection until coordinated disclosure completes.

    The function also embeds a public-safe view of the disclosure
    tracker so the /security page can render it without needing the
    internal-id -> label mapping client-side.
    """
    labels = disclosures.get('label', {}) or {}
    findings = disclosures.get('finding', []) or []

    # A finding is still under coordinated disclosure if we haven't
    # contacted the upstream maintainer yet (status == "confirmed").
    # Until the vendor knows, the tool name on the public page stays
    # anonymous; the verdict itself is published.
    PRE_DISCLOSURE_STATUS = 'confirmed'

    out = report.to_dict() if isinstance(report, SecurityReport) else report

    # Remap tool identifiers so the dashboard's per-tool columns and the
    # results dicts inside each test agree.
    id_map: dict[str, str] = {}
    public_tools: dict[str, dict] = {}
    for tid, tool in out['tools'].items():
        if tid == 'githacker':
            id_map[tid] = tid
            public_tools[tid] = tool
            continue
        label = labels.get(tid)
        if label:
            # "Tool A" -> "tool_a" as the public-side identifier.
            new_id = label.lower().replace(' ', '_')
            id_map[tid] = new_id
            public_tools[new_id] = {'name': label, 'url': '', 'version': '—'}
        else:
            id_map[tid] = tid
            public_tools[tid] = tool

    out['tools'] = public_tools

    # Rewrite each test's per-tool results: remap tool ids to public
    # labels.  All verdicts ship — the matrix is public.
    for test in out['tests']:
        new_results: dict = {}
        for tid, res in test['results'].items():
            new_results[id_map.get(tid, tid)] = res
        test['results'] = new_results

    # Build the public disclosure list — every finding ships, with the
    # tool name already mapped to its anonymous label until the status
    # progresses to "disclosed".  pending_count tells the page how many
    # findings still hide behind an anonymous label.
    public_findings = []
    pending_count = 0
    for f in findings:
        if f.get('status') == PRE_DISCLOSURE_STATUS:
            pending_count += 1
        tid = f.get('tool', '')
        public_label = 'GitHacker' if tid == 'githacker' else labels.get(tid, 'Unknown')
        public_findings.append(
            {
                'id': f.get('id', ''),
                'test': f.get('test', ''),
                'tool': public_label,
                'severity': f.get('severity', ''),
                'status': f.get('status', ''),
                'first_observed': f.get('first_observed', ''),
                'reported_at': f.get('reported_at', ''),
                'patched_at': f.get('patched_at', ''),
                'cve': f.get('cve', ''),
                'notes': f.get('notes', ''),
            }
        )
    out['disclosures'] = public_findings
    # Kept under the same key for backward compatibility with the page;
    # semantics is now "findings whose tool name is still anonymous".
    out['embargo_count'] = pending_count

    return out


def write_public_report(report: SecurityReport, path: Path = PUBLIC_DATA_PATH) -> None:
    """Write the redacted JSON to docs/public/data/security.json."""
    disclosures = _load_disclosures()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(redact_for_publication(report, disclosures), f, indent=2, sort_keys=False)
        f.write('\n')
    logger.info('Wrote %s', path)


def print_summary(report: SecurityReport) -> None:
    tool_ids = list(report.tools)
    header = ['Test', 'Severity', 'CVE'] + tool_ids
    rows = [header]
    for t in report.tests:
        row = [t.meta.id, t.meta.severity, t.meta.cve or '-']
        for tid in tool_ids:
            r = t.runs.get(tid)
            row.append(r.verdict.value if r else '?')
        rows.append(row)

    widths = [max(len(str(r[i])) for r in rows) for i in range(len(header))]
    sep = '  '
    for row in rows:
        print(sep.join(str(c).ljust(widths[i]) for i, c in enumerate(row)))

    # Per-tool aggregate
    print()
    for tid in tool_ids:
        total = len(report.tests)
        passed = sum(
            1 for t in report.tests if t.runs.get(tid) and t.runs[tid].verdict == Verdict.PASS
        )
        score = (passed / total * 100) if total else 0
        print(f'  {tid}: {passed}/{total} PASS ({score:.1f}%)')
