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

SCENARIOS_DIR = BENCHMARK_DIR / "scenarios" / "security"
RESULTS_PATH = BENCHMARK_DIR / "results" / "security.json"
EVIL_SERVER_PORT = 8080
EVIL_SERVER_HOST = "127.0.0.1"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class TestMeta:
    __test__ = False  # don't collect as a pytest test class

    id: str
    category: str  # "RCE" | "AFW" | "Info" | "CVE"
    severity: str  # "H" | "M" | "L"
    description: str
    cve: str | None = None
    server_mode: str = "static"  # "static" | "redirect"
    redirect_to: str | None = None


@dataclass
class ToolRunResult:
    verdict: Verdict
    evidence: str = ""
    duration: float = 0.0
    exit_code: int | None = None
    stderr_tail: str = ""


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
            "schema_version": 1,
            "generated_at": self.generated_at,
            "git_commit": self.git_commit,
            "tools": self.tools,
            "tests": [
                {
                    "id": t.meta.id,
                    "category": t.meta.category,
                    "severity": t.meta.severity,
                    "description": t.meta.description,
                    "cve": t.meta.cve,
                    "results": {
                        tid: dataclasses.asdict(r) | {"verdict": r.verdict.value}
                        for tid, r in t.runs.items()
                    },
                }
                for t in self.tests
            ],
        }


# ---------------------------------------------------------------------------
# Discovery & payload preparation
# ---------------------------------------------------------------------------

def discover_tests(filter_ids: list[str] | None = None,
                   filter_category: str | None = None) -> list[TestMeta]:
    tests: list[TestMeta] = []
    if not SCENARIOS_DIR.is_dir():
        return tests
    for child in sorted(SCENARIOS_DIR.iterdir()):
        if not child.is_dir() or child.name.startswith("_"):
            continue
        meta_path = child / "meta.toml"
        if not meta_path.exists():
            logger.warning("Skipping %s — no meta.toml", child.name)
            continue
        with open(meta_path, "rb") as f:
            raw = tomllib.load(f)
        meta = TestMeta(
            id=child.name,
            category=raw.get("category", "RCE"),
            severity=raw.get("severity", "M"),
            description=raw.get("description", ""),
            cve=raw.get("cve"),
            server_mode=raw.get("server_mode", "static"),
            redirect_to=raw.get("redirect_to"),
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
    payload = test_dir / "payload"
    build = test_dir / "build.py"
    needs_build = build.exists() and not any(payload.rglob("*"))
    if needs_build:
        logger.info("Building payload for %s", test_id)
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


def start_evil_server(meta: TestMeta, payload: Path) -> subprocess.Popen:
    cmd = [
        sys.executable,
        str(BENCHMARK_DIR / "evil_server.py"),
        "--mode", meta.server_mode,
        "--host", EVIL_SERVER_HOST,
        "--port", str(EVIL_SERVER_PORT),
    ]
    if meta.server_mode == "static":
        cmd.extend(["--payload", str(payload.resolve())])
    elif meta.server_mode == "redirect":
        if not meta.redirect_to:
            raise ValueError(f"{meta.id}: redirect mode requires redirect_to")
        cmd.extend(["--redirect-to", meta.redirect_to])

    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if not _wait_port(EVIL_SERVER_PORT):
        proc.terminate()
        proc.wait(timeout=2)
        raise RuntimeError(f"evil-server failed to bind {EVIL_SERVER_HOST}:{EVIL_SERVER_PORT}")
    return proc


def stop_evil_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    _wait_port_release(EVIL_SERVER_PORT)


# ---------------------------------------------------------------------------
# Oracle (custom or default)
# ---------------------------------------------------------------------------

def _load_oracle(test_id: str):
    """Return a check(output_dir, canary_dir, proc) -> Verdict, evidence."""
    custom = SCENARIOS_DIR / test_id / "oracle.py"
    if custom.exists():
        spec = importlib.util.spec_from_file_location(f"oracle_{test_id}", custom)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "check"):
            return mod.check
    return _default_oracle(test_id)


def _default_oracle(test_id: str):
    """Canary-file oracle: FAIL iff /canary/PWNED_<test_id> exists."""
    canary_name = f"PWNED_{test_id.split('_', 1)[0]}"

    def check(output_dir: Path, canary_dir: Path, proc) -> tuple[Verdict, str]:
        canary = canary_dir / canary_name
        if canary.exists():
            return Verdict.FAIL, f"{canary_name} created in canary dir"
        return Verdict.PASS, ""

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
    image = f"benchmark-{tool_id}"
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{output_dir.resolve()}:/output",
        "-v", f"{canary_dir.resolve()}:/canary",
        image,
        url, "/output",
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
            stderr_tail="\n".join((proc.stderr or "").splitlines()[-5:]),
        )
    except subprocess.TimeoutExpired:
        duration = round(time.monotonic() - start, 2)
        return ToolRunResult(
            verdict=Verdict.TIMEOUT,
            evidence=f"Exceeded {config.TOOL_TIMEOUT}s",
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
    tools = {tid: t for tid, t in all_tools.items()
             if (not tool_ids or tid in tool_ids)}
    if not tools:
        raise SystemExit("No matching tools (after --tools filter)")

    logger.info("Building tool images ...")
    for tid in list(tools):
        try:
            build_image(tid)
            tools[tid].version = get_tool_version(tid)
        except FileNotFoundError:
            logger.warning("  %s: no Dockerfile, skipping", tid)
            del tools[tid]

    tests = discover_tests(filter_ids=test_ids, filter_category=category)
    if not tests:
        raise SystemExit("No matching tests")
    logger.info("Discovered %d tests: %s", len(tests), [t.id for t in tests])

    results: list[TestResult] = []
    playground = PROJECT_ROOT / "playground" / "security"
    if playground.exists():
        shutil.rmtree(playground)

    for meta in tests:
        logger.info("=" * 60)
        logger.info("Test: %s (%s, severity=%s)", meta.id, meta.category, meta.severity)
        logger.info("=" * 60)
        try:
            payload = ensure_payload(meta.id)
        except subprocess.CalledProcessError as exc:
            logger.error("  build.py failed for %s: %s", meta.id, exc)
            runs = {tid: ToolRunResult(Verdict.ERROR, evidence=f"payload build failed: {exc}")
                    for tid in tools}
            results.append(TestResult(meta=meta, runs=runs))
            continue

        server = start_evil_server(meta, payload)
        try:
            runs: dict[str, ToolRunResult] = {}
            for tid in tools:
                output_dir = playground / meta.id / tid / "output"
                canary_dir = playground / meta.id / tid / "canary"
                logger.info("  %s ...", tid)
                run = run_tool_on_test(
                    tid, meta,
                    url=f"http://{EVIL_SERVER_HOST}:{EVIL_SERVER_PORT}/",
                    output_dir=output_dir,
                    canary_dir=canary_dir,
                )
                logger.info("    -> %s (%s)", run.verdict.value, run.evidence or run.duration)
                runs[tid] = run
        finally:
            stop_evil_server(server)

        results.append(TestResult(meta=meta, runs=runs))

    return SecurityReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        git_commit=_git_commit(),
        tools={
            tid: {"name": t.name, "url": t.url, "version": t.version}
            for tid, t in tools.items()
        },
        tests=results,
    )


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True,
        )
        return out.strip()
    except Exception:
        return "unknown"


def write_report(report: SecurityReport, path: Path = RESULTS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, sort_keys=False)
        f.write("\n")
    logger.info("Wrote %s", path)


def print_summary(report: SecurityReport) -> None:
    tool_ids = list(report.tools)
    header = ["Test", "Severity", "CVE"] + tool_ids
    rows = [header]
    for t in report.tests:
        row = [t.meta.id, t.meta.severity, t.meta.cve or "-"]
        for tid in tool_ids:
            r = t.runs.get(tid)
            row.append(r.verdict.value if r else "?")
        rows.append(row)

    widths = [max(len(str(r[i])) for r in rows) for i in range(len(header))]
    sep = "  "
    for row in rows:
        print(sep.join(str(c).ljust(widths[i]) for i, c in enumerate(row)))

    # Per-tool aggregate
    print()
    for tid in tool_ids:
        total = len(report.tests)
        passed = sum(1 for t in report.tests
                     if t.runs.get(tid) and t.runs[tid].verdict == Verdict.PASS)
        score = (passed / total * 100) if total else 0
        print(f"  {tid}: {passed}/{total} PASS ({score:.1f}%)")
