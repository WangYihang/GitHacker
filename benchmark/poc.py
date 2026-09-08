"""Emit a self-contained proof of concept for one scenario.

`benchmark repro` prints steps for someone who has this repository checked
out. A maintainer receiving a disclosure has neither the repository nor a
reason to trust a wall of instructions, so `benchmark poc` writes a directory
that can be attached to the report: the server, the malicious repository, and
a README, with no dependency on anything else.

Three things make a vendor-facing PoC different from the benchmark's own
harness, and getting them wrong wastes the maintainer's time:

* **The container holds the server, not the tool.** The benchmark
  containerises each tool because it tests seven of them. A maintainer already
  has their tool installed and wants to run *that* — so the payload gets
  isolated instead, and the proof lands on their host where they can see it.

* **The canary goes somewhere that exists.** Payloads hard-code ``/canary``
  because the harness bind-mounts it. On a machine that has no ``/canary`` the
  payload's ``touch`` fails silently, nothing appears, and the reader
  reasonably concludes they are not affected. The generated payload is
  rewritten to write into ``/tmp`` instead.

* **Not every finding proves itself with a file.** A redirect finding needs a
  listener, a recursion finding needs the server's request count, and a
  finding about a file that should not have been downloaded proves itself in
  the output directory. Telling everyone to watch for a canary that will never
  appear reads as a false report.
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

from benchmark.security import SCENARIOS_DIR, ensure_payload

PORT = 8080

# Where a generated PoC writes its proof. /tmp exists and is writable
# everywhere the tools run, which /canary is not.
POC_CANARY_DIR = '/tmp'

# How a scenario proves itself. Two axes are in play and conflating them
# misdescribes the finding: *what happened* (a command ran, or a file was
# written) and *where the proof lands* (a path the payload names, or wherever
# a relative escape resolves to).
EXEC = 'exec'  # a command ran; proof at a path the payload names
WRITE_ABS = 'write_abs'  # a file was written at an absolute path the payload named
WRITE_ESCAPE = 'write_escape'  # a file was written outside the output directory
RECOVERED_FILE = 'recovered'  # nothing ran; the file should not have been downloaded
CALLBACK = 'callback'  # the tool connected somewhere the target chose
REQUEST_LOG = 'log'  # the proof is the request count, not a file

# Membership is explicit. Guessing this from metadata produced a README that
# told a maintainer to look for command execution in a scenario that only ever
# writes a file, which reads as a false report.
_SHAPES = {
    'A7_nested_gitdir_config': RECOVERED_FILE,
    'B1_index_traversal': WRITE_ESCAPE,
    'C1_html_traversal': WRITE_ESCAPE,
    'E3_cve_2018_11235': WRITE_ESCAPE,
    'C4_absolute_path_write': WRITE_ABS,
    'C6_infinite_listing': REQUEST_LOG,
}


def _load_meta(test_id: str) -> dict:
    meta_path = SCENARIOS_DIR / test_id / 'meta.toml'
    if not meta_path.exists():
        raise SystemExit(f'No such scenario: {test_id}')
    with open(meta_path, 'rb') as f:
        return tomllib.load(f)


def _evidence_shape(test_id: str, meta: dict) -> str:
    if test_id in _SHAPES:
        return _SHAPES[test_id]
    if meta.get('callback_port') or meta.get('watch_regex'):
        return CALLBACK
    return EXEC


def _retarget_canary(payload: Path, test_id: str) -> list[str]:
    """Point the payload's canary at /tmp, and report what was rewritten.

    Only text files outside ``objects/`` are touched, and never the index:
    loose objects are compressed, and the index is length-prefixed, so a
    substitution of a different length would corrupt them. Payloads whose
    path is *relative* (they escape the output directory rather than naming
    an absolute path) are left exactly as they are — where they land is the
    finding.
    """
    rewritten = []
    for path in sorted(payload.rglob('*')):
        if not path.is_file():
            continue
        rel = path.relative_to(payload).as_posix()
        if '/objects/' in f'/{rel}' or rel.endswith('/index') or rel.endswith('.pack'):
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if '/canary/' not in text:
            continue
        # Absolute /canary/ only. "../../canary/" is a relative escape and
        # must keep pointing wherever it lands.
        out = text.replace('touch /canary/', f'touch {POC_CANARY_DIR}/')
        out = out.replace('"/canary/', f'"{POC_CANARY_DIR}/')
        if out != text:
            path.write_text(out)
            rewritten.append(rel)
    return rewritten


_DOCKERFILE = """# The malicious server, and nothing else. Your tool runs on your machine.
FROM python:3.12-slim
WORKDIR /srv
COPY evil_server.py /srv/evil_server.py
COPY payload /srv/payload
EXPOSE {port}
CMD {cmd}
"""

_COMPOSE = """services:
  target:
    build: .
    ports:
      - "{port}:{port}"
"""


def _server_cmd(meta: dict) -> str:
    mode = meta.get('server_mode', 'static')
    args = ['python', 'evil_server.py', '--mode', mode, '--host', '0.0.0.0', '--port', str(PORT)]
    if mode == 'static':
        args += ['--payload', '/srv/payload', '--access-log', '/dev/stdout']
    elif mode == 'redirect':
        args += ['--redirect-to', meta.get('redirect_to', '')]
    elif mode == 'infinite':
        args += ['--access-log', '/dev/stdout']
    if meta.get('watch_regex'):
        args += ['--watch-regex', meta['watch_regex'], '--watch-canary', '/tmp/watch-hit']
    return '[' + ', '.join(f'"{a}"' for a in args) + ']'


def _harmlessness(shape: str) -> list[str]:
    """State what the payload actually does — accurately per shape.

    "It runs touch and nothing else" is true of the command-execution
    scenarios and false of the ones where git does the writing, and a
    maintainer who reads the payload will notice the discrepancy.
    """
    if shape in (EXEC, WRITE_ABS):
        return [
            'The payload runs `touch` and nothing else. That is the entire effect: the',
            'file appearing is the proof. Read `payload/.git/config` before you run it',
            'if you would rather check than take our word for it.',
        ]
    if shape == WRITE_ESCAPE:
        return [
            'Nothing in the payload is a command. It is a crafted git object that names',
            'a path climbing out of the repository; git writes an empty file there when',
            'your tool checks the repository out. Nothing is executed and nothing is',
            'overwritten that was not already going to be written.',
        ]
    if shape == RECOVERED_FILE:
        return [
            'Nothing here executes at all. The payload is an ordinary-looking file in a',
            'place your tool should not copy out of. The proof is that it appears in',
            'your output directory.',
        ]
    if shape == REQUEST_LOG:
        return [
            'There is no payload in the usual sense — the server generates a directory',
            'tree with no bottom. Nothing is written and nothing is executed; the only',
            'effect is the requests your tool makes.',
        ]
    return [
        'The payload does not execute anything on your machine. It redirects your tool',
        'somewhere the target chose, and a listener you run confirms it went there.',
    ]


def _readme(test_id: str, meta: dict, shape: str, rewritten: list[str]) -> str:
    canary = f'PWNED_{test_id.split("_", 1)[0]}'
    sev = meta.get('severity', '?')
    lines = [
        f'# Proof of concept — {test_id}',
        '',
        f'**Severity (our rating): {sev}.** {meta.get("description", "").strip()}',
        '',
        '## What this is',
        '',
        'A container that serves one deliberately malicious `.git` over HTTP, and',
        'nothing else. Your tool stays on your machine — point it at the container',
        'and watch what happens on your side.',
        '',
        *_harmlessness(shape),
        '',
        '## Run it',
        '',
        '```',
        'docker compose up --build      # serves on http://127.0.0.1:8080/',
        '```',
        '',
        'Or without Docker — the server is stdlib-only Python, no dependencies:',
        '',
        '```',
        f'python3 evil_server.py --mode {meta.get("server_mode", "static")} \\',
        f'    --payload ./payload --port {PORT}',
        '```',
        '',
        'Then, from an empty directory:',
        '',
        '```',
        'mkdir -p /tmp/poc-run && cd /tmp/poc-run',
        f'<your-tool> http://127.0.0.1:{PORT}/ ./out',
        '```',
        '',
        '## What proves it',
        '',
    ]

    if shape == EXEC:
        lines += [
            f'`{POC_CANARY_DIR}/{canary}` appears. You did not create it; the payload did,',
            'through your tool. If the file is there, the recovered repository executed',
            'an attacker-chosen command on your machine.',
            '',
            '```',
            f'ls -l {POC_CANARY_DIR}/{canary}',
            '```',
        ]
    elif shape == WRITE_ABS:
        lines += [
            f'`{POC_CANARY_DIR}/{canary}` appears. Nothing executed: the payload names that',
            'absolute path in the directory listing it serves, and your tool honoured it,',
            'writing outside the directory you asked for.',
            '',
            '```',
            f'ls -l {POC_CANARY_DIR}/{canary}',
            '```',
        ]
    elif shape == WRITE_ESCAPE:
        lines += [
            'Nothing executed, and there is no fixed path to watch. The payload does not',
            'name an absolute path — it escapes the output directory with a relative one,',
            'so where the write lands depends on where you ran your tool. That is the',
            'finding: a file exists outside `./out` that you did not ask for.',
            '',
            '```',
            f'find /tmp/poc-run -name {canary} -not -path "*/out/*"',
            '```',
            '',
            'Widen the search if you ran the tool elsewhere; the write climbs out of the',
            'output directory relative to wherever it started.',
        ]
    elif shape == RECOVERED_FILE:
        lines += [
            'Nothing executes here, and that is the honest framing: check whether the',
            'file was *recovered*, not whether it ran.',
            '',
            '```',
            'find ./out -path "*modules*" -name config',
            '```',
            '',
            'If that config is in your output directory, your tool wrote a file git',
            "would execute into the operator's tree. git reads a submodule GIT_DIR's",
            'config once the submodule is wired up; a freshly recovered tree is not, so',
            'this is a latent hazard rather than an exploit.',
        ]
    elif shape == CALLBACK:
        port = meta.get('callback_port', 12345)
        lines += [
            'Your tool connects to an address the *target* chose, not the one you gave',
            'it. Start a listener first, in another shell:',
            '',
            '```',
            f'python3 -c "import http.server,socketserver; socketserver.TCPServer((\'127.0.0.1\',{port}), http.server.BaseHTTPRequestHandler).serve_forever()"',
            '```',
            '',
            'If that listener logs a request while your tool runs, the redirect was',
            'followed.',
        ]
    elif shape == REQUEST_LOG:
        lines += [
            'There is no file to look for. The server prints every request it answers;',
            'watch the count.',
            '',
            'The served tree is bottomless and one entry wide, so a tool that bounds its',
            'recursion stops after a handful of requests. A real `.git` is about four',
            'levels deep. If your tool keeps going into the hundreds, its recursion is',
            'bounded by nothing it controls.',
        ]

    lines += [
        '',
        '## Cleaning up',
        '',
        '```',
        'docker compose down',
        f'rm -f {POC_CANARY_DIR}/{canary}',
        'rm -rf /tmp/poc-run',
        '```',
        '',
        '## Notes',
        '',
        '- The payload is generated, not hand-edited; `payload/` here is a copy.',
    ]
    if rewritten:
        lines += [
            f'- Its canary path was retargeted to `{POC_CANARY_DIR}` so it works without',
            '  `sudo` on your machine. Files changed: ' + ', '.join(f'`{r}`' for r in rewritten),
        ]
    lines += [
        '- Nothing here is hosted anywhere. It exists in this directory and in the',
        '  container you build from it.',
        '',
    ]
    return '\n'.join(lines)


def write_poc(test_id: str, out_dir: Path) -> Path:
    meta = _load_meta(test_id)
    shape = _evidence_shape(test_id, meta)

    if out_dir.exists():
        raise SystemExit(f'{out_dir} already exists — remove it or pick another --out')
    out_dir.mkdir(parents=True)

    server = Path(__file__).resolve().parent / 'evil_server.py'
    shutil.copy(server, out_dir / 'evil_server.py')

    rewritten: list[str] = []
    if meta.get('server_mode', 'static') == 'static':
        built = ensure_payload(test_id)
        shutil.copytree(built, out_dir / 'payload')
        rewritten = _retarget_canary(out_dir / 'payload', test_id)
    else:
        # Nothing to serve from disk; the mode generates its own responses.
        (out_dir / 'payload').mkdir()
        (out_dir / 'payload' / '.keep').write_text('')

    (out_dir / 'Dockerfile').write_text(
        _DOCKERFILE.format(port=PORT, cmd=_server_cmd(meta)),
    )
    (out_dir / 'docker-compose.yml').write_text(_COMPOSE.format(port=PORT))
    (out_dir / 'README.md').write_text(_readme(test_id, meta, shape, rewritten))

    return out_dir
