"""Print the steps to reproduce one security scenario, on one machine.

Running the whole suite needs Docker and every tool image. A maintainer who
has just been told their tool is affected needs neither: they need one
malicious ``.git`` on localhost and their own tool pointed at it. That is two
commands, and this prints them for any scenario.

The steps come from the scenario's own ``meta.toml`` rather than from prose,
so a new scenario is documented the moment it is registered, and a scenario
that changes its server mode cannot leave stale instructions behind.

Nothing here is hosted. That is deliberate: several of these payloads achieve
code execution — A1 and A3 fire real canaries during a benchmark run — and a
public copy would execute on whoever pointed a vulnerable tool at it. The
payload exists on the operator's own machine, for as long as they run the
server, and nowhere else.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from benchmark.security import SCENARIOS_DIR

PORT = 8080

# Where the benchmark mounts the directory a payload writes its proof into.
# Payloads hard-code this path, so a local run needs it to exist.
CANARY_DIR = '/canary'

# Scenarios whose payload does not name an absolute path but *escapes* the
# output directory instead — where the write lands is the finding. For these
# the canary directory is beside the point; what matters is that anything
# appeared outside the output directory at all.
ESCAPES_OUTPUT_DIR = {
    'B1_index_traversal',
    'C1_html_traversal',
    'C4_absolute_path_write',
    'E3_cve_2018_11235',
}

# What each server mode needs on the command line, and what it does.
_MODES = {
    'static': (
        '--payload {payload}',
        'serves the payload directory, with an Apache-style directory listing',
    ),
    'redirect': (
        '--redirect-to {redirect_to}',
        'answers every request with a 302 to the target below',
    ),
    'infinite': (
        '',
        'generates a directory tree with no bottom, one entry wide at each level',
    ),
}


def _load_meta(test_id: str) -> dict:
    meta_path = SCENARIOS_DIR / test_id / 'meta.toml'
    if not meta_path.exists():
        raise SystemExit(f'No such scenario: {test_id}')
    with open(meta_path, 'rb') as f:
        return tomllib.load(f)


def _findings_for(test_id: str) -> list[dict]:
    path = Path(__file__).resolve().parent / 'disclosures.toml'
    if not path.exists():
        return []
    with open(path, 'rb') as f:
        data = tomllib.load(f)
    return [f for f in data.get('finding', []) if f.get('test') == test_id]


def _rel(path: Path) -> str:
    cwd = Path.cwd()
    return str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)


def print_repro(test_id: str) -> None:
    meta = _load_meta(test_id)
    mode = meta.get('server_mode', 'static')
    if mode not in _MODES:
        raise SystemExit(f'{test_id}: unknown server_mode {mode!r}')
    flag_template, mode_description = _MODES[mode]

    scenario_dir = SCENARIOS_DIR / test_id
    flags = flag_template.format(
        payload=_rel(scenario_dir / 'payload'),
        redirect_to=meta.get('redirect_to', ''),
    )
    canary = f'PWNED_{test_id.split("_", 1)[0]}'
    escapes = test_id in ESCAPES_OUTPUT_DIR

    print(f'{test_id}  [{meta.get("category", "?")}, severity {meta.get("severity", "?")}]')
    print()
    print(meta.get('description', '').strip())
    print()

    step = 1
    if not escapes:
        print(f'{step}. The payload writes its proof into {CANARY_DIR}, which the benchmark')
        print('   bind-mounts into each tool container. Outside Docker it has to exist,')
        print('   or the payload\'s `touch` fails and you read that as "not affected":')
        print(f'     sudo mkdir -p {CANARY_DIR} && sudo chmod 1777 {CANARY_DIR}')
        print('   If the tool runs in a container, the directory has to reach inside it')
        print(f'   too: add `-v {CANARY_DIR}:{CANARY_DIR}` to the docker run.')
        print()
        step += 1

    if mode == 'static':
        print(f'{step}. Build the payload (it is generated, never committed):')
        print(f'     python {_rel(scenario_dir / "build.py")}')
        print()
        step += 1

    print(f'{step}. Serve it — {mode_description}:')
    print(f'     python benchmark/evil_server.py --mode {mode} {flags} --port {PORT}')
    if meta.get('watch_regex'):
        print()
        print('   This scenario has no payload-fired canary: the server writes one when')
        print('   the tool requests a path it should not. Add to the command above:')
        print(
            f'     --watch-regex {meta["watch_regex"]!r} --watch-canary /tmp/{meta["watch_canary"]}'
        )
    print()
    step += 1

    if meta.get('callback_port'):
        print(f'{step}. In another shell, the callback listener this scenario needs:')
        print(
            f'     python benchmark/evil_server.py --mode callback '
            f'--port {meta["callback_port"]} --canary-file /tmp/{meta["callback_canary"]}'
        )
        print()
        step += 1

    print(f'{step}. Point the tool under test at it, from an empty scratch directory:')
    print('     mkdir -p /tmp/repro && cd /tmp/repro')
    print(f'     <tool> http://127.0.0.1:{PORT}/ ./out')
    print()
    step += 1

    print(f'{step}. What to look for:')
    if meta.get('watch_regex'):
        print(f'     /tmp/{meta["watch_canary"]} — written by the server, not the payload.')
    elif escapes:
        print(f'     Any {canary} written outside ./out. This payload does not name an')
        print('     absolute path; it escapes the output directory, and where it lands')
        print('     is the finding:')
        print(f'       find /tmp/repro -name {canary} -not -path "*/out/*"')
    else:
        print(f'     {CANARY_DIR}/{canary} — created only if the payload executed.')
        print('     The payload runs `touch` and nothing else.')
    if (scenario_dir / 'oracle.py').exists():
        print(f'     Custom oracle: {_rel(scenario_dir / "oracle.py")} — read it for')
        print('     exactly what the benchmark counts as a failure.')
    print()

    findings = _findings_for(test_id)
    if findings:
        print('Recorded findings for this scenario:')
        for f in findings:
            print(
                f'     {f["id"]}  {f.get("severity", "?")}  {f["tool"]:24} {f.get("status", "?")}'
            )
        print()

    print('The payload exists only in the directory above, for as long as the server')
    print('runs. It is not hosted anywhere.')


def print_index() -> None:
    """List the scenarios, so `repro` is discoverable without reading the tree."""
    rows = []
    for child in sorted(SCENARIOS_DIR.iterdir()):
        if not child.is_dir() or child.name.startswith('_'):
            continue
        if not (child / 'meta.toml').exists():
            continue
        meta = _load_meta(child.name)
        rows.append((child.name, meta.get('category', '?'), meta.get('severity', '?')))

    print(f'{len(rows)} scenarios. `python -m benchmark repro <id>` prints the steps for one.')
    print()
    for name, category, severity in rows:
        print(f'  {name:26} {category:5} {severity}')
