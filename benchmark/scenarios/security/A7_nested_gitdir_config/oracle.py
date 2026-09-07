"""Oracle for A7: an executable file recovered inside a nested GIT_DIR.

``.git/modules/<name>/`` is a real GIT_DIR. A config or hook recovered there
runs as soon as git operates on that submodule, so downloading one is the
same failure A1 measures — it just does not fire during the benchmark run,
because nothing here enters the submodule.

FAIL if the tool wrote either the nested config carrying an executable
directive, or anything under a nested ``hooks/``.
"""

from __future__ import annotations

import re
from pathlib import Path

EXECUTABLE_DIRECTIVE = re.compile(
    r'^\s*(fsmonitor|pager|editor|sshCommand|askPass|external|hooksPath)\s*=',
    re.IGNORECASE | re.MULTILINE,
)


def check(output_dir: Path, canary_dir: Path, proc):
    from benchmark.security import Verdict

    if (canary_dir / 'PWNED_A7').exists():
        return Verdict.FAIL, 'PWNED_A7 created in canary dir'

    for path in sorted(output_dir.rglob('*')):
        if not path.is_file():
            continue
        rel = path.relative_to(output_dir).as_posix()
        if '/modules/' not in rel and '/worktrees/' not in rel:
            continue

        if Path(rel).parent.name == 'hooks':
            return Verdict.FAIL, f'downloaded {rel}: an executable hook in a nested GIT_DIR'

        if Path(rel).name == 'config':
            try:
                text = path.read_text(errors='replace')
            except OSError:
                continue
            match = EXECUTABLE_DIRECTIVE.search(text)
            if match:
                return Verdict.FAIL, (
                    f'downloaded {rel} carrying core.{match.group(1)}: a nested '
                    f'GIT_DIR config git executes like the top-level one'
                )
    return Verdict.PASS, ''
