"""Oracle for A7: a would-be executable file recovered inside a nested GIT_DIR.

``.git/modules/<name>/`` is a real GIT_DIR, and git does honour its config —
plain ``git status`` in the *outer* repository fires a ``core.fsmonitor`` set
there, provided the submodule is wired up (a working tree plus a ``.git``
gitfile pointing at it).

A recovered tree has none of that, so the payload does not run: verified by
running ``git status`` against the recovered repository, where nothing fires.
What this measures is therefore the *write*, not execution — the tool put a
file git would execute into the operator's directory, past a policy that
exists to stop exactly that. FAIL means the file is there, not that it ran.
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
            return Verdict.FAIL, f'downloaded {rel}: a hook in a nested GIT_DIR'

        if Path(rel).name == 'config':
            try:
                text = path.read_text(errors='replace')
            except OSError:
                continue
            match = EXECUTABLE_DIRECTIVE.search(text)
            if match:
                return Verdict.FAIL, (
                    f'downloaded {rel} carrying core.{match.group(1)}: a nested '
                    f'GIT_DIR config, executable once the submodule is wired up'
                )
    if not any(p.is_file() for p in output_dir.rglob('*')):
        return Verdict.ERROR, (
            'the tool recovered no files at all, so "did not keep the nested '
            'GIT_DIR config" is not something this run demonstrated'
        )
    return Verdict.PASS, ''
