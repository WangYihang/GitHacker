"""E3: CVE-2018-11235 — submodule path with ``../``.

Classic submodule path-traversal; patched in git ≥ 2.17.1. Pillagers
that don't process submodules also PASS regardless of git version.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITMODULES = (
    b'[submodule "../../canary/PWNED_E3"]\n'
    b'\tpath = sub\n'
    b'\turl = https://example.invalid/sub.git\n'
)


def main() -> None:
    build_minimal_repo(
        HERE / "payload",
        config=config_with(""),
        tree_entries=[
            (0o100644, ".gitmodules", GITMODULES),
        ],
    )
    print(f"Built E3 payload at {HERE / 'payload'}")


if __name__ == "__main__":
    main()
