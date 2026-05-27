"""E2: CVE-2024-32002 — case-insensitive submodule name + symlink.

On vulnerable git versions running on case-insensitive filesystems
(macOS HFS+/APFS by default, NTFS), a submodule whose name differs
only by case from a directory containing a symlink can write a hook
to an attacker-controlled path. Pillagers that don't process
submodules or run on case-sensitive filesystems PASS.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITMODULES = (
    b'[submodule "evil"]\n'
    b'\tpath = a/modules/x\n'
    b'\turl = https://example.invalid/sub.git\n'
    b'[submodule "EVIL"]\n'
    b'\tpath = a/Modules/x\n'
    b'\turl = https://example.invalid/sub2.git\n'
)


def main() -> None:
    build_minimal_repo(
        HERE / "payload",
        config=config_with(""),
        tree_entries=[
            (0o100644, ".gitmodules", GITMODULES),
        ],
    )
    print(f"Built E2 payload at {HERE / 'payload'}")


if __name__ == "__main__":
    main()
