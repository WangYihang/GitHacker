"""Shared helpers for building security-benchmark payloads.

Every Cat A / Cat F test ships a tiny well-formed git repository (one
blob, one tree, one commit) with a maliciously crafted ``.git/config``
or ``.gitattributes``. The pillager downloads it, runs git against it,
and the malicious directive fires the canary.

This module centralizes the chore of writing git objects + refs so the
per-test ``build.py`` only has to declare the malicious bits.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import zlib
from pathlib import Path


def write_object(git_dir: Path, content: bytes, obj_type: str) -> str:
    """Write a git loose object and return its hex SHA-1."""
    body = f'{obj_type} {len(content)}'.encode() + b'\0' + content
    sha = hashlib.sha1(body).hexdigest()
    dst = git_dir / 'objects' / sha[:2] / sha[2:]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(zlib.compress(body))
    return sha


def build_index(entries) -> bytes:
    """Return raw bytes of a git index v2.

    ``entries`` is a list of ``(mode, sha_hex, path, size)``.

    Payloads need a real index because the index *is* the recovery path for a
    whole class of pillager: GitHack and dumpall read it, materialise the blobs
    it names, and stop. Without one they fetch ``.git/index``, get a 404, and
    give up after a single request — which the benchmark then scored as a clean
    PASS on every scenario, crediting them with a safety they never had the
    chance to violate.
    """
    body = b'DIRC' + struct.pack('>II', 2, len(entries))
    for mode, sha_hex, path, size in entries:
        path_b = path.encode('utf-8')
        flags = min(len(path_b), 0xFFF)
        # 10 x uint32 stat fields, 20-byte sha, uint16 flags
        entry = struct.pack(
            '>10I20sH', 0, 0, 0, 0, 0, 0, mode, 0, 0, size, bytes.fromhex(sha_hex), flags
        )
        entry += path_b + b'\0'
        while (len(entry) % 8) != 0:  # pad to an 8-byte boundary, NUL included
            entry += b'\0'
        body += entry
    return body + hashlib.sha1(body).digest()


def build_minimal_repo(
    payload_dir: Path,
    *,
    config: str,
    extra_files: dict[str, bytes] | None = None,
    tree_entries: list[tuple[int, str, bytes]] | None = None,
) -> dict[str, str]:
    """Build a minimal git repo under ``payload_dir / ".git"``.

    Returns a dict with ``blob``, ``tree``, ``commit`` SHAs so callers
    can reference them (e.g. for poisoned indices).

    Parameters
    ----------
    payload_dir
        Destination — will be wiped and recreated.
    config
        Contents of ``.git/config`` (the malicious part lives here for
        most Cat A tests).
    extra_files
        Optional mapping of relative path (under payload) to bytes. Use
        for ``.git/index.html``, ``.git/index``, ``.gitattributes`` in
        the working tree, etc.
    tree_entries
        Optional list of ``(mode, path, blob_content)`` to include in
        the committed tree. Defaults to a single ``hello.txt``.
    """
    if payload_dir.exists():
        shutil.rmtree(payload_dir)
    git_dir = payload_dir / '.git'
    git_dir.mkdir(parents=True)

    if tree_entries is None:
        tree_entries = [(0o100644, 'hello.txt', b'hello\n')]

    tree_content = b''
    blobs: dict[str, str] = {}
    for mode, path, content in tree_entries:
        sha = write_object(git_dir, content, 'blob')
        blobs[path] = sha
        tree_content += f'{mode:o} {path}'.encode() + b'\0' + bytes.fromhex(sha)
    tree_sha = write_object(git_dir, tree_content, 'tree')
    commit_content = (
        f'tree {tree_sha}\n'
        f'author Evil <evil@example.com> 0 +0000\n'
        f'committer Evil <evil@example.com> 0 +0000\n\n'
        f'init\n'
    ).encode()
    commit_sha = write_object(git_dir, commit_content, 'commit')

    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    refs = git_dir / 'refs' / 'heads'
    refs.mkdir(parents=True)
    (refs / 'main').write_text(commit_sha + '\n')
    (git_dir / 'config').write_text(config)
    (git_dir / 'objects' / 'info').mkdir(parents=True, exist_ok=True)
    (git_dir / 'objects' / 'info' / 'packs').write_text('')

    # A real index over the same tree, so index-driven pillagers have a
    # recovery path at all. Scenarios that need a *crafted* index (B1) simply
    # overwrite this one.
    (git_dir / 'index').write_bytes(
        build_index(
            [(mode, blobs[path], path, len(content)) for mode, path, content in tree_entries]
        )
    )

    if extra_files:
        for rel, data in extra_files.items():
            dst = payload_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)

    return {
        'commit': commit_sha,
        'tree': tree_sha,
        **{f'blob:{p}': s for p, s in blobs.items()},
    }


def config_with(extra: str) -> str:
    """Return a ``.git/config`` with the standard preamble + extra lines."""
    return (
        '[core]\n'
        '\trepositoryformatversion = 0\n'
        '\tfilemode = true\n'
        '\tbare = false\n'
        '\tlogallrefupdates = true\n' + extra
    )
