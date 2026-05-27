"""Unit tests for the ref/sha/wordlist validation helpers and the packed-refs
parser. These exist to lock in that server-controlled or user-supplied input
cannot reach the path-join in worker() with traversal payloads.
"""

from __future__ import annotations

from unittest import mock

import pytest

from githacker.__main__ import (
    _MAX_WORDLIST_BYTES,
    GitHacker,
    _is_safe_path_segment,
    _is_safe_ref_segment,
    _is_safe_sha,
    _load_ref_wordlist,
)

# ---------------------------------------------------------------------------
# _is_safe_ref_segment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seg", [
    "develop",
    "release-1",
    "2025.01",
    "v1.0.0",
    "feat+x",
    "main",
    "issue-10",
    "1.2.3",
])
def test_safe_ref_segment_accepts_valid(seg):
    assert _is_safe_ref_segment(seg) is True


@pytest.mark.parametrize("seg", [
    "",
    ".",
    "..",
    "../etc",
    ".foo",
    "foo.lock",
    "a/b",
    "a b",
    "a\x00b",
    "/etc/passwd",
    "\\x",
    "foo\nbar",
    None,
])
def test_safe_ref_segment_rejects_invalid(seg):
    assert _is_safe_ref_segment(seg) is False


# ---------------------------------------------------------------------------
# _is_safe_sha
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sha", [
    "0" * 40,
    "abcdef0123456789" * 2 + "abcdefab",
    "ABCDEF0123456789" * 2 + "ABCDEFAB",
])
def test_safe_sha_accepts_valid(sha):
    assert _is_safe_sha(sha) is True


@pytest.mark.parametrize("sha", [
    "",
    "0" * 39,
    "0" * 41,
    "g" * 40,
    "0" * 40 + " ",
    None,
    1234,
])
def test_safe_sha_rejects_invalid(sha):
    assert _is_safe_sha(sha) is False


# ---------------------------------------------------------------------------
# _load_ref_wordlist
# ---------------------------------------------------------------------------

def test_load_ref_wordlist_filters_and_parses(tmp_path):
    wl = tmp_path / "tags.txt"
    wl.write_text(
        "\n"
        "# this is a comment\n"
        "release-1\n"
        "feature/login\n"      # multi-segment, safe
        "..\n"                 # rejected
        "../etc/passwd\n"      # rejected (segment ".." and "etc")
        ".hidden\n"            # rejected (leading dot)
        "foo.lock\n"           # rejected (.lock suffix)
        "  spaced  \n"         # stripped -> "spaced", safe
        "\n",
        encoding="utf-8",
    )
    out = _load_ref_wordlist(str(wl))
    assert ["release-1"] in out
    assert ["feature", "login"] in out
    assert ["spaced"] in out
    # Unsafe entries should not appear in any form.
    flat = ["/".join(s) for s in out]
    assert ".." not in flat
    assert "../etc/passwd" not in flat
    assert ".hidden" not in flat
    assert "foo.lock" not in flat


def test_load_ref_wordlist_size_cap(tmp_path):
    wl = tmp_path / "huge.txt"
    wl.write_bytes(b"a" * (_MAX_WORDLIST_BYTES + 1))
    with pytest.raises(ValueError, match="too large"):
        _load_ref_wordlist(str(wl))


def test_load_ref_wordlist_entry_cap(tmp_path):
    # Patch the cap so the test stays fast and small.
    wl = tmp_path / "many.txt"
    wl.write_text("\n".join(f"name{i}" for i in range(50)) + "\n", encoding="utf-8")
    with mock.patch("githacker.__main__._MAX_WORDLIST_ENTRIES", 10):
        out = _load_ref_wordlist(str(wl))
    assert len(out) == 10


# ---------------------------------------------------------------------------
# add_packed_refs_tasks
# ---------------------------------------------------------------------------

def _make_hacker(tmp_path):
    """Build a GitHacker without running start() — patch __init__ minimally."""
    from pathlib import Path as _Path
    g = GitHacker.__new__(GitHacker)
    g.url = "http://127.0.0.1/"
    g.temp_dst_path = _Path(str(tmp_path))
    g.temp_dst = str(tmp_path)
    g.cached_404_url = set()
    g._pending = []
    return g


def test_add_packed_refs_tasks_filters_unsafe(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    sha_a = "a" * 40
    sha_b = "b" * 40
    (git_dir / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n"
        f"{sha_a} refs/heads/main\n"
        f"^{'c' * 40}\n"                       # peeled-tag pointer, ignored
        f"{sha_b} refs/tags/v1.2.3\n"
        f"{sha_a} refs/heads/feature/login\n"  # multi-segment, safe
        f"{sha_a} refs/heads/../etc/passwd\n"  # malicious, rejected
        f"{sha_a} refs/heads/.lock-bad\n"      # leading dot, rejected
        "garbage line with no fields enough\n"
        f"deadbeef refs/heads/short-sha\n"     # bad sha, rejected
        f"{sha_a} refs/heads/main.lock\n"      # .lock suffix, rejected
        f"{sha_a} other/heads/main\n"          # not refs/, rejected
        ,
        encoding="utf-8",
    )
    g = _make_hacker(tmp_path)
    n = g.add_packed_refs_tasks()
    queued = list(g._pending)

    # Three named refs were queued (each also adds a logs/* sibling, so 6 total).
    assert n == 3
    # Should include exactly the safe refs.
    assert [".git", "refs", "heads", "main"] in queued
    assert [".git", "refs", "tags", "v1.2.3"] in queued
    assert [".git", "refs", "heads", "feature", "login"] in queued
    # Should NOT include any traversal payload.
    flat = ["/".join(p) for p in queued]
    assert not any(".." in p for p in flat)
    assert not any("etc/passwd" in p for p in flat)
    assert not any("lock-bad" in p for p in flat)
    assert not any("main.lock" in p for p in flat)


def test_add_packed_refs_tasks_missing_file(tmp_path):
    g = _make_hacker(tmp_path)
    assert g.add_packed_refs_tasks() == 0


# ---------------------------------------------------------------------------
# add_head_file_tasks — regression for the path-traversal vector reported in
# PR #65 (https://github.com/WangYihang/GitHacker/pull/65). A malicious
# server can craft `.git/HEAD` with a traversal ref like
# `ref: ../../../etc/passwd`; once `.git/logs/` exists on disk (which the
# first download wave always creates), the kernel resolves the join and
# the original code would `open()` the escaped path. The fix is the same
# per-segment validator that protects the rest of the queue.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "refs/heads/../../etc/passwd",       # mid-path traversal
    "refs/heads/main\x00/../../etc/passwd",
    "/etc/passwd",                       # absolute path → empty first segment
    "refs/heads/.evil",                  # leading-dot ref name
    "refs/heads/main.lock",              # .lock-suffixed ref
])
def test_add_head_file_tasks_rejects_traversal(tmp_path, payload):
    """The malicious ref must not produce any queued task, and no `..`
    component should slip through to the filesystem layer."""
    git_dir = tmp_path / ".git"
    (git_dir / "logs").mkdir(parents=True)
    # `.git/logs/` must exist for the kernel to even resolve `..` past the
    # parent — without it `os.path.exists()` short-circuits to False and
    # the vulnerability never triggers in the first place. The first
    # download wave always creates this directory in real runs.
    (git_dir / "HEAD").write_text(f"ref: {payload}\n", encoding="utf-8")

    g = _make_hacker(tmp_path)
    n = g.add_head_file_tasks()

    assert n == 0
    assert g._pending == []


def test_add_head_file_tasks_accepts_valid_ref(tmp_path):
    """The validator must not over-block: a normal HEAD pointing at an
    on-disk logs file should still be parsed for object hashes."""
    git_dir = tmp_path / ".git"
    (git_dir / "logs" / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    # A reflog line with two valid 40-char hex SHAs.
    sha_a = "a" * 40
    sha_b = "b" * 40
    (git_dir / "logs" / "refs" / "heads" / "main").write_text(
        f"{sha_a} {sha_b} You <you@x> 1700000000 +0000\tcommit: x\n",
        encoding="utf-8",
    )

    g = _make_hacker(tmp_path)
    n = g.add_head_file_tasks()

    assert n == 2  # both hashes queued as .git/objects/<aa>/<rest> tasks
    queued_paths = ["/".join(p) for p in g._pending]
    assert f".git/objects/{sha_a[:2]}/{sha_a[2:]}" in queued_paths
    assert f".git/objects/{sha_b[:2]}/{sha_b[2:]}" in queued_paths


def test_add_head_file_tasks_valid_ref_without_logs(tmp_path):
    """A well-formed HEAD whose logs file hasn't been downloaded yet
    should be a no-op (no traversal, no error)."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    g = _make_hacker(tmp_path)
    assert g.add_head_file_tasks() == 0
    assert g._pending == []


# ---------------------------------------------------------------------------
# _is_safe_path_segment — looser than _is_safe_ref_segment because real
# .git filenames begin with a dot.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seg", [
    ".git",
    ".gitignore",
    "HEAD",
    "config",
    "pack-1234abcd5678ef901234abcd5678ef9012345678.pack",
    "applypatch-msg",
    "main",
    "v1.2.3",
    "feat+x",
])
def test_safe_path_segment_accepts_valid(seg):
    assert _is_safe_path_segment(seg) is True


@pytest.mark.parametrize("seg", [
    "",
    ".",
    "..",
    "../etc",
    "etc/passwd",
    "a\\b",
    "a\x00b",
    "a b",
    "/etc/passwd",
    "foo\nbar",
    None,
])
def test_safe_path_segment_rejects_invalid(seg):
    assert _is_safe_path_segment(seg) is False


# ---------------------------------------------------------------------------
# add_task — central trust gate for path components
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    [".git", "..", "etc", "passwd"],
    [".git", "objects", "../../../etc/passwd"],
    ["/etc/passwd"],
    [".git", ""],
    [".git", "config\x00malicious"],
    [".git", "....//"],
])
def test_add_task_rejects_traversal(tmp_path, payload):
    g = _make_hacker(tmp_path)
    assert g.add_task(payload) is False
    assert g._pending == []


def test_add_task_accepts_valid(tmp_path):
    g = _make_hacker(tmp_path)
    assert g.add_task([".git", "config"]) is True
    assert g._pending == [[".git", "config"]]


# ---------------------------------------------------------------------------
# construct_url_from_path_components — percent-encodes each segment
# ---------------------------------------------------------------------------

def test_construct_url_quotes_segments(tmp_path):
    g = _make_hacker(tmp_path)
    g.url = "http://example.com/"
    # Reserved chars would never reach this method (add_task rejects them),
    # but defensive encoding keeps the URL well-formed.
    assert g.construct_url_from_path_components([".git", "HEAD"]) == \
        "http://example.com/.git/HEAD"
    # The `+` in a tag name like `v1.2+meta` needs to survive as-is — `+` is
    # an unreserved char that quote(safe='') leaves alone.
    assert g.construct_url_from_path_components([".git", "refs", "tags", "v1.2+meta"]) == \
        "http://example.com/.git/refs/tags/v1.2%2Bmeta"


# ---------------------------------------------------------------------------
# _is_same_origin_descendant — blocks subdomain spoofing
# ---------------------------------------------------------------------------

def test_same_origin_descendant_accepts_descendant(tmp_path):
    g = _make_hacker(tmp_path)
    g.url = "http://victim.com/path/"
    g._origin = ("http", "victim.com")
    g._origin_path = "/path/"
    assert g._is_same_origin_descendant("http://victim.com/path/.git/HEAD") is True


@pytest.mark.parametrize("evil", [
    "http://victim.com.attacker.com/path/.git/HEAD",   # subdomain spoof
    "http://attacker.com/path/.git/HEAD",              # different host
    "https://victim.com/path/.git/HEAD",               # scheme mismatch
    "http://victim.com/other/.git/HEAD",               # outside base path
])
def test_same_origin_descendant_blocks_spoofing(tmp_path, evil):
    g = _make_hacker(tmp_path)
    g.url = "http://victim.com/path/"
    g._origin = ("http", "victim.com")
    g._origin_path = "/path/"
    assert g._is_same_origin_descendant(evil) is False


# ---------------------------------------------------------------------------
# _OriginRestrictedSession — blocks SSRF via 3xx redirects
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stub matching requests.Response fields used by get_redirect_target."""

    def __init__(self, url, location, status_code=302):
        self.url = url
        self.status_code = status_code
        self.headers = {"location": location} if location else {}
        self.is_redirect = location is not None


def test_origin_restricted_session_allows_same_origin_redirect():
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    s.expected_origin = ("http", "victim.com")
    resp = _FakeResponse("http://victim.com/.git/HEAD", "/.git/refs/heads/main")
    # Same-origin redirect (relative path) is allowed — get_redirect_target
    # returns the (raw) Location header for requests to follow.
    assert s.get_redirect_target(resp) == "/.git/refs/heads/main"


def test_origin_restricted_session_blocks_cross_host_redirect():
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    s.expected_origin = ("http", "victim.com")
    resp = _FakeResponse("http://victim.com/.git/HEAD", "http://attacker.com/x")
    assert s.get_redirect_target(resp) is None


def test_origin_restricted_session_blocks_internal_ssrf():
    """C3 regression: a malicious server pointing at 127.0.0.1:<internal> is
    refused even though the scheme matches."""
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    s.expected_origin = ("http", "evil.example.com")
    resp = _FakeResponse(
        "http://evil.example.com/.git/HEAD",
        "http://127.0.0.1:8500/admin",
    )
    assert s.get_redirect_target(resp) is None


def test_origin_restricted_session_blocks_scheme_upgrade():
    """Refusing scheme changes too — http→https can hide tracker/SSRF."""
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    s.expected_origin = ("http", "victim.com")
    resp = _FakeResponse(
        "http://victim.com/.git/HEAD",
        "https://victim.com/.git/HEAD",
    )
    assert s.get_redirect_target(resp) is None


def test_origin_restricted_session_no_origin_set_passes_through():
    """Without expected_origin, the session behaves like a normal Session."""
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    assert s.expected_origin is None
    resp = _FakeResponse("http://x/", "http://y/")
    assert s.get_redirect_target(resp) == "http://y/"


def test_origin_restricted_session_non_redirect_returns_none():
    from githacker.__main__ import _OriginRestrictedSession

    s = _OriginRestrictedSession()
    s.expected_origin = ("http", "victim.com")
    resp = _FakeResponse("http://victim.com/x", None, status_code=200)
    resp.is_redirect = False
    assert s.get_redirect_target(resp) is None
