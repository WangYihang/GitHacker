"""End-to-end traversal regression for ``add_folder``.

The unit tests in ``test_ref_validation.py`` pin the per-segment trust gate
(``_is_safe_path_segment``) and the individual callers that feed it
(``add_task``, ``add_head_file_tasks``, ``add_packed_refs_tasks``). What
they do *not* exercise is the full ``add_folder`` pipeline that an
attacker actually controls end to end: a malicious HTML directory listing
is fetched, ``<a href>`` targets are extracted, the same-origin gate runs,
and surviving paths are split and queued.

This module drives crafted directory listings through the real
``add_folder`` (the HTTP layer mocked) and asserts the invariant that
matters regardless of which internal gate fires: **nothing a malicious
listing can serve causes a queued path to resolve outside ``temp_dst``**,
and no traversal component (``..``) is ever queued.

Corpus context: these payloads were collected while auditing
GHSA-hr3m-4qwq-3mgc. The same set was verified against PyPI 1.1.7's
``add_folder`` -> ``worker`` -> ``wget`` chain, where the mandatory
``.git/`` URL anchor plus ``str.replace('..', '')`` already kept all of
them inside ``temp_dst``; this test locks the same guarantee into the
current allowlist-based implementation so a future refactor cannot
regress it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from githacker.__main__ import GitHacker


# Attacker-served <a href="..."> targets. Each is a single directory-listing
# entry a malicious server could return for `.git/`.
TRAVERSAL_HREFS = [
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//etc/passwd",
    "......//etc/passwd",
    "/etc/passwd",
    "//etc/passwd",
    "/.ssh/authorized_keys",
    "%2e%2e/etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2fetc%2fpasswd",
    "foo/../../etc/passwd",
    "x/../../../etc/passwd",
    "./../../etc/passwd",
    ".../etc/passwd",
    "..\\..\\etc\\passwd",
    "/proc/self/environ",
    "config\x00../../etc/passwd",
]

# Malicious *directory* entries (trailing slash) that hit the recursion
# branch and its `_is_safe_path_segment` gate rather than the file branch.
TRAVERSAL_DIR_HREFS = [
    "../",
    "....//",
    "..%2f",
    "/etc/",
]


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200


class _FakeSession:
    """Serves one crafted listing for the initial `.git/` URL and an empty
    listing for any recursive fetch, so recursion always terminates."""

    expected_origin = None

    def __init__(self, listing_url: str, listing_html: str) -> None:
        self._listing_url = listing_url
        self._listing_html = listing_html
        self.requested_urls: list[str] = []

    def get(self, url: str, *args, **kwargs) -> _FakeResponse:
        self.requested_urls.append(url)
        if url == self._listing_url:
            return _FakeResponse(self._listing_html)
        # Any recursive directory fetch returns an empty listing.
        return _FakeResponse("<html><body></body></html>")


def _listing_html(hrefs: list[str]) -> str:
    anchors = "".join(f'<a href="{h}">entry</a>\n' for h in hrefs)
    return f"<html><body>{anchors}</body></html>"


def _make_hacker(tmp_path, session: _FakeSession) -> GitHacker:
    """Build a GitHacker wired up exactly as __init__ does for the fields
    add_folder touches, without performing any network I/O."""
    g = GitHacker.__new__(GitHacker)
    g.url = "http://victim.example/"
    g._origin = ("http", "victim.example")
    g._origin_path = "/"
    g.temp_dst = str(tmp_path)
    g.temp_dst_path = Path(str(tmp_path))
    g.cached_404_url = set()
    g._pending = []
    g.session = session
    return g


def _resolves_inside(temp_dst: str, components: list[str]) -> bool:
    fs_path = os.path.join(temp_dst, *components) if components else temp_dst
    try:
        resolved = os.path.realpath(fs_path)
    except ValueError:
        # NUL byte etc. — the OS refuses to resolve, which is not an escape.
        return True
    sandbox = os.path.realpath(temp_dst)
    return resolved == sandbox or resolved.startswith(sandbox + os.sep)


@pytest.mark.parametrize("href", TRAVERSAL_HREFS)
def test_add_folder_file_entry_cannot_escape_temp_dst(tmp_path, href):
    """A malicious file entry in the listing must never produce a queued
    path that resolves outside temp_dst, and must never queue a `..`."""
    listing_url = "http://victim.example/.git/"
    session = _FakeSession(listing_url, _listing_html([href]))
    g = _make_hacker(tmp_path, session)

    g.add_folder(g.url, ".git/")

    for components in g._pending:
        assert ".." not in components, (
            f"href {href!r} queued a traversal component: {components!r}"
        )
        assert _resolves_inside(g.temp_dst, components), (
            f"href {href!r} queued {components!r} which escapes temp_dst"
        )


@pytest.mark.parametrize("href", TRAVERSAL_DIR_HREFS)
def test_add_folder_dir_entry_cannot_escape_temp_dst(tmp_path, href):
    """A malicious directory entry (recursion branch) must not drive a
    queued path outside temp_dst regardless of how deep recursion goes."""
    listing_url = "http://victim.example/.git/"
    session = _FakeSession(listing_url, _listing_html([href]))
    g = _make_hacker(tmp_path, session)

    g.add_folder(g.url, ".git/")

    for components in g._pending:
        assert ".." not in components
        assert _resolves_inside(g.temp_dst, components)


def test_add_folder_queues_benign_entries(tmp_path):
    """Sanity: a normal listing with real .git children still queues them,
    so the traversal guards above aren't passing by blocking everything."""
    listing_url = "http://victim.example/.git/"
    session = _FakeSession(listing_url, _listing_html(["HEAD", "config", "index"]))
    g = _make_hacker(tmp_path, session)

    g.add_folder(g.url, ".git/")

    assert any("HEAD" in c for c in g._pending), (
        f"benign HEAD entry was not queued: {g._pending!r}"
    )
    # Nothing benign should have escaped or carried a traversal token.
    for components in g._pending:
        assert ".." not in components
        assert _resolves_inside(g.temp_dst, components)
