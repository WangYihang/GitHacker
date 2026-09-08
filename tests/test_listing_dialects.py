"""Attack surface: the HTML directory listing.

Every byte of a listing is written by the target, so an ``<a href>`` is pure
attacker input. Two things must hold for *every* href, and this module tests
both — because testing only the first is how issue #82 survived:

* **Safety** — no href may make the crawler write outside its sandbox or
  fetch outside the ``.git/`` tree it was aimed at.
* **Liveness** — a listing that honestly describes a ``.git`` tree must be
  crawled, whichever of the several legal href dialects the server writes it
  in. A crawler that rejects everything is safe and useless.
"""

from __future__ import annotations

import pytest

from tests.conftest import ANCHOR

# ---------------------------------------------------------------------------
# Safety — cross-origin
# ---------------------------------------------------------------------------

CROSS_ORIGIN_DIRS = [
    '//attacker.example/x/',  # protocol-relative: inherits our scheme
    'http://attacker.example/x/',  # different host
    'https://victim.example/.git/x/',  # scheme is part of the origin
    'http://victim.example:8080/.git/x/',  # so is the port
    'http://victim.example@attacker.example/x/',  # userinfo makes it look ours
    'http://victim.example.attacker.com/.git/x/',  # suffix-domain lookalike
]


@pytest.mark.parametrize('href', CROSS_ORIGIN_DIRS)
def test_cross_origin_directory_href_is_not_followed(crawl, href):
    assert crawl([href]).recursed == []


@pytest.mark.parametrize('href', [h.rstrip('/') for h in CROSS_ORIGIN_DIRS])
def test_cross_origin_file_href_is_not_queued(crawl, href):
    assert crawl([href]).queued == []


@pytest.mark.parametrize(
    'href',
    ['file:///etc/', 'javascript:alert(1)', 'data:text/html,x', 'ftp://attacker.example/x'],
)
def test_non_http_scheme_href_is_ignored(crawl, href):
    result = crawl([href])
    assert result.recursed == []
    assert result.queued == []


# ---------------------------------------------------------------------------
# Safety — traversal, in the encodings a listing can smuggle it in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'href',
    [
        '%2e%2e/',  # percent-encoded ..
        '%2E%2E/',  # uppercase hex
        '%252e%252e/',  # double-encoded
        '..%00/',  # NUL-truncated
        '..;/',  # path-parameter trick
        '.%2e/',  # half-encoded
        '..%2f..%2f',  # encoded separators
        '..\\..\\',  # Windows separators
    ],
)
def test_encoded_traversal_directory_href_is_not_followed(crawl, href):
    assert crawl([href]).recursed == []


@pytest.mark.parametrize(
    'href',
    [
        '../../etc/passwd',
        '....//etc/passwd',
        '%2e%2e/etc/passwd',
        'foo/../../etc/passwd',
        'config\x00../../etc/passwd',
    ],
)
def test_traversal_file_href_cannot_escape_the_sandbox(crawl, href):
    assert crawl([href]).escaping() == []


# ---------------------------------------------------------------------------
# Safety — same-origin but outside the .git/ tree
# ---------------------------------------------------------------------------


def test_same_origin_directory_href_outside_the_git_tree_is_not_followed(crawl):
    """`/etc/` is same-origin, so the origin check alone lets it through; it
    must still be refused for leaving the tree we were pointed at."""
    assert crawl(['/etc/']).recursed == []


@pytest.mark.parametrize('href', ['/etc/passwd', '/admin/secret.txt', '/etc\n/passwd'])
def test_same_origin_file_href_outside_the_git_tree_is_not_queued(crawl, href):
    assert crawl([href]).queued_outside_anchor() == []


def test_literal_dot_run_directory_is_a_name_not_traversal(crawl):
    """`....` is a legal directory name, so the crawler descends into it. That
    is safe — it goes one level *down*, never up — and pinning the distinction
    keeps a future "reject anything dotty" change a deliberate one."""
    result = crawl(['....//'])
    assert result.recursed == [f'{ANCHOR}..../']
    assert result.escaping() == []
    assert result.fetched_outside_anchor() == []


def test_current_directory_href_is_not_followed(crawl):
    """`./` resolves to the listing itself — following it never terminates."""
    assert crawl(['./']).recursed == []


@pytest.mark.parametrize('href', ['?C=N;O=D', '#top'])
def test_listing_self_links_are_ignored(crawl, href):
    assert crawl([href]).queued == []


# ---------------------------------------------------------------------------
# Liveness — the same tree, written in every dialect a server may use
# ---------------------------------------------------------------------------

TREE = ['HEAD', 'config', 'objects/', 'refs/']

DIALECTS = {
    'relative': lambda h: h,  # Apache mod_autoindex, nginx autoindex
    'dot_relative': lambda h: f'./{h}',
    'root_absolute': lambda h: f'/.git/{h}',  # Tomcat, Jetty, many proxies
    'full_url': lambda h: f'{ANCHOR}{h}',
}


@pytest.mark.parametrize('dialect', ['dot_relative', 'root_absolute', 'full_url'])
def test_listing_dialect_does_not_change_what_is_crawled(crawl, dialect):
    """The invariant issue #82 broke: rewriting the hrefs of one honest tree
    into another legal form must not change a single thing we fetch or queue."""
    baseline = crawl([DIALECTS['relative'](h) for h in TREE])
    variant = crawl([DIALECTS[dialect](h) for h in TREE])
    assert variant.queued == baseline.queued
    assert variant.recursed == baseline.recursed


def test_relative_dialect_crawls_the_whole_tree(crawl):
    """The baseline the invariance test above compares against is not vacuous."""
    result = crawl(TREE)
    assert result.queued == [('.git', 'HEAD'), ('.git', 'config')]
    assert result.recursed == [f'{ANCHOR}objects/', f'{ANCHOR}refs/']


def test_files_inside_a_subdirectory_listing_are_queued(crawl):
    """Loose objects only ever appear in a sub-listing, so recursion has to
    carry the anchor down with it."""
    result = crawl(['objects/'], sub={f'{ANCHOR}objects/': ['ab/']})
    assert result.escaping() == []
    assert f'{ANCHOR}objects/ab/' in result.recursed


@pytest.mark.parametrize('name', ['功能', 'café', 'Ünïcode'])
def test_non_ascii_names_are_downloaded(crawl, name):
    assert crawl([name]).queued == [('.git', name)]


def test_percent_encoded_name_is_decoded_before_validation(crawl):
    assert crawl(['%E5%8A%9F%E8%83%BD']).queued == [('.git', '功能')]
