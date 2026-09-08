"""Attack surface: what a hostile server can do to the *client*.

The tests above ask whether a malicious listing can make the crawler write or
fetch the wrong thing. These ask whether it can make the crawler never stop,
run out of memory, or die with a traceback instead of an error — the failure
modes that need no traversal at all, only a server that answers.
"""

from __future__ import annotations

import pytest

from githacker.__main__ import _MAX_CRAWL_DEPTH
from tests.conftest import (
    ANCHOR,
    MAX_REQUESTS,
    RunawayCrawl,
    Server,
    listing,
)

# ---------------------------------------------------------------------------
# Termination
# ---------------------------------------------------------------------------


def test_a_server_offering_one_more_subdirectory_forever_is_stopped_by_depth(crawl):
    """A malicious server can manufacture unbounded depth with relative hrefs,
    which grow the URL at every step. The depth ceiling is what stops it —
    before the recursion limit or the filesystem's path length does."""
    result = crawl(['loop/'], always=['loop/'])
    assert len(result.fetched) == _MAX_CRAWL_DEPTH + 1


def test_a_listing_that_links_to_itself_is_read_once(crawl):
    """With an absolute href the URL does not grow, so the depth ceiling alone
    would re-read the same URL forever. The visited set is what stops this one."""
    result = crawl(['/.git/loop/'], sub={f'{ANCHOR}loop/': ['/.git/loop/']})
    assert result.fetched == [ANCHOR, f'{ANCHOR}loop/']


def test_a_finite_tree_is_crawled_exactly_once_per_directory(crawl):
    """The control for the test above: a well-behaved listing terminates, so
    the runaway detector is not simply firing on any recursion at all."""
    result = crawl(['objects/'], sub={f'{ANCHOR}objects/': ['ab/']})
    assert result.fetched == [ANCHOR, f'{ANCHOR}objects/', f'{ANCHOR}objects/ab/']


def test_the_runaway_detector_actually_fires():
    """A meta-test: the termination tests above only mean something if the
    scripted server really does refuse to answer forever. Drive it directly, so
    this stays honest however the crawler behaves."""
    server = Server(always=listing(['loop/']))
    with pytest.raises(RunawayCrawl):
        for _ in range(MAX_REQUESTS + 1):
            server.get(ANCHOR)


# ---------------------------------------------------------------------------
# Resource exhaustion
# ---------------------------------------------------------------------------


def test_downloads_are_streamed_rather_than_buffered(hacker):
    """A packfile is legitimately huge, so the bound has to be the filesystem's
    rather than a size cap. Buffering the whole body let the server pick how
    much memory the pillager used."""
    hacker.session = Server()
    hacker.wget(f'{ANCHOR}HEAD', hacker.temp_dst_path / '.git' / 'HEAD')
    assert hacker.session.last_kwargs.get('stream') is True


def test_a_listing_with_many_entries_queues_them_all(crawl):
    """Breadth is not a bug: a real .git/objects listing has thousands of
    entries, so nothing here may cap the number of siblings."""
    names = [f'ab{i:04d}' for i in range(2000)]
    assert len(crawl(names).queued) == 2000


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


def test_a_failed_clone_reports_failure_instead_of_raising(hacker):
    git_dir = hacker.temp_dst_path / '.git'
    git_dir.mkdir(parents=True)
    (git_dir / 'COMMIT_EDITMSG').write_text('not a real repository\n')
    assert hacker.git_clone() is False


def test_an_empty_body_is_not_written(hacker):
    """A server answering 200 with nothing must not leave an empty file behind
    to be mistaken for a real object."""
    hacker.session = Server()  # every URL answers '<html></html>'
    target = hacker.temp_dst_path / '.git' / 'HEAD'
    _, _, ok = hacker.wget(f'{ANCHOR}HEAD', target)
    assert ok is False


def test_content_starting_with_an_angle_bracket_is_kept(hacker):
    """The old filter dropped anything opening with "<" to catch HTML error
    pages, and took legitimate content with it. (Content that opens with a
    literal HTML tag stays undecidable from the bytes alone, so it is still
    rejected — see the test below.)"""
    assert hacker.check_file_content(b'<wip> refactor the parser\n') is True


def test_an_html_error_page_is_still_rejected(hacker):
    """The reason the filter exists: servers answer 404 with 200 and a page."""
    assert hacker.check_file_content(b'<!DOCTYPE html>\n<html><body>404') is False


# ---------------------------------------------------------------------------
# The downloaded index drives `git checkout-index`, so it is attacker input
# ---------------------------------------------------------------------------


def _repo_with_index_entry(root, path_in_index):
    """A real repo whose index names `path_in_index`.

    The entry is written by hand, through the benchmark's own index builder,
    because `git update-index` refuses to record a path containing "..". That
    refusal is exactly why the attack has to arrive as a downloaded index file
    rather than through any git command.
    """
    import importlib.util
    import subprocess

    from benchmark.security import SCENARIOS_DIR

    spec = importlib.util.spec_from_file_location(
        'b1_build', SCENARIOS_DIR / 'B1_index_traversal' / 'build.py'
    )
    b1 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b1)

    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q'], cwd=root, capture_output=True, check=True)
    sha = b1._write_object(root / '.git', b'payload\n', 'blob')
    (root / '.git' / 'index').write_bytes(b1._build_index([(0o100644, sha, path_in_index)]))
    return root


def test_an_index_naming_a_path_outside_the_repository_is_refused(hacker, tmp_path):
    """B1: `git checkout-index --all` writes every entry where the index says,
    and the index came from the target. "../../x" escapes the output directory
    with no traversal anywhere in a URL."""
    repo = _repo_with_index_entry(tmp_path / 'downloaded', '../../canary/PWNED')
    assert hacker._index_paths_are_safe(repo) is False


def test_an_ordinary_index_is_accepted(hacker, tmp_path):
    """The control: the check must not block the staged-only-blob restore it
    guards, or every normal repository loses files."""
    repo = _repo_with_index_entry(tmp_path / 'downloaded', 'src/main.py')
    assert hacker._index_paths_are_safe(repo) is True


def test_an_unreadable_index_is_treated_as_unsafe(hacker, tmp_path):
    """Fail closed: if git cannot parse it, we do not install it."""
    not_a_repo = tmp_path / 'empty'
    not_a_repo.mkdir()
    assert hacker._index_paths_are_safe(not_a_repo) is False
