"""Attack surface: what a hostile server can do to the *client*.

The tests above ask whether a malicious listing can make the crawler write or
fetch the wrong thing. These ask whether it can make the crawler never stop,
run out of memory, or die with a traceback instead of an error — the failure
modes that need no traversal at all, only a server that answers.
"""

from __future__ import annotations

import pytest

from tests.conftest import ANCHOR, RunawayCrawl, Server

# ---------------------------------------------------------------------------
# Termination
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason='The crawler keeps no record of the listings it has already read and '
    'imposes no depth limit, so a server that answers every URL with the same '
    'one-subdirectory listing drives it until the interpreter runs out of '
    'stack. PR #83 adds a second route to this: with absolute hrefs the URL '
    'stops growing, so the same listing recurses on one single URL.',
)
def test_a_server_that_always_offers_one_more_subdirectory_terminates(crawl):
    crawl(['loop/'], always=['loop/'])


def test_a_finite_tree_is_crawled_exactly_once_per_directory(crawl):
    """The control for the test above: a well-behaved listing terminates, so
    the runaway detector is not simply firing on any recursion at all."""
    result = crawl(['objects/'], sub={f'{ANCHOR}objects/': ['ab/']})
    assert result.fetched == [ANCHOR, f'{ANCHOR}objects/', f'{ANCHOR}objects/ab/']


def test_the_runaway_detector_actually_fires(crawl):
    """A meta-test: if the scripted server ever stopped counting requests, every
    termination test above would pass vacuously."""
    with pytest.raises(RunawayCrawl):
        crawl(['loop/'], always=['loop/'])


# ---------------------------------------------------------------------------
# Resource exhaustion
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason='wget() reads response.content, materialising the whole body in '
    'memory before writing it. A malicious server can answer any object '
    'request with an unbounded stream. Downloads should be streamed to disk '
    '(stream=True) so size is bounded by the filesystem, not by RAM — a cap '
    'is the wrong fix, since real packfiles are legitimately huge.',
)
def test_downloads_are_streamed_rather_than_buffered(hacker):
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


@pytest.mark.xfail(
    strict=True,
    reason='git_clone() calls copy_useful_files() before checking the return '
    'code, so a failed clone raises FileNotFoundError from inside the copy '
    'instead of reporting failure. Any target whose .git is incomplete — the '
    'exact symptom reported in issue #82 — crashes with a traceback.',
)
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


@pytest.mark.xfail(
    strict=True,
    reason='check_file_content() rejects any body starting with "<" to filter '
    'HTML error pages, which also discards legitimate content — a commit '
    'message or description beginning with "<" is silently lost.',
)
def test_legitimate_content_starting_with_an_angle_bracket_is_kept(hacker):
    assert hacker.check_file_content(b'<html> in a commit message\n') is True
