"""Shared scaffolding for the crawler test-suites.

The rules every test in this directory follows:

* **One attack per test.** The name states the attack, the body is
  serve → crawl → assert. Nothing else.
* **Independent.** Each call to the ``crawl`` fixture builds a fresh
  ``GitHacker`` in its own sandbox, so no test can be affected by another —
  not even two crawls inside the same test.
* **The invariant lives here, not in the test.** ``Crawl.escaping()`` and the
  two ``*_outside_anchor()`` helpers define the boundaries this whole suite is
  about. A test names a boundary; it never re-implements what "safe" means.
  (That duplication is what let issue #82 hide: the directory branch and the
  file branch each had their own idea of a safe href.)

The HTTP layer is a scripted server, so the crawler is exercised for real
while the "network" is entirely attacker-authored, which is the threat model.
"""

from __future__ import annotations

import html
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

import pytest

from githacker.__main__ import GitHacker

TARGET = 'http://victim.example/'
ANCHOR = f'{TARGET}.git/'

# No finite listing justifies more requests than this. A crawler that cannot
# be starved into terminating is a denial-of-service bug, so the ceiling is
# an assertion rather than a convenience.
MAX_REQUESTS = 200


class RunawayCrawl(RuntimeError):
    """The crawler would not terminate on a finite (if malicious) listing."""


def listing(hrefs):
    """Render `hrefs` as a directory-listing page, nginx/Apache shaped."""
    anchors = '\n'.join(f'<a href="{html.escape(h, quote=True)}">entry</a>' for h in hrefs)
    return (
        '<html><head><title>Index of /.git/</title></head>'
        f'<body><pre>\n{anchors}\n</pre></body></html>'
    )


@dataclass
class Response:
    text: str = ''
    content: bytes = b''
    status_code: int = 200


@dataclass
class Server:
    """Answers scripted bodies and records everything the crawler asks for.

    `pages` maps an exact URL to its listing HTML. `always`, when set, is the
    listing served for *every* other URL — that is how a malicious server
    that manufactures infinite depth is modelled.
    """

    pages: dict[str, str] = field(default_factory=dict)
    always: str | None = None
    requested: list[str] = field(default_factory=list)
    last_kwargs: dict = field(default_factory=dict)
    expected_origin = None  # the attribute GitHacker sets on a real session

    def get(self, url, *args, **kwargs):
        self.requested.append(url)
        self.last_kwargs = kwargs
        if len(self.requested) > MAX_REQUESTS:
            raise RunawayCrawl(f'{len(self.requested)} requests, last was {url!r}')
        body = self.pages.get(url, self.always if self.always is not None else '<html></html>')
        return Response(text=body, content=body.encode())


def _inside(sandbox: Path, components) -> bool:
    """True when `components` resolve inside `sandbox` — the definition of
    "did not escape", not a proxy for it."""
    try:
        resolved = Path(os.path.realpath(sandbox.joinpath(*components)))
    except ValueError:
        # NUL and friends: the OS refuses to resolve the name, so nothing
        # can be written through it. Not an escape.
        return True
    root = Path(os.path.realpath(sandbox))
    return resolved == root or root in resolved.parents


@dataclass
class Crawl:
    """What one ``add_folder()`` run actually did."""

    fetched: list[str]
    queued: list[tuple[str, ...]]
    sandbox: Path

    @property
    def recursed(self) -> list[str]:
        """URLs fetched past the initial listing — the directories we entered."""
        return self.fetched[1:]

    def escaping(self) -> list[tuple[str, ...]]:
        """Queued paths that would be written outside the sandbox."""
        return [c for c in self.queued if not _inside(self.sandbox, c)]

    def fetched_outside_anchor(self) -> list[str]:
        """URLs fetched from outside the ``.git/`` tree we were pointed at."""
        return [u for u in self.fetched if not u.startswith(ANCHOR)]

    def queued_outside_anchor(self) -> list[tuple[str, ...]]:
        """Queued paths that do not sit under the ``.git/`` tree.

        Separate from `fetched_outside_anchor` because ``add_folder`` only
        *queues* file entries — the request happens later, in the drain — so
        an off-tree file entry is invisible to the fetch log.
        """
        return [c for c in self.queued if c[:1] != ('.git',)]


def _build(sandbox: Path, out: Path, session: Server) -> GitHacker:
    # `__init__` calls complete_basic_files_list(), which fetches .git/HEAD
    # over the real network to guess the default branch — a constructor doing
    # I/O. Nothing here depends on the file lists it populates, and the
    # session cannot be swapped in until after construction, so it is stubbed
    # out for the duration.
    with mock.patch.object(GitHacker, 'complete_basic_files_list', lambda self: None):
        g = GitHacker(url=TARGET, dst=str(out), threads=1)
    shutil.rmtree(g.temp_dst, ignore_errors=True)  # drop __init__'s mkdtemp
    sandbox.mkdir(parents=True, exist_ok=True)
    g.temp_dst_path, g.temp_dst = sandbox, str(sandbox)
    g.session = session
    return g


@pytest.fixture
def hacker(tmp_path):
    """A real GitHacker aimed at TARGET, sandboxed, with no network."""
    g = _build(tmp_path / 'sandbox', tmp_path / 'out', Server())
    yield g
    g._pool.shutdown(wait=False)


@pytest.fixture
def crawl(tmp_path):
    """Serve a ``.git/`` listing and crawl it. Returns a `Crawl`.

    `sub` maps a sub-listing URL to its own entries; `always` makes every
    unlisted URL return the same entries (an infinitely deep server).
    """
    built = []

    def _crawl(hrefs, sub=None, always=None):
        n = len(built)
        server = Server(
            pages={ANCHOR: listing(hrefs), **{u: listing(e) for u, e in (sub or {}).items()}},
            always=None if always is None else listing(always),
        )
        g = _build(tmp_path / f'sandbox{n}', tmp_path / f'out{n}', server)
        built.append(g)
        g.add_folder(g.url, '.git/')
        return Crawl(server.requested, [tuple(c) for c in g._pending], g.temp_dst_path)

    yield _crawl
    for g in built:
        g._pool.shutdown(wait=False)
