"""Bridge the security-benchmark traversal corpora to GitHacker's code.

The Docker-based security benchmark (``benchmark/scenarios/security``)
runs the *whole* tool image against a live evil server, which is slow and
needs Docker.  This module pulls the same attacker ``<a href>`` corpora —
``C1_html_traversal`` (relative ``../`` climbs) and
``C4_absolute_path_write`` (server-controlled absolute paths) — straight
out of their ``build.py`` files and drives them through the *real*
``GitHacker.add_folder`` with the HTTP layer mocked.

Two things are pinned, both at unit speed:

* **GREEN for GitHacker** — every benchmark href is neutralised: no
  ``..`` component is ever queued and no queued path resolves outside
  ``temp_dst``.  If a future refactor regresses ``add_folder``, the
  benchmark corpus now also fails fast here instead of only in the
  hours-long Docker run.
* **Non-vacuous** — the corpus genuinely encodes an escape: a naive
  ``os.path.join(output, url_path)`` writer (what the benchmark is built
  to catch) lands the absolute payloads *outside* the output dir.  So the
  GREEN result above is GitHacker defending, not the corpus being inert.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse

import pytest

from githacker.__main__ import GitHacker

SCENARIOS = Path(__file__).resolve(
).parents[1] / 'benchmark' / 'scenarios' / 'security'


def _load_build(scenario: str):
    path = SCENARIOS / scenario / 'build.py'
    spec = importlib.util.spec_from_file_location(f"build_{scenario}", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_C1 = _load_build('C1_html_traversal')
_C4 = _load_build('C4_absolute_path_write')

# (scenario_id, href) pairs so failures name the offending payload.
CORPUS = [('C1', h) for h in _C1.HREFS] + [('C4', h) for h in _C4.HREFS]


# --- minimal add_folder harness (mirrors test_add_folder_traversal) -------

class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200


class _FakeSession:
    expected_origin = None

    def __init__(self, listing_url: str, listing_html: str) -> None:
        self._listing_url = listing_url
        self._listing_html = listing_html
        self.requested_urls: list[str] = []

    def get(self, url: str, *args, **kwargs) -> _FakeResponse:
        self.requested_urls.append(url)
        if url == self._listing_url:
            return _FakeResponse(self._listing_html)
        return _FakeResponse('<html><body></body></html>')


def _make_hacker(tmp_path, session: _FakeSession) -> GitHacker:
    g = GitHacker.__new__(GitHacker)
    g.url = 'http://victim.example/'
    g._origin = ('http', 'victim.example')
    g._origin_path = '/'
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
        return True
    sandbox = os.path.realpath(temp_dst)
    return resolved == sandbox or resolved.startswith(sandbox + os.sep)


# --- the corpus is real signal -------------------------------------------

def test_corpus_is_non_empty():
    # Guard against an import that silently yields [] (which would make
    # every parametrized assertion below vacuously pass).
    assert len(_C1.HREFS) >= 20
    assert len(_C4.HREFS) >= 10


@pytest.mark.parametrize('scenario,href', CORPUS, ids=[f"{s}:{h}" for s, h in CORPUS])
def test_real_add_folder_neutralizes_benchmark_corpus(tmp_path, scenario, href):
    """Every benchmark href, fed through the real add_folder, must keep
    every queued path inside temp_dst with no `..` component."""
    listing_url = 'http://victim.example/.git/'
    listing_html = f'<html><body><a href="{href}">x</a></body></html>'
    session = _FakeSession(listing_url, listing_html)
    g = _make_hacker(tmp_path, session)

    g.add_folder(g.url, '.git/')

    for components in g._pending:
        assert '..' not in components, (
            f"{scenario} href {href!r} queued a traversal component: {components!r}"
        )
        assert _resolves_inside(g.temp_dst, components), (
            f"{scenario} href {href!r} queued {components!r} escaping temp_dst"
        )


def test_c4_corpus_is_non_vacuous():
    """A naive `os.path.join(output, url_path)` writer — exactly what the
    C4 benchmark is built to catch — escapes /output for the plain
    absolute payload. Proves the GREEN result above is GitHacker
    defending, not an inert corpus."""
    base = 'http://victim.example/.git/'
    output = '/output'
    escapes = 0
    for href in _C4.HREFS:
        url_path = urlparse(urljoin(base, href)).path
        naive = os.path.normpath(os.path.join(output, url_path))
        if not (naive == output or naive.startswith(output + os.sep)):
            escapes += 1
    # At minimum the plain "/canary/PWNED_C4" base case must escape.
    assert escapes >= 1, 'C4 corpus encodes no naive-writer escape — would be vacuous'


def test_benchmark_scenarios_serve_their_canary():
    """build.py must emit the canary file the default oracle looks for,
    plus an Index-of listing GitHacker recognises as a directory."""
    for mod, prefix in ((_C1, 'C1'), (_C4, 'C4')):
        mod.main()
        payload = mod.PAYLOAD
        assert (payload / 'canary' / f"PWNED_{prefix}").is_file()
        index = (payload / '.git' / 'index.html').read_text()
        assert '<title>Index of' in index
        assert f"PWNED_{prefix}" in index
