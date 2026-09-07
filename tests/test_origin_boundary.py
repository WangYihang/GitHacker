"""Attack surface: the origin boundary.

Two gates decide whether a URL is still "ours": ``_is_same_origin_descendant``
for URLs the crawler derives itself, and ``OriginRestrictedSession`` for
``Location`` headers the server pushes at us. Both compare a parsed
``(scheme, netloc)``, so every test here is a URL a parser might read
differently from a human.
"""

from __future__ import annotations

import pytest

from githacker.__main__ import OriginRestrictedSession

ORIGIN = ('http', 'victim.example')


class Redirect:
    """The fields ``get_redirect_target`` reads off a response."""

    def __init__(self, location, url='http://victim.example/.git/HEAD'):
        self.url = url
        self.status_code = 302
        self.headers = {'location': location} if location else {}
        self.is_redirect = location is not None


@pytest.fixture
def session():
    s = OriginRestrictedSession()
    s.expected_origin = ORIGIN
    return s


# ---------------------------------------------------------------------------
# _is_same_origin_descendant — URLs the crawler derives from a listing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'url',
    [
        'http://victim.example@attacker.example/.git/HEAD',  # userinfo before the real host
        'http://victim.example.attacker.com/.git/HEAD',  # suffix domain
        'http://attacker.com/?x=http://victim.example/.git/',  # our name in a query
        'http://attacker.com/#http://victim.example/.git/',  # our name in a fragment
        'http://attacker.com/http://victim.example/.git/',  # our name in the path
        'https://victim.example/.git/HEAD',  # scheme differs
        'http://victim.example:8080/.git/HEAD',  # port differs
        'http://victim.example./.git/HEAD',  # trailing-dot FQDN
    ],
)
def test_lookalike_url_is_not_same_origin(hacker, url):
    assert hacker._is_same_origin_descendant(url) is False


@pytest.mark.parametrize(
    'url',
    [
        'http://VICTIM.EXAMPLE/.git/HEAD',  # DNS is case-insensitive; this check is not
        'http://victim.example:80/.git/HEAD',  # the explicit default port
    ],
)
def test_equivalent_url_is_rejected_because_the_origin_is_not_normalised(hacker, url):
    """Pins current behaviour, which is fail-closed: these URLs *are* ours and
    get refused anyway, costing data rather than safety. Same over-rejection
    family as #82, so it is recorded rather than left to be discovered."""
    assert hacker._is_same_origin_descendant(url) is False


def test_origin_check_alone_does_not_stop_traversal(hacker):
    """``urlparse`` does not normalise ``..``, so a path can prefix-match the
    origin path and still point above it. This gate is a *host* check, not a
    traversal check — what actually stops traversal is the per-segment gate
    downstream. Any new caller has to re-validate; this test says so."""
    assert hacker._is_same_origin_descendant('http://victim.example/../../etc/passwd') is True


def test_traversal_that_passes_the_origin_check_is_stopped_downstream(crawl):
    """The other half of the test above: the pipeline as a whole still holds."""
    assert crawl(['../../etc/passwd']).escaping() == []


def test_sibling_path_is_not_a_descendant(hacker):
    """`/pathological/` must not count as living under `/path/` — the classic
    string-prefix bug."""
    hacker.url = 'http://victim.example/path/'
    hacker._origin_path = '/path/'
    assert (
        hacker._is_same_origin_descendant('http://victim.example/pathological/.git/HEAD') is False
    )


# ---------------------------------------------------------------------------
# OriginRestrictedSession — Location headers the server controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'location',
    [
        'http://attacker.example/x',  # plain cross-host
        '//attacker.example/x',  # protocol-relative
        'http://victim.example@attacker.example/x',  # userinfo lookalike
        'http://victim.example:8080/x',  # different port
        'https://victim.example/x',  # scheme upgrade
        'http://127.0.0.1:6379/x',  # SSRF at the loopback
        'http://[::1]:6379/x',  # ...and its IPv6 spelling
        'file:///etc/passwd',  # scheme change to a local read
    ],
)
def test_redirect_off_origin_is_refused(session, location):
    assert session.get_redirect_target(Redirect(location)) is None


@pytest.mark.parametrize('location', ['/.git/refs/heads/main', 'refs/heads/main'])
def test_same_origin_redirect_is_still_followed(session, location):
    """The guard must not break ordinary redirects, or every target behind a
    normalising proxy stops working."""
    assert session.get_redirect_target(Redirect(location)) == location


def test_redirect_guard_is_inert_without_an_expected_origin():
    """An unconfigured session must behave exactly like requests.Session, so
    the guard cannot silently change unrelated call sites."""
    s = OriginRestrictedSession()
    assert (
        s.get_redirect_target(Redirect('http://anywhere.example/x')) == 'http://anywhere.example/x'
    )


def test_non_redirect_response_has_no_target(session):
    assert session.get_redirect_target(Redirect(None)) is None
