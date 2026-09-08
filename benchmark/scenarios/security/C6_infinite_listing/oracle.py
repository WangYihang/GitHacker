"""Oracle for C6: did the crawler stop on its own?

The server (``server_mode = "infinite"``) answers every directory request
with a listing offering exactly one more subdirectory. The tree is therefore
bottomless but only one entry wide, so a crawler that bounds itself in any
way — a visited set, a depth cap, a request budget — finishes in a handful of
requests. One that does not, walks until something external stops it: a
timeout, a recursion limit, or the filesystem refusing a path that has grown
past its length limit.

Counting requests in the server's access log is what makes this comparable
across tools: it does not matter *how* an unbounded crawler dies, only that
it went far past any depth a real repository has.
"""

from __future__ import annotations

from pathlib import Path

# The deepest real .git tree is about 4 levels (.git/objects/ab/, .git/refs/
# remotes/origin/). A crawler that issues more requests than this against a
# tree one entry wide is not bounding its recursion.
REQUEST_BUDGET = 100

# Only a tool that never spoke to the target is inconclusive. A tool that ran
# and issued a handful of requests has terminated — trivially so if it does not
# crawl listings at all, which is still termination.
MIN_MEANINGFUL_REQUESTS = 1

# Below this the tool plainly does not walk the listing, so its bound is
# trivial. Worth saying in the evidence rather than leaving the reader to
# assume it resisted an attack it never met.
NOT_A_CRAWLER = 5


def check(output_dir: Path, canary_dir: Path, proc):
    from benchmark.security import Verdict

    log = canary_dir / 'access.log'
    requests = len(log.read_text().splitlines()) if log.exists() else 0

    if requests < MIN_MEANINGFUL_REQUESTS:
        return Verdict.ERROR, (
            'the tool sent no requests: it never met the bottomless listing, so '
            'this run says nothing about how it bounds recursion'
        )

    if requests > REQUEST_BUDGET:
        return Verdict.FAIL, (
            f'{requests} requests against a one-entry-wide tree '
            f'(budget {REQUEST_BUDGET}): recursion is unbounded'
        )

    # A tool can also stop by crashing. That is not "bounded", it is "died" —
    # and it leaves a non-zero exit with the recursion still visible in the log.
    if proc is not None and proc.returncode not in (0, None) and requests > 10:
        tail = '\n'.join((proc.stderr or '').splitlines()[-3:])
        return Verdict.FAIL, f'exited {proc.returncode} after {requests} requests: {tail}'

    if requests < NOT_A_CRAWLER:
        return Verdict.PASS, (
            f'{requests} requests: the tool does not walk directory listings, so '
            f'the bottomless tree never applies to it'
        )
    return Verdict.PASS, ''
