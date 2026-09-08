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

# Below this the tool cannot have crawled the listing at all — it failed to
# start, or refused the target. Reporting that as PASS would credit a tool for
# a bound it never demonstrated, so it is called out as inconclusive instead.
MIN_MEANINGFUL_REQUESTS = 4


def check(output_dir: Path, canary_dir: Path, proc):
    from benchmark.security import Verdict

    log = canary_dir / 'access.log'
    requests = len(log.read_text().splitlines()) if log.exists() else 0

    if requests < MIN_MEANINGFUL_REQUESTS:
        return Verdict.ERROR, (
            f'only {requests} requests: the tool never crawled the listing, so '
            f'this run says nothing about how it bounds recursion'
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

    return Verdict.PASS, ''
