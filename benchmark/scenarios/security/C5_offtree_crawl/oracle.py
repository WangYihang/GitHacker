"""Oracle for C5: was the crawler steered outside the .git tree?

The server writes ``PWNED_C5`` when anything requests a path under
``/private/`` (``watch_regex`` in meta.toml), so the finding detects itself.

What the watch cannot tell us is whether the tool ran at all. A pillager that
fails to start requests nothing and looks exactly like one that read the
listing and correctly declined to follow it off-tree, so a run with almost no
traffic is reported as inconclusive rather than as a pass.

Not reading directory listings at all is a legitimate way to pass: a tool that
only probes known ``.git`` paths cannot be steered by a listing. The guard is
therefore on whether the tool ran, not on whether it fetched the listing.
"""

from __future__ import annotations

from pathlib import Path

# An index-driven pillager engages the target in as few as two requests: fetch
# .git/index, then the blobs it names. That is a real run, and never reading a
# listing is a legitimate way to be immune here — so the bar is only "did it
# talk to the target at all".
MIN_MEANINGFUL_REQUESTS = 2


def check(output_dir: Path, canary_dir: Path, proc):
    from benchmark.security import Verdict

    if (canary_dir / 'PWNED_C5').exists():
        return Verdict.FAIL, 'PWNED_C5 created in canary dir'

    log = canary_dir / 'access.log'
    requests = log.read_text().splitlines() if log.exists() else []
    if len(requests) < MIN_MEANINGFUL_REQUESTS:
        return Verdict.ERROR, (
            f'only {len(requests)} requests: the tool never ran against the '
            f'target, so this run proves nothing about off-tree crawling'
        )
    return Verdict.PASS, ''
