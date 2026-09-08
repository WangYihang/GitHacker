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

# A pillager that got as far as talking to the target makes at least a handful
# of requests (HEAD, config, refs...). Fewer means it never started.
MIN_MEANINGFUL_REQUESTS = 3


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
