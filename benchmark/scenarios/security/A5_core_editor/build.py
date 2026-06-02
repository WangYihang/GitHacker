"""A5: malicious core.editor in .git/config.

Fires on interactive git operations (commit, rebase --interactive).
Pillagers almost never trigger these, but we test for completeness.
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
        config=config_with('\teditor = "touch /canary/PWNED_A5; true"\n'),
    )
    print(f'Built A5 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
