"""C5: a listing that steers the crawler out of the .git tree.

Every entry in ``.git/index.html`` is a same-origin absolute path pointing
*outside* ``.git/``. A same-origin check alone lets them through — they really
are the same host — so a pillager that validates the origin but not the tree
it was aimed at will happily fetch ``/private/CREDENTIALS`` and drop it into
the operator's output directory.

Two things make this worth measuring separately from C1 (traversal) and C4
(absolute writes): nothing here escapes the output directory, and nothing
here is malformed. The listing is a perfectly ordinary page of links. The
only question is whether the crawler knows where it is supposed to be.

The oracle is the server's own ``--watch-regex``: any request under
``/private/`` creates ``PWNED_C5``.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _payload_lib import build_minimal_repo, config_with  # noqa: E402

# Same-origin, well-formed, and none of them under /.git/.
OFF_TREE_HREFS = [
    '/private/CREDENTIALS',
    '/private/backup.sql',
    '/private/',
    '../private/CREDENTIALS',
    'http://127.0.0.1:8080/private/CREDENTIALS',
]

INDEX_HTML = (
    '<!DOCTYPE html>\n'
    '<html>\n'
    '<head><title>Index of /.git/</title></head>\n'
    '<body><h1>Index of /.git/</h1><hr><pre>\n'
    '<a href="HEAD">HEAD</a>\n'
    '<a href="config">config</a>\n'
    + '\n'.join(f'<a href="{h}">{h}</a>' for h in OFF_TREE_HREFS)
    + '\n</pre><hr></body></html>\n'
)


def main() -> None:
    payload = HERE / 'payload'
    build_minimal_repo(payload, config=config_with(''))
    (payload / '.git' / 'index.html').write_text(INDEX_HTML)

    # The bait, served from the same origin but outside .git/.
    private = payload / 'private'
    private.mkdir(exist_ok=True)
    (private / 'CREDENTIALS').write_text('aws_secret_access_key = NOT_A_REAL_KEY\n')
    (private / 'backup.sql').write_text('-- pretend database dump\n')
    print(f'Built C5 payload at {payload}')


if __name__ == '__main__':
    main()
