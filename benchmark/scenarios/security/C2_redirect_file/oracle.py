"""Oracle for C2: did the pillager actually fetch /etc/passwd?

A vulnerable pillager that follows ``file://`` redirects writes the
contents of ``/etc/passwd`` somewhere under the recovered ``.git/``
directory (or the working tree). We declare FAIL if any file in the
output dir contains the unmistakable ``root:x:0:0:`` prefix that
``/etc/passwd`` always starts with.
"""

from __future__ import annotations

from pathlib import Path

from benchmark.security import Verdict

_MARKER = b'root:x:0:0:'


def check(output_dir: Path, canary_dir: Path, proc) -> tuple[Verdict, str]:
    if not output_dir.exists():
        return Verdict.PASS, ''
    for path in output_dir.rglob('*'):
        if not path.is_file():
            continue
        try:
            head = path.read_bytes()[:512]
        except OSError:
            continue
        if _MARKER in head:
            return Verdict.FAIL, f'{path.relative_to(output_dir)} contains /etc/passwd content'
    return Verdict.PASS, ''
