# GHSA-hr3m-4qwq-3mgc

| | |
|---|---|
| Title | Path traversal in GitHacker ref/hash parsing enables existence oracle and hex-fragment exfiltration via a malicious .git server |
| Package | `GitHacker` (PyPI) |
| Affected | `<= 1.1.7` |
| Patched | `1.1.8` |
| Severity | Moderate (CVSS 5.3) |
| CVSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| Weaknesses | CWE-22, CWE-23 |
| GHSA | [GHSA-hr3m-4qwq-3mgc](https://github.com/WangYihang/GitHacker/security/advisories/GHSA-hr3m-4qwq-3mgc) |
| CVE | _pending GitHub CNA assignment_ |
| Reporter | Zac Wang ([@7a6163](https://github.com/7a6163)) |

## Summary

GitHacker through 1.1.7 did not validate path segments parsed from attacker-controlled `.git/HEAD` before joining them onto its output directory. A malicious server could coerce GitHacker into reading arbitrary local files. Contents do not stream back wholesale, but the recovery loop turns any 40-character hex substring into an outbound HTTP `GET` — an existence oracle for arbitrary paths plus hex-fragment exfiltration of file contents.

## Details

### Vulnerability

GitHacker rebuilds a remote `.git/` by fetching files into `temp_dst`. Two functions derived filesystem paths from server-controlled content:

- `add_head_file_tasks` reads the downloaded `.git/HEAD`, parses `ref: <ref-path>`, and joins the raw ref-path onto `temp_dst/.git/logs/` before reading the resulting file.
- `add_hashes_parsed` scans any file it reads for 40-character hex substrings and emits `GET .git/objects/<sha[0:2]>/<sha[2:]>` for each one — onto the attacker's server and into the local output tree.

Pre-fix, `add_head_file_tasks` did not validate the ref segments. A malicious `.git/HEAD` of

```
ref: ../../../../../../etc/passwd
```

caused `add_head_file_tasks` to traverse out of `temp_dst` and read `/etc/passwd`. The bytes flowed into `add_hashes_parsed`, which emitted one outbound HTTP request per 40-char-hex match — observable on the attacker's logs.

### Impact

PR #65 originally classified this as arbitrary local file read. Joint analysis during coordinated disclosure narrowed the primitive: file contents do not stream back wholesale because the only egress channel is the 40-char-hex regex. In practice an attacker can:

- **Existence oracle** for any path on the GitHacker host (`/etc/shadow`, `/root/.ssh/id_rsa`, `/home/<user>/.git-credentials`, build artifacts under `/tmp/`).
- **Hex-fragment exfiltration** when the targeted file contains 40-char hex sequences: other git repos' refs / pack filenames, password hashes, HMAC-SHA1 outputs, some session tokens.

Not exploitable without victim action: the attacker must persuade the victim to run GitHacker against a URL they control. Project guidance has always been to run GitHacker inside a disposable container.

### Scoping note: no write-side primitive in 1.1.7

A working write-side primitive (attacker drops content outside `temp_dst` via `add_folder` / `add_task`) does **not** reproduce against the shipped 1.1.7 source. Empirical testing by the reporter against `GitHacker-1.1.7.tar.gz` (25 traversal-style payloads including `....//`, `%2e%2e%2f`, layered `foo/../../`, NUL bytes, backslash variants, absolute paths) yielded 0/25 escapes. Two structural reasons:

1. `add_folder` anchors every derived path on `self.url + '.git/'`, so the first path component after the `url_length` strip is always `.git`. `os.path.join`'s absolute-path short-circuit never fires.
2. Python's `str.replace("..", "")` is greedy non-overlapping; `....//` collapses to `//`, `......//` to `///`, etc. No literal `..` survives into `add_task`.

`5f2a8ba` is still the correct fix for the read-side primitive and additionally hardens `add_task` as defense in depth against future regressions — for example, if a later caller removes the `.git/` anchor in `add_folder` or wires a new server-controlled segment source into `add_task`.

### Fix

Commit [`5f2a8ba`](https://github.com/WangYihang/GitHacker/commit/5f2a8ba) introduces `_is_safe_path_segment` as a single trust boundary: every segment about to be joined onto `temp_dst` or appended to an outgoing URL is validated against an allowlist before `add_task` accepts it. Empty / `.` / `..` / separators / NUL / control characters are rejected; the brittle `replace("..", "")` filter is removed.

The fix also tightens adjacent surfaces preemptively:

- `add_folder` switches to `urlparse`-based scheme + netloc + path comparison.
- `construct_url_from_path_components` percent-encodes every segment.

PR #65's two-layer defense (allowlist regex + `os.path.realpath()` confinement) was consolidated onto the allowlist applied at queue-time, removing the TOCTOU window an after-the-fact `realpath()` check leaves open and the per-call-site drift risk. PR #65 was closed in favour of the broader fix.

Regression tests in [`tests/test_ref_validation.py`](https://github.com/WangYihang/GitHacker/blob/main/tests/test_ref_validation.py) (commit [`16fcd81`](https://github.com/WangYihang/GitHacker/commit/16fcd81)) pin the PoC and six bypass variants (extra-depth, mid-path, NUL, absolute path, leading-dot, `.lock`-suffix).

### Credit

Reported and patched-prototyped by **Zac Wang** ([@7a6163](https://github.com/7a6163)) in [#65](https://github.com/WangYihang/GitHacker/pull/65). Zac refined the impact framing from "arbitrary file read" to "existence oracle + hex-fragment exfiltration" and verified the absence of a write-side primitive against the shipped 1.1.7 sdist with a 25-payload harness.

## Patches

Patched in 1.1.8 (commit [`5f2a8ba`](https://github.com/WangYihang/GitHacker/commit/5f2a8ba); tests [`16fcd81`](https://github.com/WangYihang/GitHacker/commit/16fcd81)).

## Workarounds

Run GitHacker inside a disposable container. Do not point GitHacker at any URL whose contents are not under your control.

## References

- https://github.com/WangYihang/GitHacker/pull/65
- https://github.com/WangYihang/GitHacker/commit/5f2a8ba
- https://github.com/WangYihang/GitHacker/blob/main/tests/test_ref_validation.py
- https://githacker.pages.dev/security
- https://github.com/justinsteven/advisories
- https://drivertom.blogspot.com/2021/08/git.html
