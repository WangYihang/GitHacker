"""Compare recovered git repositories against the original."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from benchmark.models import FeatureResult, ScenarioResult

logger = logging.getLogger(__name__)

Manifest = dict[str, list[str]]


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _parse_packed_refs(path: Path) -> dict[str, str]:
    """Parse a `.git/packed-refs` file into a {refname: sha} mapping.

    Skips comments, blank lines, and the `^<peeled-sha>` continuation
    lines (we want the annotated-tag object SHA, which is what the
    original loose ref file would contain — not the peeled commit).
    """
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        out[ref] = sha
    return out


def _resolve_ref(recovered: Path, ref_kind: str, ref_name: str,
                 packed: dict[str, str]) -> str | None:
    """Return the SHA the recovered repo has for `refs/<ref_kind>/<ref_name>`.

    Tools differ in how they leave the ref store after recovery:
      • git-dumper writes loose refs verbatim → look in `.git/refs/<kind>/<name>`.
      • GitHacker finishes with `git clone temp final`, which moves all
        branches into `refs/remotes/origin/<name>` and packs them into
        `packed-refs` → check both alternative locations as well.

    Returns the first SHA found, or None if the ref is missing entirely.
    """
    git_dir = recovered / ".git"
    candidates = [
        git_dir / "refs" / ref_kind / ref_name,
    ]
    if ref_kind == "heads":
        # `git clone` rewrites local branches as remote-tracking branches.
        candidates.append(git_dir / "refs" / "remotes" / "origin" / ref_name)
    for c in candidates:
        if c.is_file():
            sha = c.read_text(encoding="utf-8", errors="replace").strip()
            if sha:
                return sha
    # Packed-refs fall-throughs: both the original prefix and the rewritten
    # remote-tracking form qualify.
    keys = [f"refs/{ref_kind}/{ref_name}"]
    if ref_kind == "heads":
        keys.append(f"refs/remotes/origin/{ref_name}")
    for k in keys:
        if k in packed:
            return packed[k]
    return None


_REF_PREFIXES = {
    ".git/refs/heads/": "heads",
    ".git/refs/tags/": "tags",
}


def _compare_file_list(
    origin: Path,
    recovered: Path,
    file_list: list[str],
) -> tuple[int, int, list[str], list[str]]:
    """Compare files between origin and recovered repos.

    For branch/tag ref files we resolve by ref name instead of by file
    path so a recovered ref counts whether it landed as a loose file,
    under `refs/remotes/origin/*`, or inside `packed-refs`. Other files
    (source code, hooks, objects, …) still go through the byte-for-byte
    MD5 path.

    Returns (correct, total, different_files, absent_files).
    """
    correct = 0
    total = 0
    different: list[str] = []
    absent: list[str] = []

    packed = _parse_packed_refs(recovered / ".git" / "packed-refs")

    for rel_path in file_list:
        origin_file = origin / rel_path
        recovered_file = recovered / rel_path

        if not origin_file.is_file():
            continue

        total += 1

        # .git/index always differs after checkout — treat as correct
        if ".git/index" in rel_path:
            correct += 1
            continue

        # Ref-by-name resolution for branches and tags.
        ref_kind = next(
            (k for prefix, k in _REF_PREFIXES.items() if rel_path.startswith(prefix)),
            None,
        )
        if ref_kind is not None:
            ref_name = rel_path[len(f".git/refs/{ref_kind}/"):]
            origin_sha = origin_file.read_text(
                encoding="utf-8", errors="replace",
            ).strip()
            recovered_sha = _resolve_ref(recovered, ref_kind, ref_name, packed)
            if recovered_sha is None:
                absent.append(rel_path)
            elif recovered_sha == origin_sha:
                correct += 1
            else:
                different.append(rel_path)
            continue

        if not recovered_file.exists():
            absent.append(rel_path)
            continue

        if _md5(origin_file.read_bytes()) == _md5(recovered_file.read_bytes()):
            correct += 1
        else:
            different.append(rel_path)

    return correct, total, different, absent


def compare_repos(
    origin: Path,
    recovered: Path,
    manifest: Manifest,
) -> ScenarioResult:
    """Compare *recovered* repo against *origin* using a feature manifest.

    Returns a fully populated ``ScenarioResult`` (without timing metrics —
    those are added by the runner).
    """
    features: dict[str, FeatureResult] = {}
    total_correct = 0
    total_files = 0
    all_different: list[str] = []
    all_absent: list[str] = []

    for feature, file_list in manifest.items():
        correct, total, different, absent = _compare_file_list(
            origin, recovered, file_list,
        )
        ratio = round(correct / total * 100, 2) if total > 0 else 0.0
        # A feature is "supported" if any files were recovered, OR if there
        # are no files to recover (vacuously true — e.g. remotes in a local repo)
        supported = (ratio > 0) if total > 0 else True
        features[feature] = FeatureResult(
            supported=supported,
            correct=correct,
            total=total,
            ratio=ratio,
        )
        total_correct += correct
        total_files += total
        all_different.extend(different)
        all_absent.extend(absent)

        level = (
            logging.INFO if ratio == 100.0
            else logging.WARNING if ratio > 0
            else logging.ERROR
        )
        logger.log(level, "  %s: [%d/%d] = %.2f%%", feature, correct, total, ratio)

    overall_ratio = round(total_correct / total_files * 100, 2) if total_files > 0 else 0.0

    return ScenarioResult(
        correct=total_correct,
        total=total_files,
        ratio=overall_ratio,
        features=features,
        different_files=all_different,
        absent_files=all_absent,
    )
