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


def _compare_file_list(
    origin: Path,
    recovered: Path,
    file_list: list[str],
) -> tuple[int, int, list[str], list[str]]:
    """Compare files between origin and recovered repos.

    Returns (correct, total, different_files, absent_files).
    """
    correct = 0
    total = 0
    different: list[str] = []
    absent: list[str] = []

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
        features[feature] = FeatureResult(
            supported=ratio > 0,
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
