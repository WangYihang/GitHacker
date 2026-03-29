"""Run a single tool against a single scenario and collect metrics."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path

from benchmark.compare import Manifest, compare_repos
from benchmark.config import FEATURES
from benchmark.docker import (
    get_request_count,
    restart_service,
    run_tool_container,
)
from benchmark.models import FeatureResult, ScenarioResult, Tool

logger = logging.getLogger(__name__)


def _scenario_url(scenario: str) -> str:
    if scenario == "php-lfi":
        return "http://host.docker.internal/lfi.php?file=./"
    return "http://host.docker.internal"


def _find_recovered_repo(output_dir: Path) -> Path:
    """Locate the actual .git root in the output directory (up to 2 levels)."""
    if (output_dir / ".git").exists():
        return output_dir
    # Level 1: direct children
    for child in _safe_iterdir(output_dir):
        if child.is_dir() and (child / ".git").exists():
            return child
    # Level 2: grandchildren
    for child in _safe_iterdir(output_dir):
        if child.is_dir():
            for grandchild in _safe_iterdir(child):
                if grandchild.is_dir() and (grandchild / ".git").exists():
                    return grandchild
    return output_dir


def _safe_iterdir(path: Path):
    """Iterate a directory, returning empty on error."""
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _empty_result(error: str) -> ScenarioResult:
    return ScenarioResult(
        correct=0,
        total=0,
        ratio=0.0,
        features={
            f: FeatureResult(supported=False, correct=0, total=0, ratio=0.0)
            for f in FEATURES
        },
        error=error,
    )


def run_tool_scenario(
    tool: Tool,
    scenario: str,
    origin: Path,
    manifest: Manifest,
    output_dir: Path,
) -> ScenarioResult:
    """Execute *tool* against *scenario* and return a ``ScenarioResult``.

    The result includes file-recovery accuracy, timing, request count, and
    exit code.
    """
    url = _scenario_url(scenario)
    logger.info("Running %s against %s ...", tool.id, scenario)

    # Clean output directory to prevent stale results from previous scenarios
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Restart server to reset access logs for accurate request counting
    restart_service(scenario)

    start = time.monotonic()
    try:
        proc = run_tool_container(tool.id, url, output_dir)
        duration = round(time.monotonic() - start, 2)
        exit_code = proc.returncode

        if exit_code != 0:
            logger.warning("%s exited with code %d on %s", tool.id, exit_code, scenario)

        http_requests = get_request_count(scenario)
        logger.info(
            "  %s: %.1fs, exit=%d, requests=%s",
            tool.id, duration, exit_code,
            http_requests if http_requests is not None else "N/A",
        )

        # Compare recovered files
        recovered = _find_recovered_repo(output_dir)
        result = compare_repos(origin, recovered, manifest)
        result.duration = duration
        result.exit_code = exit_code
        result.http_requests = http_requests
        return result

    except subprocess.TimeoutExpired:
        duration = round(time.monotonic() - start, 2)
        logger.error("%s timed out on %s after %.1fs", tool.id, scenario, duration)
        http_requests = get_request_count(scenario)
        result = _empty_result("Tool timed out")
        result.duration = duration
        result.exit_code = -1
        result.http_requests = http_requests
        return result

    except Exception as exc:
        duration = round(time.monotonic() - start, 2)
        logger.error("%s failed on %s: %s", tool.id, scenario, exc)
        result = _empty_result(str(exc))
        result.duration = duration
        result.exit_code = -1
        return result
