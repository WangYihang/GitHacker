"""Assemble and write the benchmark report."""

from __future__ import annotations

import datetime
import json
import logging
import subprocess
from pathlib import Path

from benchmark.config import DOCS_DATA_PATH, FEATURES, RESULTS_PATH, SCENARIOS
from benchmark.models import BenchmarkReport, Metadata, ScenarioResult, Tool

logger = logging.getLogger(__name__)


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def build_report(
    tools: dict[str, Tool],
    results: dict[str, dict[str, ScenarioResult]],
    seed: int = 0,
) -> BenchmarkReport:
    """Create a ``BenchmarkReport`` from collected results."""
    return BenchmarkReport(
        metadata=Metadata(
            generated_at=datetime.datetime.now(datetime.UTC).isoformat(),
            git_commit=_git_commit(),
            test_repo_seed=seed,
        ),
        tools=tools,
        scenarios=SCENARIOS,
        features=FEATURES,
        results=results,
    )


def write_report(report: BenchmarkReport) -> Path:
    """Serialise *report* to JSON and write to results/ and docs/."""
    data = report.to_dict()

    RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    output = RESULTS_PATH / "benchmark.json"
    output.write_text(json.dumps(data, indent=2))
    logger.info("Saved %s", output)

    DOCS_DATA_PATH.mkdir(parents=True, exist_ok=True)
    docs_copy = DOCS_DATA_PATH / "benchmark.json"
    docs_copy.write_text(json.dumps(data, indent=2))
    logger.info("Copied to %s", docs_copy)

    return output


def print_summary(
    tools: dict[str, Tool],
    results: dict[str, dict[str, ScenarioResult]],
) -> None:
    """Log a human-readable summary table."""
    logger.info("=" * 72)
    logger.info("SUMMARY")
    logger.info("=" * 72)
    for tid, tool in tools.items():
        for scenario in SCENARIOS:
            r = results.get(tid, {}).get(scenario)
            if not r:
                continue
            reqs = str(r.http_requests) if r.http_requests is not None else "N/A"
            dur = f"{r.duration:.1f}s" if r.duration is not None else "N/A"
            logger.info(
                "  %-20s | %-25s | %3d/%3d = %6.2f%% | %7s | reqs=%5s",
                tool.name, scenario, r.correct, r.total, r.ratio, dur, reqs,
            )
