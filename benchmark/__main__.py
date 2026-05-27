"""CLI entry point: ``python -m benchmark``."""

from __future__ import annotations

import argparse
import logging
import os
import shutil

import coloredlogs

from benchmark import config
from benchmark.config import (
    PLAYGROUND_PATH,
    REPO_PATH,
    SCENARIOS,
    load_tools,
)
from benchmark.docker import build_image, compose_service, get_tool_version
from benchmark.generate import generate_repo
from benchmark.models import ScenarioResult
from benchmark.report import build_report, print_summary, write_report
from benchmark.runner import run_tool_scenario


def setup_logging(verbose: bool = False) -> None:
    coloredlogs.install(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )


def cmd_run(args: argparse.Namespace) -> None:
    """Run the full benchmark suite."""
    tools = load_tools()

    # Step 1 — generate test repo
    logging.info("=" * 60)
    logging.info("Step 1: Generating test repository")
    logging.info("=" * 60)
    manifest = generate_repo(REPO_PATH)

    # Step 2 — build tool images and extract versions
    logging.info("=" * 60)
    logging.info("Step 2: Building tool Docker images")
    logging.info("=" * 60)
    for tid, tool in tools.items():
        try:
            build_image(tid)
            tool.version = get_tool_version(tid)
            logging.info("  %s: version %s", tool.name, tool.version)
        except FileNotFoundError:
            logging.warning("  %s: no Dockerfile, skipping", tool.name)

    # Step 3 — run benchmarks
    logging.info("=" * 60)
    logging.info("Step 3: Running benchmarks")
    logging.info("=" * 60)
    if PLAYGROUND_PATH.exists():
        shutil.rmtree(PLAYGROUND_PATH)

    results: dict[str, dict[str, ScenarioResult]] = {}
    for scenario in SCENARIOS:
        logging.info("\n--- Scenario: %s ---", scenario)
        with compose_service(scenario):
            for tid, tool in tools.items():
                output_dir = PLAYGROUND_PATH / tid / scenario
                result = run_tool_scenario(
                    tool, scenario, REPO_PATH, manifest, output_dir,
                )
                results.setdefault(tid, {})[scenario] = result

    # Step 4 — report
    logging.info("=" * 60)
    logging.info("Step 4: Generating report")
    logging.info("=" * 60)
    report = build_report(tools, results, seed=config.RANDOM_SEED)
    write_report(report)
    print_summary(tools, results)


def cmd_generate(args: argparse.Namespace) -> None:
    """Only generate the test repository."""
    manifest = generate_repo(REPO_PATH)
    logging.info("Generated test repo at %s (%d features)", REPO_PATH, len(manifest))


def cmd_security(args: argparse.Namespace) -> None:
    """Run the security benchmark suite."""
    from benchmark import security

    tool_ids = [s.strip() for s in args.tools.split(",")] if args.tools else None
    test_ids = [s.strip() for s in args.tests.split(",")] if args.tests else None
    report = security.run_security_suite(
        tool_ids=tool_ids,
        test_ids=test_ids,
        category=args.category,
    )
    security.write_report(report)
    security.print_summary(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="GitHacker benchmark suite",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--timeout", type=int,
        default=int(os.environ.get("GITHACKER_BENCH_TIMEOUT", config.TOOL_TIMEOUT)),
        help="Per-tool, per-scenario timeout in seconds (default: %(default)d)",
    )
    parser.add_argument(
        "--seed", type=int,
        default=int(os.environ.get("GITHACKER_BENCH_SEED", config.RANDOM_SEED)),
        help="Random seed used in the report header (default: %(default)d)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("run", help="Run the full benchmark suite (default)")
    sub.add_parser("generate", help="Only generate the test repository")

    sec = sub.add_parser(
        "security",
        help="Run the security benchmark suite (malicious .git/ payloads)",
    )
    sec.add_argument("--tools", help="Comma-separated tool IDs to test (default: all)")
    sec.add_argument("--tests", help="Comma-separated test IDs to run (default: all)")
    sec.add_argument("--category", help="Filter by category (RCE, AFW, Info, CVE)")

    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    # Override module-scope defaults so downstream callers (runner, report)
    # see the user's choices without having to thread args through.
    config.TOOL_TIMEOUT = args.timeout
    config.RANDOM_SEED = args.seed

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "security":
        cmd_security(args)
    else:
        cmd_run(args)


if __name__ == "__main__":
    main()
