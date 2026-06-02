"""Paths, constants, and tool loading."""

from __future__ import annotations

import tomllib
from pathlib import Path

from benchmark.models import Tool

# Paths (all relative to project root)
BENCHMARK_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BENCHMARK_DIR.parent
REPO_PATH = PROJECT_ROOT / 'test' / 'repo'
PLAYGROUND_PATH = PROJECT_ROOT / 'playground'
RESULTS_PATH = BENCHMARK_DIR / 'results'
TOOLS_DIR = BENCHMARK_DIR / 'tools'
DOCKER_DIR = PROJECT_ROOT / 'test' / 'docker'
DOCS_DATA_PATH = PROJECT_ROOT / 'docs' / 'public' / 'data'

# Benchmark parameters
TOOL_TIMEOUT = 300  # seconds per tool per scenario
RANDOM_SEED = 0

SCENARIOS = [
    'apache-index-enabled',
    'apache-index-disabled',
    'nginx-index-enabled',
    'nginx-index-disabled',
    'php-lfi',
]

FEATURES = [
    'source_code',
    'reflogs',
    'stashes',
    'commits',
    'branches',
    'remotes',
    'tags',
]


def load_tools() -> dict[str, Tool]:
    """Load tool definitions from tools.toml."""
    tools_file = BENCHMARK_DIR / 'tools.toml'
    with open(tools_file, 'rb') as f:
        raw = tomllib.load(f)
    return {tid: Tool(id=tid, name=cfg['name'], url=cfg['url']) for tid, cfg in raw.items()}
