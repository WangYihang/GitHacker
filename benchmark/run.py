"""
Main benchmark orchestration script.
Generates test repo, runs all tools against all scenarios, collects results into benchmark.json.
"""

import datetime
import json
import logging
import os
import shutil
import subprocess
import time

import coloredlogs

from diff import diff_repo
from gen import generate_repo

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')

# Configuration
REPO_PATH = os.path.join(os.path.dirname(__file__), '..', 'test', 'repo')
PLAYGROUND_PATH = os.path.join(os.path.dirname(__file__), '..', 'playground')
RESULTS_PATH = os.path.join(os.path.dirname(__file__), 'results')
TOOLS_PATH = os.path.join(os.path.dirname(__file__), 'tools')
DOCKER_PATH = os.path.join(os.path.dirname(__file__), '..', 'test', 'docker')

TOOL_TIMEOUT = 300  # 5 minutes per tool per scenario

TOOLS = {
    'githacker': {
        'name': 'GitHacker',
        'url': 'https://github.com/WangYihang/GitHacker',
    },
    'gittools': {
        'name': 'GitTools',
        'url': 'https://github.com/internetwache/GitTools',
    },
    'dvcs-ripper': {
        'name': 'dvcs-ripper',
        'url': 'https://github.com/kost/dvcs-ripper',
    },
    'githack': {
        'name': 'GitHack',
        'url': 'https://github.com/lijiejie/GitHack',
    },
    'git-dumper': {
        'name': 'git-dumper',
        'url': 'https://github.com/arthaud/git-dumper',
    },
}

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


def build_tool_images():
    """Build Docker images for all benchmark tools."""
    for tool_id in TOOLS:
        tool_dir = os.path.join(TOOLS_PATH, tool_id)
        if not os.path.exists(os.path.join(tool_dir, 'Dockerfile')):
            logging.warning(f"No Dockerfile for {tool_id}, skipping build")
            continue
        image_name = f"benchmark-{tool_id}"
        logging.info(f"Building Docker image: {image_name}")
        subprocess.run(
            ['docker', 'build', '-t', image_name, tool_dir],
            check=True,
            capture_output=True,
        )
        logging.info(f"Built {image_name}")


def start_server(scenario):
    """Start the web server Docker container for a scenario."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    logging.info(f"Starting server: {scenario}")
    subprocess.run(
        ['docker-compose', 'up', '-d'],
        cwd=compose_dir,
        check=True,
        capture_output=True,
    )
    # Wait for server to be ready
    time.sleep(3)


def stop_server(scenario):
    """Stop the web server Docker container for a scenario."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    logging.info(f"Stopping server: {scenario}")
    subprocess.run(
        ['docker-compose', 'down'],
        cwd=compose_dir,
        check=True,
        capture_output=True,
    )


def get_url_for_scenario(scenario):
    """Return the URL to use for a given scenario."""
    if scenario == 'php-lfi':
        return 'http://host.docker.internal/lfi.php?file=./'
    return 'http://host.docker.internal'


def run_tool(tool_id, scenario, output_dir):
    """Run a single tool against a scenario. Returns True if successful."""
    image_name = f"benchmark-{tool_id}"
    url = get_url_for_scenario(scenario)

    os.makedirs(output_dir, exist_ok=True)

    logging.info(f"Running {tool_id} against {scenario}...")

    try:
        result = subprocess.run(
            [
                'docker', 'run', '--rm',
                '--add-host=host.docker.internal:host-gateway',
                '-v', f"{os.path.abspath(output_dir)}:/output",
                image_name,
                url, '/output',
            ],
            timeout=TOOL_TIMEOUT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logging.warning(
                f"{tool_id} exited with code {result.returncode} on {scenario}",
            )
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"{tool_id} timed out on {scenario}")
        return False
    except Exception as e:
        logging.error(f"{tool_id} failed on {scenario}: {e}")
        return False


def find_recovered_repo(output_dir):
    """Find the actual recovered repo directory (tools may create subdirectories)."""
    # Check if .git exists directly in output_dir
    if os.path.exists(os.path.join(output_dir, '.git')):
        return output_dir

    # Check subdirectories
    for entry in os.listdir(output_dir):
        subdir = os.path.join(output_dir, entry)
        if os.path.isdir(subdir) and os.path.exists(os.path.join(subdir, '.git')):
            return subdir

    # Fall back to output_dir itself
    return output_dir


def run_benchmark():
    """Run the full benchmark suite."""
    # Step 1: Generate test repo
    logging.info("=" * 60)
    logging.info("Step 1: Generating test repository")
    logging.info("=" * 60)
    repo_path = os.path.abspath(REPO_PATH)
    shutil.rmtree(repo_path, ignore_errors=True)
    manifest = generate_repo(repo_path)

    # Step 2: Build tool images
    logging.info("=" * 60)
    logging.info("Step 2: Building tool Docker images")
    logging.info("=" * 60)
    build_tool_images()

    # Step 3: Run tools against scenarios
    logging.info("=" * 60)
    logging.info("Step 3: Running benchmarks")
    logging.info("=" * 60)

    results = {}
    playground_path = os.path.abspath(PLAYGROUND_PATH)
    shutil.rmtree(playground_path, ignore_errors=True)

    for scenario in SCENARIOS:
        logging.info(f"\n--- Scenario: {scenario} ---")
        start_server(scenario)

        try:
            for tool_id in TOOLS:
                output_dir = os.path.join(
                    playground_path, tool_id, scenario,
                )
                success = run_tool(tool_id, scenario, output_dir)

                if success:
                    recovered_path = find_recovered_repo(output_dir)
                    logging.info(f"Comparing {tool_id} results for {scenario}...")
                    result = diff_repo(repo_path, recovered_path, manifest)
                else:
                    result = {
                        'correct': 0,
                        'total': 0,
                        'ratio': 0.0,
                        'different_files': [],
                        'absent_files': [],
                        'features': {
                            f: {'supported': False, 'correct': 0, 'total': 0, 'ratio': 0.0}
                            for f in FEATURES
                        },
                        'error': 'Tool timed out or failed to run',
                    }

                if tool_id not in results:
                    results[tool_id] = {}
                results[tool_id][scenario] = result
        finally:
            stop_server(scenario)

    # Step 4: Assemble benchmark.json
    logging.info("=" * 60)
    logging.info("Step 4: Generating benchmark.json")
    logging.info("=" * 60)

    git_commit = 'unknown'
    try:
        git_commit = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            text=True,
        ).strip()
    except Exception:
        pass

    benchmark = {
        'metadata': {
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'git_commit': git_commit,
            'test_repo_seed': 0,
        },
        'tools': {
            tool_id: {
                'name': info['name'],
                'url': info['url'],
            }
            for tool_id, info in TOOLS.items()
        },
        'scenarios': SCENARIOS,
        'features': FEATURES,
        'results': results,
    }

    os.makedirs(RESULTS_PATH, exist_ok=True)
    output_path = os.path.join(RESULTS_PATH, 'benchmark.json')
    with open(output_path, 'w') as f:
        json.dump(benchmark, f, indent=2)

    # Also copy to docs/data/
    docs_data_path = os.path.join(
        os.path.dirname(__file__), '..', 'docs', 'data',
    )
    os.makedirs(docs_data_path, exist_ok=True)
    shutil.copy2(output_path, os.path.join(docs_data_path, 'benchmark.json'))

    logging.info(f"Benchmark results saved to {output_path}")
    logging.info("Results also copied to docs/data/benchmark.json")

    # Print summary
    logging.info("\n" + "=" * 60)
    logging.info("SUMMARY")
    logging.info("=" * 60)
    for tool_id in TOOLS:
        for scenario in SCENARIOS:
            if tool_id in results and scenario in results[tool_id]:
                r = results[tool_id][scenario]
                logging.info(
                    f"  {tool_id:15s} | {scenario:25s} | "
                    f"{r['correct']:3d}/{r['total']:3d} = {r['ratio']:6.2f}%",
                )


if __name__ == '__main__':
    run_benchmark()
