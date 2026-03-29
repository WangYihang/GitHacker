"""
Main benchmark orchestration script.
Generates test repo, runs all tools against all scenarios, collects results into benchmark.json.

Metrics collected per tool per scenario:
- File recovery accuracy (per-feature and overall)
- Execution time (seconds)
- HTTP request count (parsed from server access log)
- Exit code
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
    'gitdump': {
        'name': 'GitDump',
        'url': 'https://github.com/Ebryx/GitDump',
    },
    'git-dumper-hh': {
        'name': 'git-dumper (holly-hacker)',
        'url': 'https://github.com/holly-hacker/git-dumper',
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


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def docker_compose_cmd():
    """Return the docker compose command as a list (handles both old and new style)."""
    try:
        subprocess.run(
            ['docker', 'compose', 'version'],
            check=True, capture_output=True,
        )
        return ['docker', 'compose']
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ['docker-compose']


COMPOSE_CMD = None


def get_compose_cmd():
    global COMPOSE_CMD
    if COMPOSE_CMD is None:
        COMPOSE_CMD = docker_compose_cmd()
        logging.info(f"Using compose command: {' '.join(COMPOSE_CMD)}")
    return COMPOSE_CMD


# ---------------------------------------------------------------------------
# Tool version extraction
# ---------------------------------------------------------------------------

def get_tool_version(tool_id):
    """Extract version info from a built tool Docker image."""
    image_name = f"benchmark-{tool_id}"
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '--entrypoint', 'cat',
             image_name, '/tool-version.txt'],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        logging.warning(f"Could not get version for {tool_id}: {e}")
    return 'unknown'


def build_tool_images():
    """Build Docker images for all benchmark tools and extract version info."""
    for tool_id in TOOLS:
        tool_dir = os.path.join(TOOLS_PATH, tool_id)
        if not os.path.exists(os.path.join(tool_dir, 'Dockerfile')):
            logging.warning(f"No Dockerfile for {tool_id}, skipping build")
            TOOLS[tool_id]['version'] = 'unknown'
            continue
        image_name = f"benchmark-{tool_id}"
        logging.info(f"Building Docker image: {image_name}")
        subprocess.run(
            ['docker', 'build', '-t', image_name, tool_dir],
            check=True,
        )
        version = get_tool_version(tool_id)
        TOOLS[tool_id]['version'] = version
        logging.info(f"Built {image_name} (version: {version})")


# ---------------------------------------------------------------------------
# Server management + access log counting
# ---------------------------------------------------------------------------

def get_server_container_name(scenario):
    """Get the Docker container name for a scenario's web server."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    try:
        result = subprocess.run(
            [*get_compose_cmd(), 'ps', '-q'],
            cwd=compose_dir, capture_output=True, text=True,
        )
        container_id = result.stdout.strip().split('\n')[0]
        return container_id
    except Exception:
        return None


def get_access_log_line_count(scenario):
    """Count lines in the server's access log (= number of HTTP requests served)."""
    container_id = get_server_container_name(scenario)
    if not container_id:
        return None

    # Try common access log paths for Apache and Nginx
    log_paths = [
        '/var/log/apache2/access.log',   # Apache (Debian)
        '/var/log/apache2/other_vhosts_access.log',
        '/proc/1/fd/1',                  # stdout (docker logs)
        '/var/log/nginx/access.log',     # Nginx
    ]

    # Simplest: count lines from `docker logs`
    try:
        result = subprocess.run(
            ['docker', 'logs', container_id],
            capture_output=True, text=True, timeout=10,
        )
        # Each non-empty line in stdout is typically an access log entry
        lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
        return len(lines)
    except Exception:
        return None


def reset_server_logs(scenario):
    """Restart the server container to reset access logs before a tool run."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    subprocess.run(
        [*get_compose_cmd(), 'restart'],
        cwd=compose_dir, capture_output=True,
    )
    time.sleep(2)


def start_server(scenario):
    """Start the web server Docker container for a scenario."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    logging.info(f"Starting server: {scenario}")
    subprocess.run(
        [*get_compose_cmd(), 'up', '-d'],
        cwd=compose_dir,
        check=True,
    )
    time.sleep(3)


def stop_server(scenario):
    """Stop the web server Docker container for a scenario."""
    compose_dir = os.path.join(DOCKER_PATH, scenario)
    logging.info(f"Stopping server: {scenario}")
    subprocess.run(
        [*get_compose_cmd(), 'down'],
        cwd=compose_dir,
        check=True,
    )


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def get_url_for_scenario(scenario):
    """Return the URL to use for a given scenario."""
    if scenario == 'php-lfi':
        return 'http://host.docker.internal/lfi.php?file=./'
    return 'http://host.docker.internal'


def run_tool(tool_id, scenario, output_dir):
    """
    Run a single tool against a scenario.
    Returns (success, duration_seconds, exit_code, http_requests).
    """
    image_name = f"benchmark-{tool_id}"
    url = get_url_for_scenario(scenario)

    os.makedirs(output_dir, exist_ok=True)

    logging.info(f"Running {tool_id} against {scenario}...")

    # Reset server logs so we can count requests for this tool only
    reset_server_logs(scenario)

    start_time = time.monotonic()
    exit_code = -1

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
        exit_code = result.returncode
        duration = round(time.monotonic() - start_time, 2)

        if exit_code != 0:
            logging.warning(
                f"{tool_id} exited with code {exit_code} on {scenario}",
            )

        # Count HTTP requests from server access log
        http_requests = get_access_log_line_count(scenario)

        logging.info(
            f"  {tool_id}: {duration}s, exit={exit_code}, "
            f"requests={http_requests or 'N/A'}",
        )
        return True, duration, exit_code, http_requests

    except subprocess.TimeoutExpired:
        duration = round(time.monotonic() - start_time, 2)
        logging.error(f"{tool_id} timed out on {scenario} after {duration}s")
        http_requests = get_access_log_line_count(scenario)
        return False, duration, -1, http_requests

    except Exception as e:
        duration = round(time.monotonic() - start_time, 2)
        logging.error(f"{tool_id} failed on {scenario}: {e}")
        return False, duration, -1, None


def find_recovered_repo(output_dir):
    """Find the actual recovered repo directory (tools may create subdirectories)."""
    if os.path.exists(os.path.join(output_dir, '.git')):
        return output_dir

    try:
        for entry in os.listdir(output_dir):
            subdir = os.path.join(output_dir, entry)
            if os.path.isdir(subdir) and os.path.exists(os.path.join(subdir, '.git')):
                return subdir
    except OSError:
        pass

    return output_dir


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

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
                success, duration, exit_code, http_requests = run_tool(
                    tool_id, scenario, output_dir,
                )

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
                            f: {
                                'supported': False,
                                'correct': 0,
                                'total': 0,
                                'ratio': 0.0,
                            }
                            for f in FEATURES
                        },
                        'error': 'Tool timed out or failed to run',
                    }

                # Add performance metrics
                result['duration'] = duration
                result['exit_code'] = exit_code
                result['http_requests'] = http_requests

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
                'version': info.get('version', 'unknown'),
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

    # Also copy to docs/public/data/
    docs_data_path = os.path.join(
        os.path.dirname(__file__), '..', 'docs', 'public', 'data',
    )
    os.makedirs(docs_data_path, exist_ok=True)
    shutil.copy2(output_path, os.path.join(docs_data_path, 'benchmark.json'))

    logging.info(f"Benchmark results saved to {output_path}")
    logging.info("Results also copied to docs/public/data/benchmark.json")

    # Print summary
    logging.info("\n" + "=" * 60)
    logging.info("SUMMARY")
    logging.info("=" * 60)
    for tool_id in TOOLS:
        for scenario in SCENARIOS:
            r = results.get(tool_id, {}).get(scenario)
            if r:
                reqs = r.get('http_requests')
                reqs_str = str(reqs) if reqs is not None else 'N/A'
                logging.info(
                    f"  {tool_id:20s} | {scenario:25s} | "
                    f"{r['correct']:3d}/{r['total']:3d} = {r['ratio']:6.2f}% | "
                    f"{r['duration']:6.1f}s | "
                    f"reqs={reqs_str:>5s}",
                )


if __name__ == '__main__':
    run_benchmark()
