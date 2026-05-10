"""Docker and Docker Compose helpers."""

from __future__ import annotations

import functools
import logging
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from benchmark import config
from benchmark.config import DOCKER_DIR, TOOLS_DIR

logger = logging.getLogger(__name__)

SERVER_PORT = 80


# ---------------------------------------------------------------------------
# Port readiness helpers
# ---------------------------------------------------------------------------

def _wait_for_port(port: int = SERVER_PORT, host: str = "127.0.0.1", timeout: float = 30) -> bool:
    """Block until *port* is accepting connections, or *timeout* expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    logger.warning("Port %d did not become ready within %.0fs", port, timeout)
    return False


def _wait_for_port_release(port: int = SERVER_PORT, host: str = "127.0.0.1", timeout: float = 15) -> bool:
    """Block until *port* is no longer accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                time.sleep(0.5)  # still open, wait
        except OSError:
            return True
    logger.warning("Port %d was not released within %.0fs", port, timeout)
    return False


# ---------------------------------------------------------------------------
# Compose command detection
# ---------------------------------------------------------------------------

@functools.cache
def compose_cmd() -> list[str]:
    """Detect the available docker compose command."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
        )
        cmd = ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        cmd = ["docker-compose"]
    logger.info("Using compose command: %s", " ".join(cmd))
    return cmd


# ---------------------------------------------------------------------------
# Image building & version extraction
# ---------------------------------------------------------------------------

def build_image(tool_id: str) -> None:
    """Build the Docker image for a benchmark tool."""
    tool_dir = TOOLS_DIR / tool_id
    if not (tool_dir / "Dockerfile").exists():
        raise FileNotFoundError(f"No Dockerfile for {tool_id}")
    image = f"benchmark-{tool_id}"
    logger.info("Building image %s", image)
    subprocess.run(["docker", "build", "-t", image, str(tool_dir)], check=True)


def get_tool_version(tool_id: str) -> str:
    """Read /tool-version.txt from a built tool image."""
    image = f"benchmark-{tool_id}"
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "cat", image, "/tool-version.txt"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as exc:
        logger.warning("Could not get version for %s: %s", tool_id, exc)
    return "unknown"


# ---------------------------------------------------------------------------
# Compose service lifecycle
# ---------------------------------------------------------------------------

@contextmanager
def compose_service(scenario: str) -> Iterator[None]:
    """Start a compose service for *scenario*, yield, then tear it down.

    Uses port polling instead of fixed sleep to ensure the server is
    actually ready before yielding, and fully stopped before returning.
    """
    cwd = DOCKER_DIR / scenario
    logger.info("Starting server: %s", scenario)
    subprocess.run([*compose_cmd(), "up", "-d"], cwd=cwd, check=True)

    if not _wait_for_port():
        logger.error("Server for %s failed to start", scenario)

    try:
        yield
    finally:
        logger.info("Stopping server: %s", scenario)
        subprocess.run([*compose_cmd(), "down"], cwd=cwd, check=True)
        _wait_for_port_release()


def restart_service(scenario: str) -> None:
    """Restart the compose service (resets logs)."""
    cwd = DOCKER_DIR / scenario
    subprocess.run([*compose_cmd(), "restart"], cwd=cwd, capture_output=True)
    _wait_for_port()


def get_container_id(scenario: str) -> str | None:
    """Return the first container ID for a scenario's compose project."""
    cwd = DOCKER_DIR / scenario
    try:
        result = subprocess.run(
            [*compose_cmd(), "ps", "-q"],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        ids = result.stdout.strip().split("\n")
        return ids[0] if ids and ids[0] else None
    except Exception:
        return None


def get_request_count(scenario: str) -> int | None:
    """Count HTTP requests by reading docker logs for the server container."""
    container_id = get_container_id(scenario)
    if not container_id:
        return None
    try:
        result = subprocess.run(
            ["docker", "logs", container_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = [line for line in result.stdout.strip().split("\n") if line.strip()]
        return len(lines)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool container execution
# ---------------------------------------------------------------------------

def run_tool_container(
    tool_id: str,
    url: str,
    output_dir: Path,
) -> subprocess.CompletedProcess[str]:
    """Run a tool's Docker container and return the CompletedProcess."""
    image = f"benchmark-{tool_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", "host",
            "-v", f"{output_dir.resolve()}:/output",
            image,
            url, "/output",
        ],
        timeout=config.TOOL_TIMEOUT,
        capture_output=True,
        text=True,
    )
