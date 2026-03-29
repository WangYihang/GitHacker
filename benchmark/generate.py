"""Generate a test git repository with known structure for benchmarking."""

from __future__ import annotations

import json
import logging
import random
import shutil
import string
from pathlib import Path

import semver
from git import Repo

from benchmark.compare import Manifest
from benchmark.config import RANDOM_SEED, REPO_PATH

logger = logging.getLogger(__name__)

random.seed(RANDOM_SEED)

_CHARSET = string.ascii_letters + string.digits

WELL_KNOWN_BRANCHES = [
    "daily", "dev", "feature", "feat", "fix", "hotfix", "issue",
    "main", "master", "ng", "quickfix", "release", "test", "testing", "wip",
]


def _rand(length: int = 0x10) -> str:
    return "".join(random.choice(_CHARSET) for _ in range(length))


def _random_files(root: Path, n: int, prefix: str = "normal") -> list[str]:
    paths: list[str] = []
    for _ in range(n):
        fp = root / f"{prefix}_{_rand()}.php"
        fp.write_text(_rand())
        paths.append(str(fp))
    return paths


def _random_commits(repo: Repo, root: Path, n: int, prefix: str) -> None:
    for _ in range(n):
        files = _random_files(root, random.randint(2, 16), f"{prefix}_commit")
        repo.index.add(files)
        repo.index.commit(f"create {len(files)} files")


def _random_branches(repo: Repo, root: Path, n: int) -> None:
    for _ in range(n):
        name = _rand()
        repo.create_head(name)
        _random_commits(repo, root, random.randint(2, 4), f"branch_{name}")


def _random_stashes(repo: Repo, root: Path, n: int) -> None:
    for _ in range(n):
        _random_files(root, random.randint(2, 16), "stash")
        repo.index.add([str(p) for p in root.glob("stash_*.php") if p.is_file()])
        repo.git.stash()


def _random_tags(repo: Repo, root: Path) -> None:
    version = semver.VersionInfo(0, 0, 1)
    repo.git.checkout("release")
    for _ in range(0x10):
        if random.choice([True, False]):
            version = random.choice(
                [version.bump_patch, version.bump_minor, version.bump_major],
            )()
            repo.create_tag(version, message=f"v{version}")
        _random_commits(repo, root, random.randint(2, 4), f"tag_v{version}")
    repo.git.checkout("master")


# ---------------------------------------------------------------------------
# Manifest collection
# ---------------------------------------------------------------------------

def _collect_manifest(repo_path: Path) -> Manifest:
    """Walk the repo and categorise files by git feature."""
    git_dir = repo_path / ".git"
    manifest: Manifest = {
        "source_code": [],
        "reflogs": [],
        "stashes": [],
        "commits": [],
        "branches": [],
        "remotes": [],
        "tags": [],
    }

    def _rel(p: Path) -> str:
        return str(p.relative_to(repo_path))

    # Source code — everything outside .git
    for f in repo_path.rglob("*"):
        if f.is_file() and ".git" not in f.relative_to(repo_path).parts:
            manifest["source_code"].append(_rel(f))

    # Reflogs
    logs_dir = git_dir / "logs"
    if logs_dir.exists():
        for f in logs_dir.rglob("*"):
            if f.is_file():
                manifest["reflogs"].append(_rel(f))

    # Stashes
    for stash_path in [git_dir / "refs" / "stash", git_dir / "logs" / "refs" / "stash"]:
        if stash_path.exists():
            manifest["stashes"].append(_rel(stash_path))

    # Commits (objects)
    objects_dir = git_dir / "objects"
    if objects_dir.exists():
        for f in objects_dir.rglob("*"):
            if f.is_file() and "info" not in f.relative_to(objects_dir).parts:
                manifest["commits"].append(_rel(f))

    # Branches
    heads_dir = git_dir / "refs" / "heads"
    if heads_dir.exists():
        for f in heads_dir.rglob("*"):
            if f.is_file():
                manifest["branches"].append(_rel(f))

    # Remotes
    remotes_dir = git_dir / "refs" / "remotes"
    if remotes_dir.exists():
        for f in remotes_dir.rglob("*"):
            if f.is_file():
                manifest["remotes"].append(_rel(f))

    # Tags
    tags_dir = git_dir / "refs" / "tags"
    if tags_dir.exists():
        for f in tags_dir.rglob("*"):
            if f.is_file():
                manifest["tags"].append(_rel(f))

    # Packed refs
    packed_refs = git_dir / "packed-refs"
    if packed_refs.exists():
        rel = _rel(packed_refs)
        manifest["branches"].append(rel)
        manifest["tags"].append(rel)

    return manifest


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_repo(path: Path | None = None) -> Manifest:
    """Generate a test repository and return its feature manifest."""
    path = path or REPO_PATH
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)

    logger.info("Creating repo: %s", path)
    repo = Repo.init(str(path))
    repo.config_writer().set_value("user", "name", "test").release()
    repo.config_writer().set_value("user", "email", "test@githacker.com").release()

    logger.info("Generating random commits...")
    _random_commits(repo, path, random.randint(2, 16), "normal")

    logger.info("Generating random branches...")
    _random_branches(repo, path, random.randint(2, 8))

    logger.info("Generating well-known branches...")
    for name in WELL_KNOWN_BRANCHES:
        repo.create_head(name)
        _random_commits(repo, path, random.randint(2, 4), "branch_commits")

    logger.info("Generating random tags...")
    _random_tags(repo, path)

    logger.info("Generating random stashes...")
    _random_stashes(repo, path, random.randint(2, 16))

    logger.info("Generating staging area files...")
    files = _random_files(path, random.randint(2, 16), "staging")
    repo.index.add(files)

    logger.info("Generating working directory files...")
    _random_files(path, random.randint(2, 16), "unstaged")

    logger.info("Generating PHP LFI script...")
    (path / "lfi.php").write_text("<?php @readfile($_GET['file']);?>")

    logger.info("Generating .git/whoami...")
    (path / ".git" / "whoami").write_text("root")

    logger.info("Collecting manifest...")
    manifest = _collect_manifest(path)
    (path / "manifest.json").write_text(json.dumps(manifest, indent=2))

    for feature, files_list in manifest.items():
        logger.info("  %s: %d files", feature, len(files_list))

    logger.info("Test repo generation finished")
    return manifest
