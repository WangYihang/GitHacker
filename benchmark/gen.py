"""
Generate a test git repository with known structure for benchmarking.
Outputs a manifest.json that categorizes files by feature for per-feature evaluation.
"""

import json
import logging
import os
import random
import shutil

import coloredlogs
import semver
from git import Repo

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')

random.seed(0)


def random_string(length=0x10, charset=__import__('string').ascii_letters + __import__('string').digits):
    return ''.join([random.choice(charset) for i in range(length)])


def generate_random_files(repo, root, n, prefix='normal'):
    files = []
    for i in range(n):
        filename = f"{prefix}_{random_string()}.php"
        filepath = os.path.join(os.path.abspath(root), filename)
        with open(filepath, 'w') as f:
            f.write(random_string())
        files.append(filepath)
    return files


def generate_random_commits(repo, root, n, prefix):
    for i in range(n):
        files = generate_random_files(
            repo, root, random.randint(2, 16), prefix=f"{prefix}_commit",
        )
        repo.index.add(files)
        repo.index.commit(f"create {files}")


def generate_random_stashes(repo, root, n):
    for i in range(n):
        files = generate_random_files(
            repo, root, random.randint(2, 16), prefix='stash',
        )
        repo.index.add(files)
        repo.git.stash()


def generate_random_tags(repo, root, n):
    version = semver.VersionInfo(0, 0, 1)
    repo.git.checkout('release')
    for i in range(0x10):
        if random.choice([True, False]):
            version = random.choice(
                [version.bump_patch, version.bump_minor, version.bump_major],
            )()
            repo.create_tag(
                version,
                message=f"v{version}",
            )
        generate_random_commits(
            repo, root, random.randint(
                2, 4,
            ), prefix=f"tag_v{version}",
        )
    repo.git.checkout('master')


def generate_random_branches(repo, root, n):
    for i in range(n):
        branch_name = random_string()
        repo.create_head(branch_name)
        generate_random_commits(
            repo, root, random.randint(
                2, 4,
            ), prefix=f"branch_{branch_name}",
        )


def collect_manifest(repo_path):
    """
    Walk the generated repo and categorize files by feature.
    Returns a dict: { feature_name: [relative_file_paths] }
    """
    import glob as globmod

    manifest = {
        'source_code': [],
        'reflogs': [],
        'stashes': [],
        'commits': [],
        'branches': [],
        'remotes': [],
        'tags': [],
    }

    git_dir = os.path.join(repo_path, '.git')

    # Source code: all non-.git files
    for f in globmod.glob(f"{repo_path}/**/*", recursive=True):
        if os.path.isfile(f) and '/.git/' not in f and not f.endswith('/.git'):
            manifest['source_code'].append(os.path.relpath(f, repo_path))

    # Reflogs
    reflogs_dir = os.path.join(git_dir, 'logs')
    if os.path.exists(reflogs_dir):
        for f in globmod.glob(f"{reflogs_dir}/**/*", recursive=True):
            if os.path.isfile(f):
                manifest['reflogs'].append(os.path.relpath(f, repo_path))

    # Stashes: tracked via refs/stash and stash reflog
    stash_ref = os.path.join(git_dir, 'refs', 'stash')
    if os.path.exists(stash_ref):
        manifest['stashes'].append(os.path.relpath(stash_ref, repo_path))
    stash_log = os.path.join(git_dir, 'logs', 'refs', 'stash')
    if os.path.exists(stash_log):
        manifest['stashes'].append(os.path.relpath(stash_log, repo_path))

    # Commits: objects in .git/objects (loose) and pack files
    objects_dir = os.path.join(git_dir, 'objects')
    if os.path.exists(objects_dir):
        for f in globmod.glob(f"{objects_dir}/**/*", recursive=True):
            if os.path.isfile(f) and '/info/' not in f:
                manifest['commits'].append(os.path.relpath(f, repo_path))

    # Branches: refs/heads
    heads_dir = os.path.join(git_dir, 'refs', 'heads')
    if os.path.exists(heads_dir):
        for f in globmod.glob(f"{heads_dir}/**/*", recursive=True):
            if os.path.isfile(f):
                manifest['branches'].append(os.path.relpath(f, repo_path))

    # Remotes: refs/remotes
    remotes_dir = os.path.join(git_dir, 'refs', 'remotes')
    if os.path.exists(remotes_dir):
        for f in globmod.glob(f"{remotes_dir}/**/*", recursive=True):
            if os.path.isfile(f):
                manifest['remotes'].append(os.path.relpath(f, repo_path))

    # Tags: refs/tags
    tags_dir = os.path.join(git_dir, 'refs', 'tags')
    if os.path.exists(tags_dir):
        for f in globmod.glob(f"{tags_dir}/**/*", recursive=True):
            if os.path.isfile(f):
                manifest['tags'].append(os.path.relpath(f, repo_path))

    # Packed refs (contains branches, tags, remotes in one file)
    packed_refs = os.path.join(git_dir, 'packed-refs')
    if os.path.exists(packed_refs):
        manifest['branches'].append(os.path.relpath(packed_refs, repo_path))
        manifest['tags'].append(os.path.relpath(packed_refs, repo_path))

    return manifest


def generate_repo(folder):
    logging.info(f"Creating repo: {folder}")
    root = folder
    repo = Repo.init(root)

    repo.config_writer().set_value('user', 'name', 'test').release()
    repo.config_writer().set_value('user', 'email', 'test@githacker.com').release()

    # Generate random commits
    logging.info('Generating random commits...')
    generate_random_commits(repo, root, random.randint(2, 16), prefix='normal')

    # Create random branches
    logging.info('Generating random branches...')
    generate_random_branches(repo, root, random.randint(2, 8))

    # Create well-known branches
    logging.info('Generating well-known branches...')
    branch_names = [
        'daily', 'dev', 'feature', 'feat', 'fix', 'hotfix', 'issue',
        'main', 'master', 'ng', 'quickfix', 'release', 'test', 'testing', 'wip',
    ]
    for branch_name in branch_names:
        repo.create_head(branch_name)
        generate_random_commits(
            repo, root, random.randint(2, 4), prefix='branch_commits',
        )

    # Create tags
    logging.info('Generating random tags...')
    generate_random_tags(repo, root, random.randint(2, 16))

    # Create stashes
    logging.info('Generating random stashes...')
    generate_random_stashes(repo, root, random.randint(2, 16))

    # Generate files in staging area
    logging.info('Generating random files in staging area...')
    repo.index.add(
        generate_random_files(repo, root, random.randint(2, 16), prefix='staging'),
    )

    # Generate files in working directory
    logging.info('Generating random files in working directory...')
    generate_random_files(repo, root, random.randint(2, 16), prefix='unstaged')

    # Generate PHP LFI script
    logging.info('Generating php local file inclusion script...')
    with open(os.path.join(root, 'lfi.php'), 'w') as f:
        f.write("<?php @readfile($_GET['file']);?>")

    # Generate custom file in .git folder
    logging.info('Generate custom file in .git folder...')
    with open(os.path.join(root, '.git', 'whoami'), 'w') as f:
        f.write('root')

    # Collect and save manifest
    logging.info('Collecting file manifest...')
    manifest = collect_manifest(root)
    manifest_path = os.path.join(root, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    # Log manifest stats
    for feature, files in manifest.items():
        logging.info(f"  {feature}: {len(files)} files")

    logging.info('Test repo generation finished')
    return manifest


def main():
    sample_repo_path = './test/repo'
    shutil.rmtree(sample_repo_path, ignore_errors=True)
    generate_repo(sample_repo_path)


if __name__ == '__main__':
    main()
