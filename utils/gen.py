import glob
import os
import random
import semver
import shutil
import logging
import coloredlogs

from git import Repo

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def random_string(length=0x10, charset=__import__('string').ascii_letters+__import__('string').digits):
    return ''.join([random.choice(charset) for i in range(length)])


def cleanup():
    for filename in glob.glob("./test/*/www/*.php"):
        os.unlink(filename)

    for folder in glob.glob("./test/*/www"):
        shutil.rmtree(os.path.join(folder, ".git"), ignore_errors=True)

    shutil.rmtree("playground", ignore_errors=True)


def generate_random_files(repo, root, n, prefix='normal'):
    files = []
    for i in range(n):
        logging.debug(f"Creating the {i+1} th of {n} random files")
        filename = f"{prefix}_{random_string()}.php"
        filepath = os.path.join(os.path.abspath(root), filename)
        with open(filepath, 'w') as f:
            f.write(random_string())
        files.append(filepath)
    return files


def generate_random_commits(repo, root, n, prefix):
    for i in range(n):
        logging.debug(f"Creating the {i+1} th of {n} random commits")
        files = generate_random_files(repo, root, random.randint(2, 16), prefix=f"{prefix}_commit")
        repo.index.add(files)
        repo.index.commit(f"create {files}")


def generate_random_stashes(repo, root, n):
    for i in range(n):
        logging.debug(f"Creating the {i+1} th of {n} random commits")
        files = generate_random_files(repo, root, random.randint(2, 16), prefix="stash")
        repo.index.add(files)
        repo.git.stash()


def generate_random_tags(repo, root, n):
    version = semver.VersionInfo(0, 0, 1)
    repo.git.checkout("release")
    for i in range(0x10):
        if random.choice([True, False]):
            version = random.choice([
                version.bump_patch,
                version.bump_minor,
                version.bump_major
            ])()
            repo.create_tag(
                version,
                message=f"v{version}",
            )
        generate_random_commits(repo, root, random.randint(2, 4), prefix=f"tag_v{version}")
    repo.git.checkout("master")


def generate_random_branches(repo, root, n):
    for i in range(n):
        logging.debug(f"Creating the {i+1} th of {n} random branches")
        branch_name = random_string()
        repo.create_head(branch_name)
        generate_random_commits(repo, root, random.randint(2, 4), prefix=f"branch_{branch_name}")


def generate_repo(folder):
    # 1. Create a new repo
    logging.info(f"Creating repo: {folder}")
    root = folder
    repo = Repo.init(root)

    # 2. Generate [2, 16] some random commits
    logging.info(f"Generating random commits...")
    generate_random_commits(repo, root, random.randint(2, 16), prefix="normal")

    # 3. Create Branches
    logging.info(f"Generating random branches...")
    generate_random_branches(repo, root, random.randint(2, 8))

    # 4. Create well-known branches
    logging.info(f"Generating well-known branches...")
    branch_names = [
        'daily', 'dev', 'feature', 'feat', 'fix', 'hotfix', 'issue', 
        'main', 'master', 'ng', 'quickfix', 'release',
        'test', 'testing', 'wip',
    ]
    for branch_name in branch_names:
        repo.create_head(branch_name)
        generate_random_commits(repo, root, random.randint(2, 4), prefix="branch_commits")

    # 5. Create 0x10 Tags
    logging.info(f"Generating random tags...")
    generate_random_tags(repo, root, random.randint(2, 16))

    # 6. Create [2, 4] Stashes
    logging.info(f"Generating random stashes...")
    generate_random_stashes(repo, root, random.randint(2, 16))

    # 7. Generate [2, 16] random files in the staging area
    logging.info(f"Generating random files in staging area...")
    repo.index.add(generate_random_files(repo, root, random.randint(2, 16), prefix="staging"))

    # 8. Generate [2, 16] random files in the working directory
    logging.info(f"Generating random files in working directory...")
    generate_random_files(repo, root, random.randint(2, 16), prefix="unstaged")

    # 9. Generate PHP Local File Inclusion Script
    logging.info(f"Generating php local file inclusion script...")
    with open(os.path.join(root, "lfi.php"), "w") as f:
        f.write("<?php @readfile($_GET['file']);?>")

    logging.info(f"Test repo generation finished")

def main():
    sample_repo_path = "./test/repo"
    shutil.rmtree(sample_repo_path, ignore_errors=True)
    generate_repo(sample_repo_path)


if __name__ == "__main__":
    main()
