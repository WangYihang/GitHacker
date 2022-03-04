import glob
import os
import random
import semver
import shutil
import termcolor

from git import Repo


def print_info(data):
    print(termcolor.colored(data, "cyan"))


def print_success(data):
    print(termcolor.colored(data, "green"))


def print_warning(data):
    print(termcolor.colored(data, "yellow"))


def print_absent(data):
    print(termcolor.colored(data, "red"))


def random_string(length=0x10, charset=__import__('string').ascii_letters+__import__('string').digits):
    return ''.join([random.choice(charset) for i in range(length)])


def md5(data):
    if type(data) is str:
        data = bytes(data, encoding='utf-8')
    return __import__('hashlib').md5(data).hexdigest()


def cleanup():
    for filename in glob.glob("./test/*/www/*.php"):
        os.unlink(filename)

    for folder in glob.glob("./test/*/www"):
        shutil.rmtree(os.path.join(folder, ".git"), ignore_errors=True)

    shutil.rmtree("playground", ignore_errors=True)


def generate():
    for folder in glob.glob("./test/*/www"):
        # Create new repo
        root = folder
        repo = Repo.init(root)

        # Generate some random commit
        for i in range(0x10):
            filename = "index-{:02d}.php".format(i)
            filepath = os.path.join(root, filename)
            with open(filepath, 'w') as f:
                f.write(random_string())
            repo.index.add([filename])
            repo.index.commit("create {}".format(filename))

        version = semver.VersionInfo(0, 0, 1)

        # Create branches
        branch_names = ["dev", "master", "main", "hotfix",
                        "release", "fix", "wip", "issue", "daily"]
        for branch_name in branch_names:
            try:
                branch = repo.create_head(branch_name)
                # Create tags
                if random.choice([True, False]):
                    version = random.choice(
                        [version.bump_patch, version.bump_minor, version.bump_major])()
                    repo.create_tag(
                        version,
                        ref=branch,
                        message="v{}".format(version)
                    )
            except:
                pass

        # Generate some random files
        unstashed = []
        for i in range(0x10):
            filename = "{}.php".format(random_string())
            filepath = os.path.join(root, filename)
            with open(filepath, 'w') as f:
                f.write(random_string())
                if random.choice([True, False]):
                    repo.index.add([filename])
                else:
                    unstashed.append(filename)

        # Create stashes
        git = repo.git
        git.stash()

        # Second stash
        for i in unstashed:
            repo.index.add([i])

        # Create stashes
        git = repo.git
        git.stash()


def diff(left, right):
    visible_files = glob.glob("{}/**/*".format(left), recursive=True)
    invisiable_files = glob.glob("{}/**/.*".format(left), recursive=True)
    git_files = glob.glob("{}/.git/**/*".format(left), recursive=True)
    files = visible_files + invisiable_files + git_files
    total = 0
    same = 0
    difference = []
    right_absence = []
    for filename in files:
        if os.path.isfile(filename):
            total += 1
            current_filename = filename.replace(left, right)
            if not os.path.exists(current_filename):
                right_absence.append(current_filename)
                continue

            # There is no need to compare the `.git/index` file, leave it as same
            if os.path.join(".git", "index") in filename:
                same += 1
                continue

            origin_md5 = md5(open(filename, "rb").read())
            current_md5 = md5(open(current_filename, "rb").read())
            if origin_md5 == current_md5:
                same += 1
            else:
                difference.append(filename)

    return (same, total, difference, right_absence)


def diffall():
    for folder in glob.glob("./test/*"):
        basename = os.path.basename(folder)
        origin_path = os.path.join('test', basename, "www")
        current_path = glob.glob(f"{os.path.join('playground', basename)}/*")[0]
        same, total, difference, right_absence = diff(
            origin_path, current_path)
        ratio = (same / total) * 100
        if ratio == 100.0:
            print_success("[{} / {}] = {:.2f}%, {}, {}".format(same,
                          total, ratio, origin_path, current_path))
        else:
            print_warning("[{} / {}] = {:.2f}%, {}, {}".format(same,
                          total, ratio, origin_path, current_path))
        if len(difference) > 0:
            print_info("  Different files:")
            for filename in difference:
                print_absent("    {}".format(filename))
        if len(right_absence) > 0:
            print_info("  Files absent:")
            for filename in right_absence:
                print_absent("    {}".format(filename))


def main():
    cleanup()
    generate()
    cwd = os.getcwd()
    for folder in glob.glob("./test/*"):
        # Start docker
        os.chdir(os.path.join(cwd, folder))
        os.system("docker-compose up -d")

        os.chdir(cwd)
        try:
            os.makedirs("playground")
        except:
            pass

        if "php-lfi" in folder:
            html_folder = os.path.join(folder, "www", "html")
            try:
                os.makedirs(html_folder)
            except:
                pass
            with open(os.path.join(html_folder, "index.php"), "w") as f:
                f.write("<?php @readfile($_GET['file']);?>")
            os.system(
                "python3 GitHacker/__init__.py --brute --url 'http://127.0.0.1/?file=../.git/' --output-folder playground/{}".format(os.path.basename(folder)))
        else:
            os.system(
                "python3 GitHacker/__init__.py --brute --url 'http://127.0.0.1/' --output-folder playground/{}".format(os.path.basename(folder)))

        # Stop docker
        os.chdir(os.path.join(cwd, folder))
        os.system("docker-compose down")

    # Diff origin git folder and the downloaded git folder
    os.chdir(cwd)
    diffall()


if __name__ == "__main__":
    main()
