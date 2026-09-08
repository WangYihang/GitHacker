"""Attack surface: the dangerous-file gate.

``is_dangerous_git_file`` is the only thing standing between a downloaded
``.git`` tree and code execution: ``core.fsmonitor`` / ``core.pager`` in a
config, or any file under ``hooks/``, runs as soon as git touches the repo —
and ``git_clone()`` touches it immediately. The gate is a suffix denylist over
``Path(...).parts``, so every test here is a path that *is* one of those files
as far as git is concerned, but does not look like one to a tuple comparison.
"""

from __future__ import annotations

import pytest

from tests.conftest import ANCHOR, Response


class ContentServer:
    """Serves one body for any URL, so `wget` has something to write."""

    expected_origin = None

    def __init__(self, body=b'[core]\n\tfsmonitor = touch /tmp/pwned\n'):
        self.body = body

    def get(self, url, *args, **kwargs):
        return Response(text=self.body.decode(), content=self.body)

    def close(self):
        pass


# ---------------------------------------------------------------------------
# The gate does catch the canonical spellings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'path',
    [
        '.git/config',
        '.git/hooks/pre-commit',
        '.git/hooks/post-checkout',
        '.git/hooks/fsmonitor-watchman',
        '.git/hooks/PRE-COMMIT',  # the hooks rule ignores the filename, so case is moot here
        'out/.git/config',  # anywhere in the tree, not just at the root
    ],
)
def test_known_execution_vectors_are_flagged(hacker, path):
    assert hacker.is_dangerous_git_file(path) is True


@pytest.mark.parametrize('path', ['.git/HEAD', '.git/index', '.git/objects/ab/cdef'])
def test_ordinary_repository_files_are_not_flagged(hacker, path):
    """The gate must stay narrow, or the tool refuses to download the repo."""
    assert hacker.is_dangerous_git_file(path) is False


# ---------------------------------------------------------------------------
# Case. The comparison folds case, because the filesystem may too.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'path',
    [
        '.git/CONFIG',
        '.git/Config',
        '.GIT/config',
        '.git/HOOKS/pre-commit',
    ],
)
def test_case_variants_are_flagged(hacker, path):
    assert hacker.is_dangerous_git_file(path) is True


def test_uppercase_config_is_not_written_to_disk(hacker):
    hacker.session = ContentServer()
    target = hacker.temp_dst_path / '.git' / 'CONFIG'
    hacker.wget(f'{ANCHOR}CONFIG', target)
    assert not target.exists()


def test_lowercase_config_is_refused(hacker):
    """The control: the gate really does stop the canonical spelling, so the
    test above is measuring the bypass and not a broken harness."""
    hacker.session = ContentServer()
    target = hacker.temp_dst_path / '.git' / 'config'
    hacker.wget(f'{ANCHOR}config', target)
    assert not target.exists()


# ---------------------------------------------------------------------------
# Nested git dirs. A submodule's GIT_DIR is .git/modules/<name>, and git reads
# its config and runs its hooks just like the top-level one.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'path',
    [
        '.git/modules/sub/config',
        '.git/modules/sub/hooks/pre-commit',
        '.git/modules/a/modules/b/config',
        '.git/worktrees/wt/config',
    ],
)
def test_nested_git_dirs_are_flagged(hacker, path):
    assert hacker.is_dangerous_git_file(path) is True


# ---------------------------------------------------------------------------
# The gate's own contract
# ---------------------------------------------------------------------------


def test_hooks_gate_covers_hooks_not_yet_invented(hacker):
    """The point of the `parts[-3:-1] == ('.git', 'hooks')` rule is that a hook
    git adds in a future release is covered without a list update."""
    assert hacker.is_dangerous_git_file('.git/hooks/some-future-hook') is True


def test_a_file_merely_named_like_a_hook_directory_is_not_flagged(hacker):
    """`hooks` as a *ref* name must not be confused with the hooks directory,
    or a repo with a branch called `hooks` becomes undownloadable."""
    assert hacker.is_dangerous_git_file('.git/refs/heads/hooks') is False
