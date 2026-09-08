"""The new benchmark scenarios, and the harness pieces they need.

These scenarios encode findings that started life as unit tests against
GitHacker's internals. Moving them here turns each one into a question every
tool in the matrix has to answer, so the tests below check the two things
that make a scenario trustworthy: that it is registered with the metadata the
runner reads, and that its oracle actually distinguishes a failing run from a
passing one rather than always saying the same thing.
"""

from __future__ import annotations

import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from benchmark import config, security
from benchmark.security import Verdict

SCENARIOS = security.SCENARIOS_DIR


def _oracle(test_id: str):
    return security._load_oracle(test_id)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'test_id,category,mode',
    [
        ('A7_nested_gitdir_config', 'Info', 'static'),
        ('C5_offtree_crawl', 'Info', 'static'),
        ('C6_infinite_listing', 'DoS', 'infinite'),
    ],
)
def test_scenario_is_registered(test_id, category, mode):
    """A7 is deliberately Info, not RCE: it demonstrates that the tool wrote a
    file git would execute, not that anything executed. The recovered tree has
    no wired-up submodule, and `git status` against it fires nothing."""
    metas = security.discover_tests(filter_ids=[test_id])
    assert len(metas) == 1
    assert metas[0].category == category
    assert metas[0].server_mode == mode
    assert metas[0].description


def test_c5_declares_the_watch_that_is_its_only_evidence():
    """C5 has no canary of its own — the server writes one when the crawler
    requests a path under /private/. Without these two fields it always
    passes, whatever the tool does."""
    meta = security.discover_tests(filter_ids=['C5_offtree_crawl'])[0]
    assert meta.watch_regex == '^/private/'
    assert meta.watch_canary == 'PWNED_C5'


def test_c6_caps_its_own_runtime():
    """A denial-of-service test provokes a tool that never finishes, so it must
    not be allowed to spend the suite's default five-minute budget per tool."""
    meta = security.discover_tests(filter_ids=['C6_infinite_listing'])[0]
    assert meta.timeout_seconds is not None
    assert meta.timeout_seconds < config.TOOL_TIMEOUT


def test_absolute_href_scenario_is_in_the_functional_matrix():
    """The #82 guard: a listing dialect no other scenario serves."""
    assert 'absolute-href-index' in config.SCENARIOS
    scenario_dir = config.DOCKER_DIR / 'absolute-href-index'
    assert (scenario_dir / 'docker-compose.yml').exists()
    assert (scenario_dir / 'server.py').exists()


# ---------------------------------------------------------------------------
# A7 oracle — an executable file recovered inside a nested GIT_DIR
# ---------------------------------------------------------------------------


def test_a7_flags_a_nested_config_carrying_an_executable_directive(tmp_path):
    cfg = tmp_path / '.git' / 'modules' / 'sub' / 'config'
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[core]\n\tfsmonitor = "touch /canary/x"\n')
    verdict, evidence = _oracle('A7_nested_gitdir_config')(tmp_path, tmp_path, None)
    assert verdict is Verdict.FAIL
    assert 'fsmonitor' in evidence


def test_a7_flags_a_nested_hook(tmp_path):
    hook = tmp_path / '.git' / 'modules' / 'sub' / 'hooks' / 'pre-commit'
    hook.parent.mkdir(parents=True)
    hook.write_text('#!/bin/sh\ntouch /canary/x\n')
    verdict, _ = _oracle('A7_nested_gitdir_config')(tmp_path, tmp_path, None)
    assert verdict is Verdict.FAIL


def test_a7_ignores_a_harmless_nested_config(tmp_path):
    """A submodule config with nothing executable in it is not a finding, or
    every tool that recovers submodules at all fails this test."""
    cfg = tmp_path / '.git' / 'modules' / 'sub' / 'config'
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[core]\n\trepositoryformatversion = 0\n')
    verdict, _ = _oracle('A7_nested_gitdir_config')(tmp_path, tmp_path, None)
    assert verdict is Verdict.PASS


def test_a7_ignores_the_top_level_config(tmp_path):
    """A1 owns the top-level config. A7 must measure only the nested one, or
    the two scenarios stop being independent."""
    cfg = tmp_path / '.git' / 'config'
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[core]\n\tfsmonitor = "touch /canary/x"\n')
    verdict, _ = _oracle('A7_nested_gitdir_config')(tmp_path, tmp_path, None)
    assert verdict is Verdict.PASS


# ---------------------------------------------------------------------------
# C6 oracle — did the crawler stop on its own?
# ---------------------------------------------------------------------------


def _with_log(tmp_path: Path, lines: int) -> Path:
    (tmp_path / 'access.log').write_text('GET /.git/ HTTP/1.1\n' * lines)
    return tmp_path


def test_c6_flags_a_crawl_that_blew_the_request_budget(tmp_path):
    verdict, evidence = _oracle('C6_infinite_listing')(tmp_path, _with_log(tmp_path, 500), None)
    assert verdict is Verdict.FAIL
    assert '500 requests' in evidence


def test_c6_passes_a_crawl_that_bounded_itself(tmp_path):
    verdict, _ = _oracle('C6_infinite_listing')(tmp_path, _with_log(tmp_path, 12), None)
    assert verdict is Verdict.PASS


def test_c6_flags_a_crawl_that_stopped_by_crashing(tmp_path):
    """Dying on a recursion limit or a too-long path is not bounding."""

    class Crashed:
        returncode = 1
        stderr = 'OSError: [Errno 36] File name too long\n'

    verdict, evidence = _oracle('C6_infinite_listing')(tmp_path, _with_log(tmp_path, 60), Crashed())
    assert verdict is Verdict.FAIL
    assert 'exited 1' in evidence


# ---------------------------------------------------------------------------
# The infinite server mode itself
# ---------------------------------------------------------------------------


@pytest.fixture
def infinite_server():
    import socket

    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [
            sys.executable,
            str(config.BENCHMARK_DIR / 'evil_server.py'),
            '--mode',
            'infinite',
            '--port',
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert security._wait_port(port), 'infinite server did not bind'
    yield f'http://127.0.0.1:{port}'
    proc.terminate()
    proc.wait(timeout=5)


def _get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310
        return r.read().decode()


def test_infinite_server_offers_one_more_subdirectory_at_every_depth(infinite_server):
    shallow = _get(f'{infinite_server}/.git/')
    deep = _get(f'{infinite_server}/.git/deeper/deeper/deeper/deeper/')
    assert 'deeper/' in shallow
    assert 'deeper/' in deep, 'the tree has a bottom, so it cannot test unbounded recursion'


def test_infinite_server_looks_like_a_directory_listing(infinite_server):
    """Pillagers decide whether to crawl by looking for this title, so the
    scenario never starts without it."""
    assert '<title>Index of' in _get(f'{infinite_server}/.git/')


def test_infinite_server_answers_head_so_the_target_looks_like_a_repo(infinite_server):
    assert _get(f'{infinite_server}/.git/HEAD').startswith('ref: ')


# ---------------------------------------------------------------------------
# The default oracle's non-vacuity guard
# ---------------------------------------------------------------------------


def test_default_oracle_refuses_to_pass_a_tool_that_sent_no_requests(tmp_path):
    """A tool broken in the harness makes no requests and trips no canary. That
    is not a clean sheet; it is no evidence at all."""
    (tmp_path / 'access.log').write_text('')
    verdict, evidence = security._default_oracle('A1_fsmonitor')(tmp_path, tmp_path, None)
    assert verdict is Verdict.ERROR
    assert 'no requests' in evidence


def test_default_oracle_passes_a_tool_that_ran_and_tripped_nothing(tmp_path):
    (tmp_path / 'access.log').write_text('GET /.git/HEAD HTTP/1.1\n')
    verdict, _ = security._default_oracle('A1_fsmonitor')(tmp_path, tmp_path, None)
    assert verdict is Verdict.PASS


def test_default_oracle_still_fails_on_a_canary(tmp_path):
    """The guard must not shadow the finding it sits in front of."""
    (tmp_path / 'access.log').write_text('')
    (tmp_path / 'PWNED_A1').write_text('x')
    verdict, _ = security._default_oracle('A1_fsmonitor')(tmp_path, tmp_path, None)
    assert verdict is Verdict.FAIL


# ---------------------------------------------------------------------------
# `benchmark repro` — the local reproduction steps handed to maintainers
# ---------------------------------------------------------------------------


def _repro(test_id, capsys):
    from benchmark.repro import print_repro

    print_repro(test_id)
    return capsys.readouterr().out


def test_repro_covers_every_registered_scenario(capsys):
    """Generated from meta.toml, so a new scenario is documented the moment it
    is registered — and a scenario the printer cannot describe is a bug, not a
    silently missing page."""
    for meta in security.discover_tests():
        out = _repro(meta.id, capsys)
        assert meta.id in out
        assert 'evil_server.py' in out


def test_repro_names_the_server_mode_the_scenario_actually_needs(capsys):
    """The steps must not drift from the harness: a redirect scenario served
    as a static one reproduces nothing."""
    assert '--mode infinite' in _repro('C6_infinite_listing', capsys)
    assert '--mode redirect' in _repro('C3_redirect_ssrf', capsys)
    assert '--mode static' in _repro('A1_fsmonitor', capsys)


def test_repro_tells_the_reader_to_create_the_canary_directory(capsys):
    """The payloads hard-code /canary because the harness bind-mounts it.
    Without this step the touch fails, nothing appears, and a maintainer reads
    that as "not affected" — verified the hard way while writing this."""
    out = _repro('A1_fsmonitor', capsys)
    assert '/canary' in out
    assert 'mkdir' in out


def test_repro_describes_escaping_payloads_differently(capsys):
    """B1 does not write to /canary at all — it escapes the output directory,
    and where it lands is the finding. Telling the reader to watch /canary
    would have them watch the wrong place."""
    out = _repro('B1_index_traversal', capsys)
    assert 'outside ./out' in out
    assert 'find ' in out


def test_repro_surfaces_the_recorded_findings(capsys):
    """A disclosure email should be able to cite the steps and the ID together."""
    out = _repro('A1_fsmonitor', capsys)
    assert 'DIS-2026-002' in out
    assert 'git-dumper' in out


def test_repro_states_that_nothing_is_hosted(capsys):
    """The corpus is deliberately local; the printed steps say so, because the
    steps are what gets pasted into an issue."""
    assert 'not hosted' in _repro('A1_fsmonitor', capsys)


def test_repro_index_lists_all_scenarios(capsys):
    from benchmark.repro import print_index

    print_index()
    out = capsys.readouterr().out
    for meta in security.discover_tests():
        assert meta.id in out


def test_repro_rejects_an_unknown_scenario():
    from benchmark.repro import print_repro

    with pytest.raises(SystemExit):
        print_repro('Z9_does_not_exist')
