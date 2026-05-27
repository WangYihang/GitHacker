"""Unit tests for benchmark.security — discovery, default oracle, report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark import security
from benchmark.security import (
    SecurityReport,
    TestMeta,
    TestResult,
    ToolRunResult,
    Verdict,
    _default_oracle,
)


def test_default_oracle_pass_when_canary_absent(tmp_path):
    output_dir = tmp_path / "out"
    canary_dir = tmp_path / "canary"
    output_dir.mkdir()
    canary_dir.mkdir()

    check = _default_oracle("A1_fsmonitor")
    verdict, evidence = check(output_dir, canary_dir, proc=None)
    assert verdict is Verdict.PASS
    assert evidence == ""


def test_default_oracle_fail_when_canary_present(tmp_path):
    output_dir = tmp_path / "out"
    canary_dir = tmp_path / "canary"
    output_dir.mkdir()
    canary_dir.mkdir()
    (canary_dir / "PWNED_A1").write_text("pwned\n")

    check = _default_oracle("A1_fsmonitor")
    verdict, evidence = check(output_dir, canary_dir, proc=None)
    assert verdict is Verdict.FAIL
    assert "PWNED_A1" in evidence


def test_default_oracle_canary_name_from_test_id_prefix():
    """The canary file is named after the test_id's first segment."""
    assert _default_oracle("A1_fsmonitor").__closure__ is not None
    # Black-box: it checks for PWNED_<prefix>. Verify via behavior.

    def _run(tmp_path, test_id, canary_name):
        d = tmp_path
        (d / canary_name).write_text("x")
        check = _default_oracle(test_id)
        v, _ = check(d, d, None)
        return v

    import tempfile
    with tempfile.TemporaryDirectory() as t:
        assert _run(Path(t), "B1_index_traversal", "PWNED_B1") is Verdict.FAIL
    with tempfile.TemporaryDirectory() as t:
        assert _run(Path(t), "C1_html_traversal", "PWNED_C1") is Verdict.FAIL
    with tempfile.TemporaryDirectory() as t:
        # No canary file -> PASS
        assert _run(Path(t), "Z9_nothing", "PWNED_OTHER") is Verdict.PASS


def test_discover_tests_picks_up_a1_b1_c1():
    """At least the three Phase-S1 tests are registered."""
    tests = security.discover_tests()
    ids = {t.id for t in tests}
    assert "A1_fsmonitor" in ids
    assert "B1_index_traversal" in ids
    assert "C1_html_traversal" in ids


def test_discover_tests_filter_by_id():
    tests = security.discover_tests(filter_ids=["A1_fsmonitor"])
    assert [t.id for t in tests] == ["A1_fsmonitor"]


def test_discover_tests_filter_by_category():
    tests = security.discover_tests(filter_category="RCE")
    assert all(t.category == "RCE" for t in tests)
    # A1 is in RCE, B1/C1 are in AFW
    assert "A1_fsmonitor" in {t.id for t in tests}
    assert "B1_index_traversal" not in {t.id for t in tests}


def test_discover_tests_skips_underscore_prefixed():
    """Subdirectories like _evil_server should be ignored."""
    ids = {t.id for t in security.discover_tests()}
    assert not any(i.startswith("_") for i in ids)


def test_meta_toml_parses_for_each_phase_s1_test():
    """Every Phase S1 test has a valid meta.toml with required fields."""
    for tid in ("A1_fsmonitor", "B1_index_traversal", "C1_html_traversal"):
        metas = security.discover_tests(filter_ids=[tid])
        assert len(metas) == 1
        m = metas[0]
        assert m.category in ("RCE", "AFW", "Info", "CVE")
        assert m.severity in ("H", "M", "L")
        assert m.description
        assert m.server_mode in ("static", "redirect")


def test_security_report_to_dict_round_trip():
    """SecurityReport.to_dict() emits all required fields and is JSON-safe."""
    report = SecurityReport(
        generated_at="2026-05-27T00:00:00+00:00",
        git_commit="deadbeef",
        tools={"githacker": {"name": "GitHacker", "url": "http://example.com", "version": "1.1.3"}},
        tests=[
            TestResult(
                meta=TestMeta(
                    id="A1_fsmonitor", category="RCE", severity="H",
                    description="x", cve=None, server_mode="static",
                ),
                runs={"githacker": ToolRunResult(
                    verdict=Verdict.FAIL, evidence="canary fired",
                    duration=4.2, exit_code=0,
                )},
            ),
        ],
    )
    d = report.to_dict()
    # serializable
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["schema_version"] == 1
    assert parsed["tests"][0]["id"] == "A1_fsmonitor"
    assert parsed["tests"][0]["results"]["githacker"]["verdict"] == "FAIL"
    assert parsed["tests"][0]["results"]["githacker"]["evidence"] == "canary fired"


def test_default_oracle_ignores_unrelated_files(tmp_path):
    """Stray files in canary_dir other than PWNED_<prefix> shouldn't trip the oracle."""
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    (canary_dir / "PWNED_OTHER").write_text("x")
    (canary_dir / "some_unrelated_file").write_text("x")

    check = _default_oracle("A1_fsmonitor")
    verdict, _ = check(tmp_path, canary_dir, None)
    assert verdict is Verdict.PASS


@pytest.mark.parametrize("test_id,prefix", [
    ("A1_fsmonitor", "A1"),
    ("B1_index_traversal", "B1"),
    ("C1_html_traversal", "C1"),
])
def test_canary_naming_matches_payload_convention(tmp_path, test_id, prefix):
    """Sanity: the prefix the default oracle derives matches the test ID."""
    check = _default_oracle(test_id)
    (tmp_path / f"PWNED_{prefix}").write_text("x")
    verdict, evidence = check(tmp_path, tmp_path, None)
    assert verdict is Verdict.FAIL
    assert f"PWNED_{prefix}" in evidence
