# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The benchmark script on tiny logs: log building, measuring a real process, the tables."""

import json
from pathlib import Path

import pytest

from scripts import benchmark, generate_results_table


def test_logs_are_built_in_order_for_every_format(tmp_path: Path) -> None:
    for parser in benchmark.LOGS:
        path = tmp_path / f"{parser}.log"
        written = benchmark.build_log(parser, 500, path)
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == written >= 500
    first = benchmark.build_log("access_log", 500, tmp_path / "again.log")
    assert (tmp_path / "again.log").read_bytes() == (tmp_path / "access_log.log").read_bytes()
    assert first


def test_a_small_run_measures_real_processes(tmp_path: Path) -> None:
    out = tmp_path / "performance.json"
    work = tmp_path / "work"
    assert (
        benchmark.main(["--lines", "300", "--no-pipeline", "--out", str(out), "--work", str(work)])
        == 0
    )
    assert not work.exists()  # deleted unless --keep
    results = json.loads(out.read_text(encoding="utf-8"))
    names = [r["name"] for r in results["runs"]]
    assert names == ["incidents-access_log", "incidents-auth_log", "incidents-app_json", "demo"]
    for run in results["runs"]:
        assert run["exit_code"] == 0
        assert run["peak_memory_mib"] > 20  # the Python process itself, not a launcher
        assert "WORK" in run["command"] or run["name"] == "demo"
    table = generate_results_table.render_performance(results)
    assert "| `demo` |" in table
    assert "Lines a second" in generate_results_table.render_performance_summary(results)
    assert generate_results_table.render_performance_summary(None) == "No performance results yet."


def test_alert_storm_is_measured_against_a_fixed_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Linux a child's peak memory can include its parent's from before exec, and the parent
    # here is the whole test run; the bound itself is checked by running the script directly.
    monkeypatch.setattr(benchmark, "STORM_BOUND_MIB", 1_000_000)
    log = tmp_path / "storm.jsonl"
    assert benchmark.build_alert_storm(20, log) == 20
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert {r["event"]["action"] for r in records} == {"admin.role.granted"}
    out = tmp_path / "performance.json"
    out.write_text(json.dumps({"runs": [], "kept": True}), encoding="utf-8")
    work = tmp_path / "work"
    assert benchmark.main(["--alerts", "200", "--out", str(out), "--work", str(work)]) == 0
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["kept"] is True  # the other measurements stay
    storm = results["alert_storm"]
    assert storm["bound_mib"] == 1_000_000
    assert [r["name"] for r in storm["runs"]] == [
        "storm-detect-json",
        "storm-detect-table",
        "storm-incidents",
    ]
    assert all(r["within_bound"] and r["exit_code"] == 0 for r in storm["runs"])
    assert storm["runs"][0]["alerts"] >= 200
    table = "\n".join(generate_results_table._storm_lines(storm))
    assert "| `incidents` (keeps a bounded number of alerts) |" in table


def test_alert_storm_needs_an_existing_results_file(tmp_path: Path) -> None:
    missing = tmp_path / "none.json"
    assert benchmark.main(["--alerts", "5", "--out", str(missing), "--work", str(tmp_path)]) == 1
