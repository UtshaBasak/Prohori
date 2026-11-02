"""The benchmark script on tiny logs: log building, measuring a real process, the tables."""

import json
from pathlib import Path

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
