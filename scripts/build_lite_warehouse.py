"""Build a lite-mode warehouse from the simulator, for the dbt models.

Every scenario is simulated, replayed through its own lite pipeline (its own topics, so the
scenarios' different clocks do not make each other's events late) into one DuckDB file, and its
labels are loaded; flow-model results are loaded too. CI builds the dbt models on the result.

    uv run python scripts/build_lite_warehouse.py --db .prohori/pipeline/prohori.duckdb
"""

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from prohori.pipeline.producers import replay
from prohori.pipeline.runner import LitePipeline, LiteSettings
from prohori.pipeline.stages import ParserSettings
from prohori.pipeline.transport import MemoryTransport
from prohori.pipeline.warehouse import evaluation_rows, label_rows, load, open_warehouse
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import SCENARIOS, simulate, write

ROOT = Path(__file__).resolve().parents[1]
RESULTS = tuple(ROOT / "results" / name for name in ("ml_unsw-nb15.json", "ml_cicids2017.json"))


def build(
    database: Path,
    work: Path,
    *,
    seed: int = 1,
    variant: str = "default",
    scenarios: Sequence[str] | None = None,
    results: Sequence[Path] = RESULTS,
) -> dict[str, object]:
    """Simulate, replay and load every scenario into ``database``; return a summary."""
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    summary: dict[str, object] = {}
    for name in sorted(scenarios or SCENARIOS):
        simulation = simulate(name, seed=seed, variant=variant)
        folder = work / name
        write(simulation, folder)
        log = folder / simulation.scenario.filename
        year = simulation.year if simulation.scenario.parser == "auth_log" else None
        parsers = ParserSettings(year=year)
        settings = LiteSettings(
            rules=rules, database=database, parsers=parsers, lateness=timedelta(minutes=5)
        )
        pipeline = LitePipeline(MemoryTransport(), settings)
        try:
            replay(log, pipeline.transport, parser=simulation.scenario.parser)
            metrics = pipeline.run()
        finally:
            pipeline.close()
        labels = label_rows(log, parser=simulation.scenario.parser, settings=parsers)
        sink = open_warehouse(database=database)
        try:
            load(sink, "labels", labels)
        finally:
            sink.close()
        summary[name] = metrics["tables"]
    rows = [row for path in results if path.is_file() for row in evaluation_rows(path)]
    sink = open_warehouse(database=database)
    try:
        load(sink, "model_evaluations", rows)
        summary["tables"] = sink.counts()
    finally:
        sink.close()
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, required=True, help="DuckDB file to create or extend")
    parser.add_argument(
        "--work", type=Path, help="folder for the simulated logs (default: next to --db)"
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--variant", default="default", choices=["default", "heldout"])
    args = parser.parse_args(argv)
    work = args.work or args.db.parent / "simulated"
    summary = build(args.db, work, seed=args.seed, variant=args.variant)
    print(json.dumps(summary["tables"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
