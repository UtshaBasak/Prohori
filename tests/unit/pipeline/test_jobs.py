"""Scheduled jobs: incident digest, recall gate and enrichment refresh (and their commands)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.enrich import Enricher
from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.offline import OfflineProvider
from prohori.pipeline import jobs
from prohori.pipeline.producers import replay
from prohori.pipeline.runner import LitePipeline, LiteSettings
from prohori.pipeline.sink import Sink
from prohori.pipeline.transport import MemoryTransport
from prohori.pipeline.warehouse import LoadError, open_warehouse
from prohori.rules import builtin_rules_dir, load_rules
from prohori.simulate import simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "results" / "ml_unsw-nb15.json"
RULES = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


@pytest.fixture(scope="module")
def warehouse(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A lite-mode DuckDB file after replaying a simulated password-spraying attack."""
    out = tmp_path_factory.mktemp("jobs")
    write(simulate("password-spraying", seed=1), out)
    database = out / "prohori.duckdb"
    pipeline = LitePipeline(MemoryTransport(), LiteSettings(rules=RULES, database=database))
    replay(out / "password-spraying.jsonl", pipeline.transport, parser="app_json")
    pipeline.run()
    pipeline.close()
    return database


def _window() -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    return now - timedelta(hours=1), now + timedelta(minutes=1)


def test_digest_counts_what_was_stored_in_the_window(warehouse: Path) -> None:
    sink = open_warehouse(database=warehouse)
    try:
        digest = jobs.build_digest(sink, *_window(), limit=3)
        empty = jobs.build_digest(
            sink, datetime(2000, 1, 1, tzinfo=UTC), datetime(2000, 1, 2, tzinfo=UTC)
        )
    finally:
        sink.close()
    assert digest.events == 622
    assert digest.alerts > 0
    assert digest.dead_letters == 0
    assert len(digest.incidents) == 3
    assert sum(digest.severities.values()) >= len(digest.incidents)
    assert list(digest.severities) == [s for s in jobs.SEVERITIES if s in digest.severities]
    scores = [i.score for i in digest.incidents]
    assert scores == sorted(scores, reverse=True)
    assert sum(n for _, n in digest.rules) == digest.alerts
    text = jobs.render_digest(digest)
    assert text.startswith("# Prohori incident digest")
    assert "## Top incidents" in text
    assert digest.incidents[0].id in text
    data = json.loads(jobs.digest_json(digest))
    assert data["format"] == "prohori.digest/1"
    assert data["events"] == 622
    assert "Nothing was detected in this period." in jobs.render_digest(empty)
    assert empty.incidents == []


def test_digest_escapes_table_cells() -> None:
    incident = jobs.DigestIncident(
        "INC-1",
        "high",
        50.0,
        "high",
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 1, tzinfo=UTC),
        1,
        "a|b\nc",
    )
    digest = jobs.Digest(
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
        1,
        1,
        0,
        [incident],
        {"high": 1},
        [("R", 1)],
    )
    assert "a\\|b c" in jobs.render_digest(digest)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[Any]]] = []

    def execute(self, sql: str, params: list[Any]) -> "_Recorder":
        self.calls.append((sql, params))
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        return [("a", 1)]


def test_queries_use_the_raw_schema_and_placeholders_on_postgres() -> None:
    recorder = _Recorder()
    sink = cast(Sink, SimpleNamespace(connection=recorder))
    assert jobs._query(sink, "SELECT x FROM {t}events WHERE a = ?", (1,)) == [("a", 1)]
    assert recorder.calls == [("SELECT x FROM raw.events WHERE a = %s", [1])]


def test_digest_command(warehouse: Path, tmp_path: Path) -> None:
    printed = runner.invoke(app, ["pipeline", "digest", "--db", str(warehouse)])
    assert printed.exit_code == 0, printed.output
    assert "# Prohori incident digest" in printed.stdout
    out = tmp_path / "digests" / "today.json"
    written = runner.invoke(
        app, ["pipeline", "digest", "--db", str(warehouse), "-f", "json", "--out", str(out)]
    )
    assert written.exit_code == 0, written.output
    assert "incident(s) listed" in written.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["events"] == 622


def test_recall_gate_on_the_committed_results() -> None:
    check = jobs.check_recall(
        RESULTS, minimum=0.75, model="hgb", variant="cleaned", operating_point="fpr_0.01"
    )
    assert check.dataset == "unsw-nb15"
    assert len(check.recalls) == 3
    assert 0.8 < check.mean < 0.85
    assert check.passed
    strict = jobs.check_recall(
        RESULTS, minimum=0.9, model="hgb", variant="cleaned", operating_point="fpr_0.01"
    )
    assert not strict.passed
    with pytest.raises(ValueError, match=r"has no knn/cleaned/fpr_0.01 runs"):
        jobs.check_recall(
            RESULTS, minimum=0.5, model="knn", variant="cleaned", operating_point="fpr_0.01"
        )


def test_check_recall_command(tmp_path: Path) -> None:
    ok = runner.invoke(app, ["pipeline", "check-recall", str(RESULTS)])
    assert ok.exit_code == 0, ok.output
    assert ok.stdout.startswith("OK: unsw-nb15 hgb/cleaned at fpr_0.01: mean recall 0.8")
    low = runner.invoke(app, ["pipeline", "check-recall", str(RESULTS), "--min-recall", "0.9"])
    assert low.exit_code == ExitCode.NO_EVENTS
    assert "recall dropped below the minimum" in low.stderr
    wrong = runner.invoke(app, ["pipeline", "check-recall", str(RESULTS), "--model", "knn"])
    assert wrong.exit_code == ExitCode.USAGE
    missing = runner.invoke(app, ["pipeline", "check-recall", str(tmp_path / "none.json")])
    assert missing.exit_code == ExitCode.USAGE
    other = tmp_path / "other.json"
    other.write_text('{"format": "something else"}', encoding="utf-8")
    unreadable = runner.invoke(app, ["pipeline", "check-recall", str(other)])
    assert unreadable.exit_code == ExitCode.NO_EVENTS
    with pytest.raises(LoadError):
        jobs.check_recall(
            other, minimum=0.5, model="hgb", variant="cleaned", operating_point="fpr_0.01"
        )


def test_recent_addresses_keep_public_ones_only(tmp_path: Path) -> None:
    sink = open_warehouse(database=tmp_path / "w.duckdb")
    try:
        sink.connection.execute(  # type: ignore[attr-defined]
            "INSERT INTO events (id, timestamp, log_source, action, category, outcome, source_ip,"
            " record) VALUES "
            "('1', now(), 's', 'a', 'c', 'o', '8.8.8.8', '{}'),"
            "('2', now(), 's', 'a', 'c', 'o', '8.8.8.8', '{}'),"
            "('3', now(), 's', 'a', 'c', 'o', '1.1.1.1', '{}'),"
            "('4', now(), 's', 'a', 'c', 'o', '10.0.0.1', '{}'),"
            "('5', now(), 's', 'a', 'c', 'o', 'not an ip', '{}'),"
            "('6', now(), 's', 'a', 'c', 'o', NULL, '{}')"
        )
        since = datetime.now(UTC) - timedelta(days=1)
        assert jobs.recent_addresses(sink, since) == ["8.8.8.8", "1.1.1.1"]
        assert jobs.recent_addresses(sink, since, limit=1) == ["8.8.8.8"]
    finally:
        sink.close()


def test_refresh_enrichment_purges_and_looks_up(tmp_path: Path) -> None:
    cache = EnrichmentCache(tmp_path / "cache.sqlite")
    cache.put("abuseipdb", "8.8.8.8", None, timedelta(seconds=-1))  # already expired
    enricher = Enricher([OfflineProvider()], cache, offline=True)
    result = jobs.refresh_enrichment(enricher, ["8.8.8.8", "1.1.1.1"])
    assert result == jobs.RefreshResult(
        addresses=2, looked_up=2, purged=1, providers=[OfflineProvider.name]
    )
    assert jobs.refresh_enrichment(Enricher([]), []).purged == 0


def test_refresh_enrichment_command(warehouse: Path) -> None:
    done = runner.invoke(app, ["pipeline", "refresh-enrichment", "--db", str(warehouse)])
    assert done.exit_code == 0, done.output
    # The simulator only uses documentation addresses, which are never looked up.
    assert done.stdout.startswith("Refreshed 0 of 0 public address(es) (offline;")
