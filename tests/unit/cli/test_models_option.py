"""``--models`` on detect, incidents and triage: model alerts join the rule alerts."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.simulate import simulate, write
from tests.unit.enrich.conftest import isolated_settings, no_network

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache or keys

ROOT = Path(__file__).resolve().parents[3]
runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


@pytest.fixture(scope="module")
def web_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sim")
    write(simulate("web-scanning", seed=1), out)
    return out / "web-scanning.log"


def _alerts(output: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def test_detect_with_models(web_log: Path) -> None:
    plain = runner.invoke(app, ["detect", str(web_log), "-f", "json"])
    with_models = runner.invoke(app, ["detect", str(web_log), "-f", "json", "--models"])
    assert plain.exit_code == with_models.exit_code == ExitCode.ALERTS_FOUND
    rule_alerts = _alerts(plain.stdout)
    all_alerts = _alerts(with_models.stdout)
    models = [a for a in all_alerts if a["detector_kind"] == "model"]
    assert {a["detector_id"] for a in models} == {"PRH-ML-ZSCORE", "PRH-ML-IFOREST"}
    assert all_alerts[: len(rule_alerts)] == rule_alerts  # rules are unchanged
    assert all(a["detector_kind"] == "rule" for a in rule_alerts)
    table = runner.invoke(app, ["detect", str(web_log), "--models"])
    assert "PRH-ML-ZSCORE" in table.stdout


def test_incidents_and_triage_with_models(web_log: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["incidents", str(web_log), "-f", "json", "--models"])
    incidents = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    detectors = {a["detector_id"] for i in incidents for a in i["alerts"]}
    assert "PRH-ML-ZSCORE" in detectors
    model_incident = next(
        i for i in incidents if any(a["detector_kind"] == "model" for a in i["alerts"])
    )
    assert any("anomaly detector" in text for text in model_incident["limitations"])
    assert any(
        "window an anomaly detector flagged" in a for a in model_incident["recommended_actions"]
    )
    # Redaction still succeeds: model explanations hold only numbers.
    out = tmp_path / "triage"
    triage = runner.invoke(
        app, ["triage", str(web_log), "-o", str(out), "--models", "--redact-ips", "--exit-zero"]
    )
    assert triage.exit_code == 0, triage.stdout + triage.stderr
    assert "PRH-ML-ZSCORE" in (out / "incidents.jsonl").read_text(encoding="utf-8")


def test_too_few_windows_is_explained(tmp_path: Path) -> None:
    log = tmp_path / "tiny.log"
    log.write_text(
        '192.0.2.1 - - [24/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["detect", str(log), "--models"])
    assert result.exit_code == 0
    assert "needs at least 20 source-IP windows" in result.stderr


def test_models_without_the_ml_extra(web_log: Path) -> None:
    """With scikit-learn missing, --models still runs the z-score detector."""
    code = f"""
import sys
for name in ("sklearn", "pandas", "pyarrow", "joblib"):
    sys.modules[name] = None
from typer.testing import CliRunner
from prohori.cli import app
result = CliRunner().invoke(app, ["detect", {str(web_log)!r}, "-f", "json", "--models"])
print("ZSCORE" if "PRH-ML-ZSCORE" in result.stdout else "none")
print("IFOREST" if "PRH-ML-IFOREST" in result.stdout else "no-iforest")
print(result.stderr)
"""
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[:2] == ["ZSCORE", "no-iforest"]
    assert "the Isolation Forest needs the ml extra" in done.stdout
