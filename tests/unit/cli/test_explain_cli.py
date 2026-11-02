"""``prohori explain``: off by default, the payload preview, mock answers and fallbacks."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prohori.cli import app
from prohori.cli.exit_codes import ExitCode
from prohori.llm import payload as payload_module
from tests.unit.llm.conftest import (
    SAMPLE,
    SECRET_KEY,
    USER,
    isolated_settings,
    no_network,
    personal_incident,
)

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real settings

runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


@pytest.fixture
def incident_file(tmp_path: Path) -> Path:
    path = tmp_path / "incident.json"
    path.write_text(personal_incident().model_dump_json(), encoding="utf-8")
    return path


def test_off_by_default_exits_cleanly(incident_file: Path) -> None:
    result = runner.invoke(app, ["explain", str(incident_file)])
    assert result.exit_code == 0, result.output
    assert "The LLM analyst is off" in result.stdout
    assert "nothing was sent" in result.stdout


def test_show_payload_prints_the_redacted_payload(incident_file: Path) -> None:
    result = runner.invoke(app, ["explain", str(incident_file), "--show-payload", "--mask-ips"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["id"] == personal_incident().id
    assert USER not in result.stdout
    assert "203.0.113.7" not in result.stdout
    assert "nothing was sent" in result.stderr


def test_mock_provider_answers(incident_file: Path) -> None:
    result = runner.invoke(app, ["explain", str(incident_file), "--provider", "mock"])
    assert result.exit_code == 0, result.output
    assert "## Summary" in result.stdout
    assert "by mock" in result.stderr
    kept = runner.invoke(
        app, ["explain", str(incident_file), "--provider", "mock", "--keep-pseudonyms"]
    )
    assert "[user:" in kept.stdout


def test_gemini_without_a_key_falls_back(incident_file: Path) -> None:
    result = runner.invoke(app, ["explain", str(incident_file), "--provider", "gemini"])
    assert result.exit_code == 0, result.output
    assert "Local summary" in result.stderr
    assert "nothing was sent: GEMINI_API_KEY is not set" in result.stderr
    assert "## Summary" in result.stdout


def test_gemini_with_a_key_warns_about_the_free_tier(
    incident_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from prohori.cli import explain as explain_cli
    from tests.unit.llm.test_providers import _answer, _client

    monkeypatch.setenv("GEMINI_API_KEY", SECRET_KEY)
    monkeypatch.setenv("PROHORI_LLM_PROVIDER", "gemini")
    from prohori.llm.provider import GeminiProvider

    monkeypatch.setattr(
        explain_cli,
        "GeminiProvider",
        lambda key, model, timeout: GeminiProvider(
            key, model, timeout=timeout, client=_client(_answer("## Summary\nfrom gemini"))
        ),
    )
    result = runner.invoke(app, ["explain", str(incident_file)])
    assert result.exit_code == 0, result.output
    assert "free tier" in result.stderr
    assert "from gemini" in result.stdout
    assert "900 tokens in, 120 out" in result.stderr
    assert SECRET_KEY not in result.output
    monkeypatch.setenv("PROHORI_LLM_TIER", "paid")
    paid = runner.invoke(app, ["explain", str(incident_file)])
    assert "free tier" not in paid.stderr


def test_redaction_failure_sends_nothing(
    incident_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(payload_module, "find_leaks", lambda text, values: ["x"])
    result = runner.invoke(app, ["explain", str(incident_file), "--provider", "mock"])
    assert result.exit_code == ExitCode.REDACTION_FAILED
    assert "nothing was sent" in result.stderr


def test_bad_settings_and_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROHORI_LLM_PROVIDER", "openai")
    bad = runner.invoke(app, ["explain", str(SAMPLE)])
    assert bad.exit_code == ExitCode.USAGE
    monkeypatch.delenv("PROHORI_LLM_PROVIDER")
    missing = runner.invoke(app, ["explain", str(tmp_path / "none.json")])
    assert missing.exit_code == ExitCode.USAGE
