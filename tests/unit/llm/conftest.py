"""Shared fixtures: no network, no real settings, and an incident full of personal data."""

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from prohori.llm.settings import ENV_VARS
from prohori.schema import Incident

ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "samples" / "incidents" / "INC-ee7c8818fbb34989.json"

USER = "rahim.khan"
BANGLA_USER = "রহিম"  # a non-ASCII account name
EMAIL = "rahim.khan@example.com"
RAW = "RAWLINE-7c1f"  # stands for log content an attacker controls
SECRET_KEY = "test-key-test-key-test-key"  # noqa: S105  # gitleaks:allow - fake, for leak tests


def _blocked(*args: object, **kwargs: object) -> None:
    raise OSError("network access is blocked in tests")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Hide real LLM settings and keys; keep the request budget in a temporary cache."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("PROHORI_CACHE_PATH", str(tmp_path / "cache.sqlite"))
    monkeypatch.chdir(tmp_path)  # no .env from the repository


def personal_incident() -> Incident:
    """The sample incident with account names, emails and log content in every free-text field."""
    data: dict[str, Any] = json.loads(SAMPLE.read_text(encoding="utf-8"))
    data["entities"]["user.name"] = [USER, BANGLA_USER]
    data["title"] = f"Takeover of {USER} and {BANGLA_USER}"
    data["alerts"][0]["entities"]["user.name"] = USER
    data["alerts"][0]["explanation"] = f"{USER} signed in after failures"
    data["score_breakdown"][0]["reason"] += f" for {USER}"
    data["limitations"].append(f"Contact {EMAIL} to confirm; {BANGLA_USER} was on leave")
    data["recommended_actions"].append(f"Reset the password of {USER}")
    for entry in data["timeline"]:
        if entry["alert_id"] is None:
            entry["description"] += f" {RAW} ua=Mozilla {EMAIL} user={USER}"
            entry["account"] = USER
    return Incident.model_validate(data)
