"""Providers, settings and the fallback to a local summary."""

import builtins
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.config import ConfigError
from prohori.enrich.ratelimit import DailyBudget
from prohori.llm import MissingExtraError
from prohori.llm.explain import clean_answer, explain, local_summary
from prohori.llm.payload import build_payload
from prohori.llm.provider import (
    GeminiProvider,
    MockProvider,
    NoneProvider,
    ProviderDisabledError,
    ProviderError,
    QuotaError,
    Request,
)
from prohori.llm.settings import DEFAULT_MODEL, LLMSettings, ProviderName, Tier
from tests.unit.llm.conftest import SECRET_KEY, USER, personal_incident


class FakeAPIError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code} {message}")
        self.code = code


class FakeModels:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _client(outcome: Any) -> SimpleNamespace:
    return SimpleNamespace(models=FakeModels(outcome))


def _answer(text: str | None, reason: str = "STOP") -> SimpleNamespace:
    return SimpleNamespace(
        text=text,
        usage_metadata=SimpleNamespace(prompt_token_count=900, candidates_token_count=120),
        candidates=[SimpleNamespace(finish_reason=SimpleNamespace(value=reason))],
    )


REQUEST = Request(system="sys", prompt="prompt", max_output_tokens=256)


def test_gemini_sends_one_request_with_the_settings() -> None:
    client = _client(_answer("## Summary\nok"))
    provider = GeminiProvider("", "gemini-3.5-flash-lite", client=client)
    response = provider.generate(REQUEST)
    assert response.text.startswith("## Summary")
    assert (response.input_tokens, response.output_tokens) == (900, 120)
    call = client.models.calls[0]
    assert call["model"] == "gemini-3.5-flash-lite"
    assert call["contents"] == "prompt"
    assert call["config"] == {
        "system_instruction": "sys",
        "max_output_tokens": 256,
        "temperature": 0.2,
    }


@pytest.mark.parametrize(
    ("outcome", "error", "message"),
    [
        (FakeAPIError(429, "RESOURCE_EXHAUSTED"), QuotaError, "rate limit or quota"),
        (FakeAPIError(403, "PERMISSION_DENIED"), ProviderError, "refused the API key"),
        (FakeAPIError(500, f"internal key={SECRET_KEY}"), ProviderError, "Gemini error 500"),
        (type("ReadTimeout", (Exception,), {})("slow"), ProviderError, "did not answer in time"),
        (ConnectionError("down " + SECRET_KEY), ProviderError, "request failed"),
    ],
)
def test_gemini_errors_never_show_the_key(outcome: Exception, error: type, message: str) -> None:
    provider = GeminiProvider(SECRET_KEY, "m", client=_client(outcome))
    with pytest.raises(error, match=message) as info:
        provider.generate(REQUEST)
    assert SECRET_KEY not in str(info.value)


def test_an_empty_or_blocked_answer_is_an_error() -> None:
    provider = GeminiProvider("", "m", client=_client(_answer(None, "SAFETY")))
    with pytest.raises(ProviderError, match="finish reason SAFETY"):
        provider.generate(REQUEST)
    empty = GeminiProvider("", "m", client=_client(SimpleNamespace(text="  ", candidates=[])))
    with pytest.raises(ProviderError, match="empty or blocked"):
        empty.generate(REQUEST)


def test_gemini_needs_a_key_and_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ProviderError, match="GEMINI_API_KEY is not set"):
        GeminiProvider("", "m")
    real_import = builtins.__import__

    def no_genai(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("google"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_genai)
    with pytest.raises(MissingExtraError, match="'llm' extra"):
        GeminiProvider(SECRET_KEY, "m")


def test_the_real_client_is_built_without_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.genai", reason="the llm extra is not installed")
    from google import genai

    seen: dict[str, Any] = {}

    def fake_client(**kwargs: Any) -> SimpleNamespace:
        seen.update(kwargs)
        return _client(_answer("ok"))

    monkeypatch.setattr(genai, "Client", fake_client)
    GeminiProvider(SECRET_KEY, "m", timeout=30).generate(REQUEST)
    assert seen["api_key"] == SECRET_KEY
    assert seen["vertexai"] is False
    assert seen["http_options"].timeout == 30_000
    assert seen["http_options"].retry_options.attempts == 1


def test_none_provider_refuses() -> None:
    with pytest.raises(ProviderDisabledError):
        NoneProvider().generate(REQUEST)


def test_fallbacks_say_why_and_whether_anything_was_sent(tmp_path: Path) -> None:
    incident = personal_incident()
    quota = GeminiProvider("", "m", client=_client(FakeAPIError(429, "quota")))
    result = explain(incident, quota)
    assert (result.source, result.sent) == ("local", True)
    assert "quota" in (result.reason or "")
    assert result.text == local_summary(incident)

    budget = DailyBudget("llm:gemini", 1, EnrichmentCache(tmp_path / "c.sqlite"))
    ok = GeminiProvider("", "m", client=_client(_answer("fine")))
    assert explain(incident, ok, budget=budget).source == "gemini"
    used_up = explain(incident, ok, budget=budget)
    assert (used_up.source, used_up.sent) == ("local", False)
    assert "budget" in (used_up.reason or "")


def test_mock_explanation_and_pseudonyms() -> None:
    incident = personal_incident()
    provider = MockProvider()
    shown = explain(incident, provider, payload=build_payload(incident), restore=False)
    assert shown.source == "mock"
    assert not shown.sent
    assert USER not in shown.text
    assert "[user:" in shown.text


def test_answers_are_cleaned() -> None:
    assert clean_answer("ok\x1b[31m red\r\nline\x07") == "ok red\nline"
    assert clean_answer("x" * 30_000).endswith("[truncated]")


def test_settings_from_env_and_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROHORI_LLM_PROVIDER", "gemini")  # an empty environ means none at all
    assert LLMSettings.load(environ={}, env_file=None) == LLMSettings()
    env = tmp_path / ".env"
    env.write_text(
        f"PROHORI_LLM_PROVIDER=Gemini\nGEMINI_API_KEY={SECRET_KEY}\nPROHORI_LLM_MASK_IPS=yes\n"
        "PROHORI_LLM_TIER=paid\nPROHORI_LLM_DAILY_REQUESTS=5\nUNRELATED=1\n",
        encoding="utf-8",
    )
    settings = LLMSettings.load(environ={"PROHORI_LLM_MODEL": "gemini-3.8-flash"}, env_file=env)
    assert settings.provider is ProviderName.GEMINI
    assert settings.api_key == SECRET_KEY
    assert settings.model == "gemini-3.8-flash"
    assert settings.mask_ips
    assert settings.tier is Tier.PAID
    assert settings.daily_requests == 5
    assert SECRET_KEY not in repr(settings)
    assert LLMSettings().model == DEFAULT_MODEL
    for key, value, message in [
        ("PROHORI_LLM_PROVIDER", "openai", "must be one of"),
        ("PROHORI_LLM_MASK_IPS", "maybe", "true or false"),
        ("PROHORI_LLM_TIMEOUT", "soon", "whole number"),
        ("PROHORI_LLM_MAX_OUTPUT_TOKENS", "10", "at least 64"),
    ]:
        with pytest.raises(ConfigError, match=message):
            LLMSettings.load(environ={key: value}, env_file=None)


def test_every_llm_variable_is_documented() -> None:
    from prohori.llm.settings import ENV_VARS
    from tests.unit.llm.conftest import ROOT

    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "LLM_ANALYST.md").read_text(encoding="utf-8")
    for name in ENV_VARS:
        assert f"{name}=" in example, name
        assert name in guide, name
