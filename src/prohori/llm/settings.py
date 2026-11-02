"""LLM analyst settings from environment variables and an optional ``.env`` file.

Environment variables win over ``.env``. Only the variables in :data:`ENV_VARS` are read. The API
key is kept out of ``repr`` and error messages.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TypeVar

from prohori.enrich.config import ConfigError, read_env_file

#: Every variable the LLM analyst reads, with its meaning.
ENV_VARS: dict[str, str] = {
    "PROHORI_LLM_PROVIDER": "none (default: nothing is sent), mock (offline, for tests) or gemini",
    "PROHORI_LLM_MODEL": "Model name for the provider (default gemini-3.5-flash-lite)",
    "GEMINI_API_KEY": "Gemini API key from Google AI Studio (needed for the gemini provider)",
    "PROHORI_LLM_TIER": "free (default; Google may use what is sent) or paid (billing enabled)",
    "PROHORI_LLM_MASK_IPS": "true to replace IP addresses with pseudonyms too (default false)",
    "PROHORI_LLM_DAILY_REQUESTS": "Requests per UTC day before falling back (default 20)",
    "PROHORI_LLM_MAX_INPUT_TOKENS": "Estimated input size limit; the timeline is trimmed (6000)",
    "PROHORI_LLM_MAX_OUTPUT_TOKENS": "Longest answer requested, in tokens (default 1024)",
    "PROHORI_LLM_TIMEOUT": "Seconds to wait for an answer (default 60)",
}

DEFAULT_MODEL = "gemini-3.5-flash-lite"
E = TypeVar("E", bound=StrEnum)
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"", "0", "false", "no", "off"})


class ProviderName(StrEnum):
    NONE = "none"
    MOCK = "mock"
    GEMINI = "gemini"


class Tier(StrEnum):
    FREE = "free"
    PAID = "paid"


@dataclass(frozen=True)
class LLMSettings:
    provider: ProviderName = ProviderName.NONE
    model: str = DEFAULT_MODEL
    api_key: str = field(default="", repr=False)
    tier: Tier = Tier.FREE
    mask_ips: bool = False
    daily_requests: int = 20
    max_input_tokens: int = 6000
    max_output_tokens: int = 1024
    timeout: float = 60.0

    @classmethod
    def load(
        cls, environ: Mapping[str, str] | None = None, env_file: Path | None = Path(".env")
    ) -> "LLMSettings":
        """Build settings from ``environ`` (default ``os.environ``) over ``env_file``.

        Raises:
            ConfigError: if a setting has an invalid value.
        """
        values = read_env_file(env_file, ENV_VARS) if env_file is not None else {}
        values.update({k: v for k, v in (environ or os.environ).items() if k in ENV_VARS})
        return cls(
            provider=_choice(values, "PROHORI_LLM_PROVIDER", ProviderName, ProviderName.NONE),
            model=values.get("PROHORI_LLM_MODEL", "").strip() or DEFAULT_MODEL,
            api_key=values.get("GEMINI_API_KEY", "").strip(),
            tier=_choice(values, "PROHORI_LLM_TIER", Tier, Tier.FREE),
            mask_ips=_flag(values, "PROHORI_LLM_MASK_IPS"),
            daily_requests=_count(values, "PROHORI_LLM_DAILY_REQUESTS", 20, minimum=0),
            max_input_tokens=_count(values, "PROHORI_LLM_MAX_INPUT_TOKENS", 6000, minimum=500),
            max_output_tokens=_count(values, "PROHORI_LLM_MAX_OUTPUT_TOKENS", 1024, minimum=64),
            timeout=float(_count(values, "PROHORI_LLM_TIMEOUT", 60, minimum=1)),
        )


def _choice(values: Mapping[str, str], key: str, kind: type[E], default: E) -> E:
    raw = values.get(key, "").strip().lower()
    if not raw:
        return default
    try:
        return kind(raw)
    except ValueError:
        allowed = ", ".join(m.value for m in kind)
        raise ConfigError(f"{key} must be one of {allowed}, not {raw[:40]!r}") from None


def _flag(values: Mapping[str, str], key: str) -> bool:
    raw = values.get(key, "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ConfigError(f"{key} must be true or false, not {raw[:40]!r}")


def _count(values: Mapping[str, str], key: str, default: int, *, minimum: int) -> int:
    raw = values.get(key, "").strip()
    if not raw:
        return default
    try:
        number = int(raw)
    except ValueError:
        raise ConfigError(f"{key} must be a whole number, not {raw[:40]!r}") from None
    if number < minimum:
        raise ConfigError(f"{key} must be at least {minimum}")
    return number
