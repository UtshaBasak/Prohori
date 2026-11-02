"""LLM providers behind one small interface: ``none``, ``mock`` and ``gemini``.

A provider turns a :class:`Request` (system instruction and prompt) into a :class:`Response`, or
raises :class:`ProviderError`. Errors never contain the API key, and their text is shortened.

- ``none`` sends nothing; asking it for an answer raises :class:`ProviderDisabledError`.
- ``mock`` answers offline from the payload in the prompt and records every request, for tests
  and demonstrations.
- ``gemini`` calls the Gemini Developer API through the ``google-genai`` SDK (``llm`` extra) with
  ``generate_content``, one attempt per request (the SDK's own retries are turned off, so one
  request counts once against the daily budget) and a timeout.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from prohori.llm import MissingExtraError
from prohori.parsers import sanitize

MAX_ERROR = 300


@dataclass(frozen=True)
class Request:
    system: str
    prompt: str
    max_output_tokens: int = 1024
    temperature: float = 0.2


@dataclass(frozen=True)
class Response:
    text: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class ProviderError(RuntimeError):
    """The provider could not answer (the caller falls back to a local summary)."""


class ProviderDisabledError(ProviderError):
    """The ``none`` provider: the LLM analyst is off."""


class QuotaError(ProviderError):
    """The provider's rate limit or quota was reached (HTTP 429)."""


class Provider(Protocol):
    name: ClassVar[str]
    sends_data: ClassVar[bool]

    def generate(self, request: Request) -> Response:
        """Answer ``request`` or raise :class:`ProviderError`."""


class NoneProvider:
    name: ClassVar[str] = "none"
    sends_data: ClassVar[bool] = False

    def generate(self, request: Request) -> Response:
        del request
        raise ProviderDisabledError("the LLM analyst is off")


@dataclass
class MockProvider:
    """Answers offline from the payload in the prompt; ``requests`` keeps what it was sent."""

    name: ClassVar[str] = "mock"
    sends_data: ClassVar[bool] = False
    requests: list[Request] = field(default_factory=list)

    def generate(self, request: Request) -> Response:
        self.requests.append(request)
        start, end = request.prompt.find("{"), request.prompt.rfind("}")
        data = json.loads(request.prompt[start : end + 1])
        rules = ", ".join(sorted({a["rule"] for a in data["alerts"]}))
        accounts = sorted({v for k, vs in data["entities"].items() if "user" in k for v in vs})
        lines = [
            "## Summary",
            f"{data['title']} ({data['severity']}, score {data['score']:g}).",
            "",
            "## Evidence",
            f"- Rules: {rules}.",
            f"- Accounts: {', '.join(accounts) or 'none named'}.",
            f"- {data['timeline']['events']} events from {data['first_seen']} to "
            f"{data['last_seen']}.",
            "",
            "## Next steps",
            *(f"- {a}" for a in data["recommended_actions"][:3]),
        ]
        text = "\n".join(lines)
        return Response(
            text=text,
            model="mock",
            input_tokens=len(request.prompt) // 4,
            output_tokens=len(text) // 4,
        )


class GeminiProvider:
    """The Gemini Developer API (``google-genai``). ``client`` is injected in tests."""

    name: ClassVar[str] = "gemini"
    sends_data: ClassVar[bool] = True

    def __init__(
        self, api_key: str, model: str, *, timeout: float = 60.0, client: object = None
    ) -> None:
        if not api_key and client is None:
            raise ProviderError("GEMINI_API_KEY is not set")
        self.model = model
        self._key = api_key
        self._client: Any = client if client is not None else _client(api_key, timeout)

    def generate(self, request: Request) -> Response:
        config = {
            "system_instruction": request.system,
            "max_output_tokens": request.max_output_tokens,
            "temperature": request.temperature,
        }
        try:
            response = self._client.models.generate_content(
                model=self.model, contents=request.prompt, config=config
            )
        except Exception as exc:  # the SDK's APIError, httpx timeouts, connection errors
            raise self._error(exc) from None
        text = getattr(response, "text", None)
        if not text or not text.strip():
            raise ProviderError(f"no answer from {self.model} ({_finish_reason(response)})")
        usage = getattr(response, "usage_metadata", None)
        return Response(
            text=text,
            model=self.model,
            input_tokens=getattr(usage, "prompt_token_count", None),
            output_tokens=getattr(usage, "candidates_token_count", None),
        )

    def _error(self, exc: Exception) -> ProviderError:
        code = getattr(exc, "code", None)
        message = _clean(str(exc), self._key)
        if code == 429:  # HTTP Too Many Requests
            return QuotaError(f"Gemini rate limit or quota reached: {message}")
        if code in {401, 403}:
            return ProviderError(f"Gemini refused the API key ({code})")
        if "timeout" in type(exc).__name__.lower():
            return ProviderError("Gemini did not answer in time")
        prefix = f"Gemini error {code}" if code else f"Gemini request failed ({type(exc).__name__})"
        return ProviderError(f"{prefix}: {message}")


def _client(api_key: str, timeout: float) -> Any:  # noqa: ANN401 - google-genai is optional
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise MissingExtraError("the gemini provider") from exc
    options = types.HttpOptions(
        timeout=int(timeout * 1000),  # milliseconds
        retry_options=types.HttpRetryOptions(attempts=1),
    )
    # vertexai=False and an explicit key: GOOGLE_GENAI_USE_VERTEXAI or GOOGLE_API_KEY in the
    # environment never redirect the request or replace the key.
    return genai.Client(api_key=api_key, vertexai=False, http_options=options)


def _finish_reason(response: object) -> str:
    candidates = getattr(response, "candidates", None) or []
    reason = getattr(candidates[0], "finish_reason", None) if candidates else None
    value = getattr(reason, "value", reason)
    return f"finish reason {value}" if value else "the answer was empty or blocked"


def _clean(text: str, key: str) -> str:
    if key:
        text = text.replace(key, "[key]")
    text = re.sub(r"key=[A-Za-z0-9_-]{8,}", "key=[key]", text)
    text = sanitize(" ".join(text.split()))
    return text if len(text) <= MAX_ERROR else text[: MAX_ERROR - 1] + "…"
