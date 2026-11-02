"""``prohori explain``: an incident explained by an LLM, opt-in and redacted."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.cli.report import _parse, _read, _select
from prohori.enrich.config import ConfigError, EnrichSettings
from prohori.llm import MissingExtraError
from prohori.llm.explain import Explanation, explain
from prohori.llm.payload import RedactionError, build_payload
from prohori.llm.provider import (
    GeminiProvider,
    MockProvider,
    NoneProvider,
    Provider,
    ProviderError,
)
from prohori.llm.settings import LLMSettings, ProviderName, Tier

OFF_MESSAGE = (
    "The LLM analyst is off (PROHORI_LLM_PROVIDER=none), so nothing was sent. To use it, set "
    "PROHORI_LLM_PROVIDER=gemini and GEMINI_API_KEY in the environment or .env, or pass "
    "--provider; see docs/LLM_ANALYST.md. 'prohori report' and --show-payload work offline."
)
FREE_TIER_NOTICE = (
    "Note: on the Gemini API free tier, Google may use what is sent to improve its products. "
    "The incident was redacted first; set PROHORI_LLM_TIER=paid once billing is enabled."
)


def explain_command(
    file: Annotated[
        str,
        typer.Argument(
            metavar="INCIDENT",
            help="Incident JSON, or JSON Lines from 'prohori incidents -f json'; '-' for stdin.",
        ),
    ],
    incident_id: Annotated[
        str | None,
        typer.Option(
            "--incident", "-i", help="Which incident to explain when the file has several."
        ),
    ] = None,
    provider_name: Annotated[
        ProviderName | None,
        typer.Option(
            "--provider",
            help="none, mock or gemini (default: PROHORI_LLM_PROVIDER, else none).",
            show_default=False,
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(help="Model name (default: PROHORI_LLM_MODEL).", show_default=False),
    ] = None,
    mask_ips: Annotated[
        bool, typer.Option("--mask-ips", help="Also replace IP addresses before sending.")
    ] = False,
    show_payload: Annotated[
        bool,
        typer.Option("--show-payload", help="Print exactly what would be sent, and send nothing."),
    ] = False,
    keep_pseudonyms: Annotated[
        bool,
        typer.Option(
            "--keep-pseudonyms",
            help="Show the answer with the pseudonyms instead of the original accounts.",
        ),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Settings file read under the environment variables.")
    ] = Path(".env"),
) -> None:
    """Explain an incident in plain language with an LLM (opt-in; redacted before sending).

    Off by default: with the provider 'none' nothing is sent. Account names, ids and emails are
    replaced with pseudonyms before anything leaves the machine (and IP addresses with
    --mask-ips); event descriptions from the logs are never sent. If the provider cannot answer
    (no key, budget or rate limit reached, timeout), a local summary is shown instead. Exit
    codes: 0 explained or summarised (or the analyst is off), 1 redaction could not remove every
    personal value (nothing was sent), 2 invalid usage, input or setting.
    """
    try:
        settings = LLMSettings.load(env_file=env_file)
        cache_path = EnrichSettings.load(env_file=env_file).cache_path
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from None
    data, _ = _read(file)
    incident = _select(_parse(data), incident_id)
    try:
        payload = build_payload(
            incident,
            mask_ips=mask_ips or settings.mask_ips,
            max_input_tokens=settings.max_input_tokens,
        )
    except RedactionError as exc:
        typer.echo(f"error: {exc}; nothing was sent", err=True)
        raise typer.Exit(ExitCode.REDACTION_FAILED) from None
    if show_payload:
        typer.echo(payload.text)
        typer.echo(
            f"(about {payload.estimated_tokens} tokens; nothing was sent"
            + (f"; trimmed: {', '.join(payload.trimmed)}" if payload.trimmed else "")
            + ")",
            err=True,
        )
        return
    name = provider_name or settings.provider
    if name is ProviderName.NONE:
        typer.echo(OFF_MESSAGE)
        return
    provider, problem = _provider(name, model or settings.model, settings)
    if provider is None:
        provider, reason_first = NoneProvider(), problem
    else:
        reason_first = None
    budget = None
    if provider.sends_data:
        from prohori.enrich.cache import EnrichmentCache
        from prohori.enrich.ratelimit import DailyBudget

        budget = DailyBudget(
            f"llm:{provider.name}", settings.daily_requests, EnrichmentCache(cache_path)
        )
        if settings.tier is Tier.FREE:
            typer.echo(FREE_TIER_NOTICE, err=True)
    result = explain(
        incident,
        provider,
        payload=payload,
        budget=budget,
        max_output_tokens=settings.max_output_tokens,
        restore=not keep_pseudonyms,
    )
    if reason_first is not None:
        result = Explanation(
            text=result.text, source="local", model=None, sent=False, reason=reason_first
        )
    _print(result, incident.id)


def _provider(
    name: ProviderName, model: str, settings: LLMSettings
) -> tuple[Provider | None, str | None]:
    if name is ProviderName.MOCK:
        return MockProvider(), None
    try:
        return GeminiProvider(settings.api_key, model, timeout=settings.timeout), None
    except (MissingExtraError, ProviderError) as exc:
        return None, str(exc)


def _print(result: Explanation, incident_id: str) -> None:
    console = Console(highlight=False, soft_wrap=True)
    if result.source == "local":
        sent = "the request was sent but not answered" if result.sent else "nothing was sent"
        typer.echo(f"Local summary of {incident_id} ({sent}: {result.reason}).", err=True)
    else:
        usage = ""
        if result.input_tokens is not None and result.output_tokens is not None:
            usage = f", {result.input_tokens} tokens in, {result.output_tokens} out"
        typer.echo(
            f"Explanation of {incident_id} by {result.source} ({result.model}{usage}).", err=True
        )
    # Text(), never markup: the answer is untrusted.
    console.print(Text(result.text))
