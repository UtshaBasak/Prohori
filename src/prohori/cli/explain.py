"""``prohori explain`` and ``prohori ask``: the opt-in LLM analyst, redacted and checked."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from prohori.cli.exit_codes import ExitCode
from prohori.cli.report import _parse, _read, _select
from prohori.enrich.config import ConfigError, EnrichSettings
from prohori.enrich.ratelimit import DailyBudget
from prohori.llm import MissingExtraError
from prohori.llm.explain import Explanation, ask, explain
from prohori.llm.payload import Payload, RedactionError, build_payload
from prohori.llm.provider import (
    GeminiProvider,
    MockProvider,
    NoneProvider,
    Provider,
    ProviderError,
)
from prohori.llm.settings import LLMSettings, ProviderName, Tier
from prohori.schema import Incident

OFF_MESSAGE = (
    "The LLM analyst is off (PROHORI_LLM_PROVIDER=none), so nothing was sent. To use it, set "
    "PROHORI_LLM_PROVIDER=gemini and GEMINI_API_KEY in the environment or .env, or pass "
    "--provider; see docs/LLM_ANALYST.md. 'prohori report' and --show-payload work offline."
)
FREE_TIER_NOTICE = (
    "Note: on the Gemini API free tier, Google may use what is sent to improve its products. "
    "The incident was redacted first; set PROHORI_LLM_TIER=paid once billing is enabled."
)

ProviderOption = Annotated[
    ProviderName | None,
    typer.Option(
        "--provider",
        help="none, mock or gemini (default: PROHORI_LLM_PROVIDER, else none).",
        show_default=False,
    ),
]
ModelOption = Annotated[
    str | None,
    typer.Option(help="Model name (default: PROHORI_LLM_MODEL).", show_default=False),
]
MaskOption = Annotated[
    bool, typer.Option("--mask-ips", help="Also replace IP addresses before sending.")
]
ShowOption = Annotated[
    bool,
    typer.Option(
        "--show-payload", help="Print the incident payload that would be sent, and send nothing."
    ),
]
KeepOption = Annotated[
    bool,
    typer.Option(
        "--keep-pseudonyms",
        help="Show the answer with the pseudonyms instead of the original accounts.",
    ),
]
ToolsOption = Annotated[
    int, typer.Option(min=0, max=5, help="Most read-only tool calls the model may make.")
]
EnvOption = Annotated[
    Path, typer.Option(help="Settings file read under the environment variables.")
]


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
    provider_name: ProviderOption = None,
    model: ModelOption = None,
    mask_ips: MaskOption = False,
    show_payload: ShowOption = False,
    keep_pseudonyms: KeepOption = False,
    max_tool_calls: ToolsOption = 3,
    env_file: EnvOption = Path(".env"),
) -> None:
    """Explain an incident in plain language with an LLM (opt-in; redacted before sending).

    Off by default: with the provider 'none' nothing is sent. Account names, ids and emails are
    replaced with pseudonyms before anything leaves the machine (and IP addresses with
    --mask-ips); event descriptions from the logs are never sent. If the provider cannot answer
    (no key, budget or rate limit reached, timeout), or its answer cites an address, account,
    id or technique that is not in the incident or the sources, a local summary is shown
    instead. Exit codes: 0 explained or summarised (or the analyst is off), 1 redaction could
    not remove every personal value (nothing was sent), 2 invalid usage, input or setting.
    """
    settings, cache_path = _settings(env_file)
    incident = _incident(file, incident_id)
    payload = _payload(incident, mask_ips or settings.mask_ips, settings)
    if show_payload:
        _show(payload)
        return
    session = _session(provider_name or settings.provider, model, settings, cache_path)
    if session is None:
        typer.echo(OFF_MESSAGE)
        return
    provider, problem, budget = session
    result = explain(
        incident,
        provider,
        payload=payload,
        budget=budget,
        max_output_tokens=settings.max_output_tokens,
        max_tool_calls=max_tool_calls,
        restore=not keep_pseudonyms,
    )
    _print(_unavailable(result, problem), f"Explanation of {incident.id}")


def ask_command(
    question: Annotated[str, typer.Argument(metavar="QUESTION", help="Your question, in quotes.")],
    file: Annotated[
        str | None,
        typer.Option(
            "--incident-file",
            "-f",
            metavar="INCIDENT",
            help="Ask about this incident (JSON or JSON Lines; '-' for stdin).",
            show_default=False,
        ),
    ] = None,
    incident_id: Annotated[
        str | None,
        typer.Option("--incident", "-i", help="Which incident when the file has several."),
    ] = None,
    provider_name: ProviderOption = None,
    model: ModelOption = None,
    mask_ips: MaskOption = False,
    show_payload: ShowOption = False,
    keep_pseudonyms: KeepOption = False,
    max_tool_calls: ToolsOption = 3,
    env_file: EnvOption = Path(".env"),
) -> None:
    """Ask a question, answered from ATT&CK and the runbooks (and an incident, if given).

    The best-matching ATT&CK techniques and runbook sections are found locally and given to the
    model as sources; the model may look up more with read-only tools. Off by default: with the
    provider 'none' the matching sources are shown and nothing is sent. Answers that cite an
    address, account, id or technique not in the incident or the sources are rejected. Exit
    codes: 0 answered (or sources shown), 1 redaction could not remove every personal value
    (nothing was sent), 2 invalid usage, input or setting.
    """
    if not question.strip() or len(question) > 2000:
        raise typer.BadParameter("give a question of 1 to 2000 characters", param_hint="QUESTION")
    settings, cache_path = _settings(env_file)
    incident = _incident(file, incident_id) if file is not None else None
    payload = None
    if incident is not None:
        payload = _payload(incident, mask_ips or settings.mask_ips, settings)
    if show_payload:
        if payload is None:
            raise typer.BadParameter("needs --incident-file", param_hint="--show-payload")
        _show(payload)
        return
    session = _session(provider_name or settings.provider, model, settings, cache_path)
    provider, problem, budget = session or (NoneProvider(), "the LLM analyst is off", None)
    result = ask(
        question,
        provider,
        incident=incident,
        payload=payload,
        budget=budget,
        max_output_tokens=settings.max_output_tokens,
        max_tool_calls=max_tool_calls,
        restore=not keep_pseudonyms,
    )
    _print(_unavailable(result, problem), "Answer")


def _settings(env_file: Path) -> tuple[LLMSettings, Path]:
    try:
        settings = LLMSettings.load(env_file=env_file)
        return settings, EnrichSettings.load(env_file=env_file).cache_path
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from None


def _incident(file: str, incident_id: str | None) -> Incident:
    data, _ = _read(file)
    return _select(_parse(data), incident_id)


def _payload(incident: Incident, mask_ips: bool, settings: LLMSettings) -> Payload:
    try:
        return build_payload(
            incident, mask_ips=mask_ips, max_input_tokens=settings.max_input_tokens
        )
    except RedactionError as exc:
        typer.echo(f"error: {exc}; nothing was sent", err=True)
        raise typer.Exit(ExitCode.REDACTION_FAILED) from None


def _show(payload: Payload) -> None:
    typer.echo(payload.text)
    trimmed = f"; trimmed: {', '.join(payload.trimmed)}" if payload.trimmed else ""
    typer.echo(f"(about {payload.estimated_tokens} tokens; nothing was sent{trimmed})", err=True)


def _session(
    name: ProviderName, model: str | None, settings: LLMSettings, cache_path: Path
) -> tuple[Provider, str | None, DailyBudget | None] | None:
    """The provider, why it cannot be used (if so) and the budget; None when the analyst is off."""
    if name is ProviderName.NONE:
        return None
    if name is ProviderName.MOCK:
        return MockProvider(), None, None
    try:
        provider = GeminiProvider(
            settings.api_key, model or settings.model, timeout=settings.timeout
        )
    except (MissingExtraError, ProviderError) as exc:
        return NoneProvider(), str(exc), None
    from prohori.enrich.cache import EnrichmentCache

    budget = DailyBudget(
        f"llm:{provider.name}", settings.daily_requests, EnrichmentCache(cache_path)
    )
    if settings.tier is Tier.FREE:
        typer.echo(FREE_TIER_NOTICE, err=True)
    return provider, None, budget


def _unavailable(result: Explanation, problem: str | None) -> Explanation:
    """Report why the provider could not be used instead of 'the analyst is off'."""
    if problem is None or result.source != "local":
        return result
    return Explanation(
        text=result.text,
        source="local",
        model=None,
        sent=False,
        reason=problem,
        sources=result.sources,
    )


def _print(result: Explanation, what: str) -> None:
    console = Console(highlight=False, soft_wrap=True)
    if result.source == "local":
        if result.rejected:
            sent = "the answer was rejected"
        elif result.sent:
            sent = "the request was sent but not answered"
        else:
            sent = "nothing was sent"
        typer.echo(f"{what}: local, without the model ({sent}: {result.reason}).", err=True)
    else:
        usage = ""
        if result.input_tokens is not None and result.output_tokens is not None:
            usage = f", {result.input_tokens} tokens in, {result.output_tokens} out"
        tools = f", {result.tool_calls} tool call(s)" if result.tool_calls else ""
        typer.echo(f"{what} by {result.source} ({result.model}{usage}{tools}).", err=True)
    # Text(), never markup: the answer is untrusted.
    console.print(Text(result.text))
    if result.sources and result.source != "local":
        console.print(Text("\nSources:"))
        for number, document in enumerate(result.sources, start=1):
            console.print(Text(f"[S{number}] {document.title}"))
