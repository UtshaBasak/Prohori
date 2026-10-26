"""``prohori report``: render an incident as Markdown, HTML, JSON or CSV."""

import hashlib
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from prohori.cli.exit_codes import ExitCode
from prohori.parsers import sanitize
from prohori.reports import RedactionError, ReportFormat, ReportSource, make_report
from prohori.schema import Incident

#: Largest incident file read, in bytes.
MAX_INPUT_BYTES = 32 * 1024 * 1024


def report_command(
    file: Annotated[
        str,
        typer.Argument(
            metavar="INCIDENT",
            help="Incident JSON, or JSON Lines from 'prohori incidents -f json'; '-' for stdin.",
        ),
    ],
    output_format: Annotated[
        ReportFormat,
        typer.Option("--format", "-f", help="md, html (one self-contained file), json or csv."),
    ] = ReportFormat.MARKDOWN,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to this file (default: stdout)."),
    ] = None,
    incident_id: Annotated[
        str | None,
        typer.Option(
            "--incident", "-i", help="Which incident to render when the file has several."
        ),
    ] = None,
    redact: Annotated[
        bool,
        typer.Option(
            "--redact", help="Replace account names, ids and emails with keyed pseudonyms."
        ),
    ] = False,
    redact_ips: Annotated[
        bool, typer.Option("--redact-ips", help="Also replace IP addresses (implies --redact).")
    ] = False,
) -> None:
    """Render an incident report: summary, timeline, indicators, ATT&CK, score and actions.

    Exit codes: 0 written, 1 redaction could not remove every personal value (nothing is
    written), 2 invalid usage or input.
    """
    data, name = _read(file)
    incident = _select(_parse(data), incident_id)
    source = ReportSource(name=name, sha256=hashlib.sha256(data).hexdigest())
    try:
        text = make_report(
            incident, output_format, source=source, redact=redact, redact_ips=redact_ips
        )
    except RedactionError as exc:
        typer.echo(f"error: {exc}; no report was written", err=True)
        raise typer.Exit(ExitCode.REDACTION_FAILED) from None
    payload = text.encode("utf-8")
    if output is None:
        # Bytes, not text: the console code page could not encode every character.
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    else:
        output.write_bytes(payload)
        typer.echo(f"wrote {output} ({output_format.value}, {incident.id})", err=True)


def _read(file: str) -> tuple[bytes, str]:
    if file == "-":
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        name = "<stdin>"
    else:
        path = Path(file)
        if not path.is_file():
            raise typer.BadParameter(f"file not found: {file}", param_hint="INCIDENT")
        with path.open("rb") as handle:
            data = handle.read(MAX_INPUT_BYTES + 1)
        name = path.name
    if len(data) > MAX_INPUT_BYTES:
        raise typer.BadParameter(
            f"file is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MiB", param_hint="INCIDENT"
        )
    return data, name


def _parse(data: bytes) -> list[Incident]:
    text = data.decode("utf-8", errors="replace").lstrip("﻿")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:  # JSON Lines: one incident per line
        lines = [line for line in text.splitlines() if line.strip()]
    except RecursionError:
        raise typer.BadParameter("the JSON is nested too deeply", param_hint="INCIDENT") from None
    else:
        items = document if isinstance(document, list) else [document]
        lines = [json.dumps(item) for item in items]
    incidents: list[Incident] = []
    for number, line in enumerate(lines, start=1):
        try:
            incidents.append(Incident.model_validate_json(line))
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"]) or "document"
            message = sanitize(f"incident {number}: {where}: {first['msg']}")[:300]
            raise typer.BadParameter(message, param_hint="INCIDENT") from None
    if not incidents:
        raise typer.BadParameter("no incident in the file", param_hint="INCIDENT")
    return incidents


def _select(incidents: list[Incident], incident_id: str | None) -> Incident:
    if incident_id is not None:
        for incident in incidents:
            if incident.id == incident_id:
                return incident
        raise typer.BadParameter(
            f"no incident {sanitize(incident_id)[:80]!r} in the file", param_hint="--incident"
        )
    if len(incidents) > 1:
        ids = ", ".join(i.id for i in incidents[:20])
        raise typer.BadParameter(
            f"the file has {len(incidents)} incidents; choose one with --incident ({ids})",
            param_hint="--incident",
        )
    return incidents[0]
