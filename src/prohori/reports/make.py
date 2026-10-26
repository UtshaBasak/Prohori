"""Produce a finished report: optional redaction, the leak check and rendering in one call."""

import os

from prohori.reports.redact import Redactor, find_leaks, incident_strings
from prohori.reports.render import RedactionNote, ReportFormat, ReportSource, render
from prohori.schema import Incident


class RedactionError(ValueError):
    """Redaction left personal values in the report; nothing should be written."""

    def __init__(self, count: int) -> None:
        super().__init__(f"{count} value(s) could not be redacted")
        self.count = count


def make_report(
    incident: Incident,
    fmt: ReportFormat,
    *,
    source: ReportSource | None = None,
    redact: bool = False,
    redact_ips: bool = False,
    key: bytes | None = None,
) -> str:
    """Render ``incident``; with ``redact`` or ``redact_ips``, redact it first and fail closed.

    ``key`` is the redaction key (a fresh random one when omitted).

    Raises:
        RedactionError: if an original value would remain in the report.
    """
    if not (redact or redact_ips):
        return render(incident, fmt, source=source)
    redactor = Redactor(key if key is not None else os.urandom(32), ips=redact_ips)
    redacted = redactor.redact(incident)
    note = RedactionNote(users=True, ips=redact_ips, replaced=len(redactor.replaced))
    text = render(redacted, fmt, source=source, redaction=note)
    # Every value a report shows comes from these strings. Checking them, rather than the
    # rendered output, avoids matching Prohori's own words (JSON keys, the CSS ":root", "from"
    # in the summary) against an attacker-chosen account name such as "root".
    leaks = find_leaks("\n".join(incident_strings(redacted)), redactor.replaced)
    if leaks:
        raise RedactionError(len(leaks))
    return text
