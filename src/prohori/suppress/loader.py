# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Read a suppressions file safely and report every problem with its line.

The file is one YAML mapping with ``suppressions`` (alert suppressions) and ``allow_ips``
(addresses known to be benign), read with the rule-file limits: size, safe YAML only, no
aliases, bounded nesting (:func:`prohori.rules.loader.read_yaml_file`). ``docs/RULES.md``
describes the format.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from prohori.rules.loader import LocatedError, RuleLoadError, locate, read_yaml_file
from prohori.rules.matching import RuleError
from prohori.suppress.entries import (
    ANY_RULE,
    MAX_ENTRIES,
    AllowIpDocument,
    Entry,
    EntryDocument,
    compile_allow,
    compile_entry,
)


class _File(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    suppressions: Annotated[list[object], Field(max_length=MAX_ENTRIES)] = []
    allow_ips: Annotated[list[object], Field(max_length=MAX_ENTRIES)] = []


def utc_today() -> date:
    """Today in UTC: what the "expired" warnings compare with (never what applies an entry)."""
    return datetime.now(UTC).date()


class SuppressionFileError(ValueError):
    """The file cannot be used; ``errors`` says where and why."""

    def __init__(self, file: Path, errors: list[LocatedError]) -> None:
        super().__init__(f"{file}: {len(errors)} problem(s)")
        self.file = file
        self.errors = errors


@dataclass(frozen=True)
class Suppressions:
    """The entries of one file, suppressions first, in file order."""

    entries: tuple[Entry, ...]
    file: Path | None = None

    def __bool__(self) -> bool:
        return bool(self.entries)

    def expired(self, today: date | None = None) -> list[Entry]:
        """Entries past their ``expires`` day (UTC): they no longer apply to new alerts."""
        day = today or utc_today()
        return [e for e in self.entries if e.expired(day)]

    def unknown_rules(self, detector_ids: Iterable[str]) -> list[tuple[Entry, str]]:
        """Rules named by an entry that are not loaded (a typo would silence nothing)."""
        known = set(detector_ids)
        return [
            (entry, rule)
            for entry in self.entries
            for rule in entry.rules
            if rule != ANY_RULE and rule not in known
        ]

    def warnings(self, detector_ids: Iterable[str], today: date | None = None) -> list[str]:
        """Plain-text warnings for a run: expired entries and rules that are not loaded."""
        notes = [
            f"suppression {e.id!r} expired on {e.expires.isoformat()} (owner: {e.owner}); it "
            "no longer applies to new alerts: review it, then renew or delete it"
            for e in self.expired(today)
        ]
        notes += [
            f"suppression {entry.id!r} names rule {rule!r}, which is not loaded; it silences "
            "nothing for that rule"
            for entry, rule in self.unknown_rules(detector_ids)
        ]
        return notes

    def allowed_ip(self, address: str, when: datetime) -> Entry | None:
        """The ``allow_ips`` entry in force at ``when`` that lists ``address``, if any."""
        return next(
            (e for e in self.entries if e.allows_ips and e.in_force(when) and e.allows_ip(address)),
            None,
        )


NO_SUPPRESSIONS = Suppressions(())


def _pydantic(exc: ValidationError, prefix: tuple[str | int, ...]) -> list[RuleError]:
    return [
        RuleError((*prefix, *error["loc"]), error["msg"].removeprefix("Value error, "))
        for error in exc.errors()
    ]


def parse_suppressions(document: object) -> tuple[tuple[Entry, ...], list[RuleError]]:
    """Validate and compile a parsed suppressions document."""
    if not isinstance(document, Mapping):
        return (), [RuleError((), "a suppressions file must be a YAML mapping")]
    try:
        top = _File.model_validate(document)
    except ValidationError as exc:
        return (), _pydantic(exc, ())
    if not top.suppressions and not top.allow_ips:
        return (), [RuleError((), "add at least one entry under suppressions or allow_ips")]
    errors: list[RuleError] = []
    entries: list[Entry] = []
    for index, raw in enumerate(top.suppressions):
        path = ("suppressions", index)
        try:
            entry_doc = EntryDocument.model_validate(raw)
        except ValidationError as exc:
            errors.extend(_pydantic(exc, path))
            continue
        entry = compile_entry(entry_doc, path, errors)
        if entry is not None:
            entries.append(entry)
    for index, raw in enumerate(top.allow_ips):
        try:
            entries.append(compile_allow(AllowIpDocument.model_validate(raw)))
        except ValidationError as exc:
            errors.extend(_pydantic(exc, ("allow_ips", index)))
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            errors.append(RuleError((), f"duplicate entry id {entry.id!r}"))
        seen.add(entry.id)
    return tuple(entries), errors


def load_suppressions(file: Path) -> Suppressions:
    """Read, validate and compile a suppressions file.

    Raises:
        SuppressionFileError: if the file cannot be read or has any problem (nothing applies
            then: a half-loaded file would silence some alerts and not others).
    """
    try:
        document, lines = read_yaml_file(file)
    except RuleLoadError as exc:
        raise SuppressionFileError(file, [LocatedError(exc.line, "", str(exc))]) from None
    entries, errors = parse_suppressions(document)
    if errors:
        raise SuppressionFileError(file, [locate(e, lines) for e in errors])
    return Suppressions(entries, file)
