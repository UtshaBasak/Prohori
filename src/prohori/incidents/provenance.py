"""Record how incidents were produced: tool version, input hashes and the rules that fired."""

import hashlib
from collections.abc import Iterable, Sequence
from pathlib import Path

from prohori.rules import CompiledRule
from prohori.schema import Incident, InputFile, Provenance, RuleRef
from prohori.version import __version__


def file_sha256(path: Path) -> str | None:
    """SHA-256 of a file, or None if it cannot be read."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def rule_refs(rules: Iterable[CompiledRule]) -> dict[str, RuleRef]:
    """A reference (id, title, file hash) for each rule, keyed by rule id."""
    refs: dict[str, RuleRef] = {}
    for rule in rules:
        sha = file_sha256(Path(rule.source)) if rule.source else None
        refs[rule.id] = RuleRef(id=rule.id, title=rule.meta.title, sha256=sha)
    return refs


def with_provenance(
    incidents: Sequence[Incident],
    *,
    inputs: Sequence[InputFile],
    rules: Iterable[CompiledRule],
    enrichment: str,
) -> list[Incident]:
    """Attach a :class:`Provenance` to each incident, listing only the rules that fired in it."""
    refs = rule_refs(rules)
    result = []
    for incident in incidents:
        fired = sorted({a.detector_id for a in incident.alerts})
        provenance = Provenance(
            tool_version=__version__,
            inputs=tuple(inputs),
            rules=tuple(refs.get(r, RuleRef(id=r, title=r)) for r in fired),
            enrichment=enrichment,
        )
        result.append(incident.model_copy(update={"provenance": provenance}))
    return result
