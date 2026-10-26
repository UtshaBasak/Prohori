"""Map an incident's rule tags onto ATT&CK tactics and techniques.

Tags come from the rules that fired. Built-in rules only use tags verified against the pinned
ATT&CK release (:mod:`prohori.rules.attack`); custom rules may use others, which are kept but
reported as unverified.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from prohori.rules.attack import ATTACK_VERSION, TACTICS, TECHNIQUES

_TACTIC_ORDER = {tag: index for index, tag in enumerate(TACTICS)}


@dataclass(frozen=True)
class TechniqueRef:
    """A technique as shown in a report: ``T1110.001 Password Guessing``."""

    tag: str
    id: str
    name: str


@dataclass(frozen=True)
class TacticRef:
    """A tactic and the incident's techniques under it."""

    tag: str
    name: str
    techniques: tuple[TechniqueRef, ...]


@dataclass(frozen=True)
class AttackMapping:
    """The ATT&CK view of an incident."""

    tags: tuple[str, ...]  # tactics in ATT&CK order, then techniques, then unverified tags
    tactics: tuple[TacticRef, ...]
    unverified: tuple[str, ...]
    version: str = ATTACK_VERSION


def technique_id(tag: str) -> str:
    """``attack.t1110.001`` -> ``T1110.001``."""
    return tag.removeprefix("attack.").upper()


def map_attack(tags: Iterable[str]) -> AttackMapping:
    """Order and group ATT&CK tags.

    A technique is listed under each of its tactics that the incident is tagged with; when none
    is, under all of its tactics, so no technique is left out.
    """
    unique = {tag for tag in tags if tag.startswith("attack.")}
    tactics = sorted((t for t in unique if t in TACTICS), key=_TACTIC_ORDER.__getitem__)
    techniques = sorted(t for t in unique if t in TECHNIQUES)
    unverified = sorted(unique - set(tactics) - set(techniques))
    under: dict[str, list[TechniqueRef]] = {}
    for tag in techniques:
        technique = TECHNIQUES[tag]
        ref = TechniqueRef(tag, technique_id(tag), technique.name)
        homes = [t for t in technique.tactics if t in tactics] or list(technique.tactics)
        for tactic in homes:
            under.setdefault(tactic, []).append(ref)
    shown = sorted(set(tactics) | set(under), key=_TACTIC_ORDER.__getitem__)
    return AttackMapping(
        tags=(*tactics, *techniques, *unverified),
        tactics=tuple(TacticRef(t, TACTICS[t], tuple(under.get(t, ()))) for t in shown),
        unverified=tuple(unverified),
    )
