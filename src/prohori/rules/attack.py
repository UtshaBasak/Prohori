"""ATT&CK techniques and tactics used by the built-in rules, verified against a pinned release.

Every entry was checked against the official Enterprise ATT&CK STIX bundle named below (id, name,
tactics, and neither revoked nor deprecated). ``scripts/verify_attack.py`` repeats the check; it
needs network access and is run by hand, never by the test suite.
"""

from typing import NamedTuple

ATTACK_VERSION = "20.0"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-20.0.json"
)
ATTACK_STIX_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"


class Technique(NamedTuple):
    """An ATT&CK technique: its name and the tactic tags it belongs to."""

    name: str
    tactics: tuple[str, ...]


#: Tactic tag (``attack.<shortname>`` with ``-`` replaced by ``_``) -> tactic name.
TACTICS: dict[str, str] = {
    "attack.reconnaissance": "Reconnaissance",
    "attack.resource_development": "Resource Development",
    "attack.initial_access": "Initial Access",
    "attack.execution": "Execution",
    "attack.persistence": "Persistence",
    "attack.privilege_escalation": "Privilege Escalation",
    "attack.stealth": "Stealth",
    "attack.defense_impairment": "Defense Impairment",
    "attack.credential_access": "Credential Access",
    "attack.discovery": "Discovery",
    "attack.lateral_movement": "Lateral Movement",
    "attack.collection": "Collection",
    "attack.command_and_control": "Command and Control",
    "attack.exfiltration": "Exfiltration",
    "attack.impact": "Impact",
}

#: Technique tag -> technique. Only techniques that rules use are listed.
TECHNIQUES: dict[str, Technique] = {
    "attack.t1078": Technique(
        "Valid Accounts",
        (
            "attack.stealth",
            "attack.persistence",
            "attack.privilege_escalation",
            "attack.initial_access",
        ),
    ),
    "attack.t1098": Technique(
        "Account Manipulation", ("attack.persistence", "attack.privilege_escalation")
    ),
    "attack.t1110": Technique("Brute Force", ("attack.credential_access",)),
    "attack.t1110.001": Technique("Password Guessing", ("attack.credential_access",)),
    "attack.t1110.003": Technique("Password Spraying", ("attack.credential_access",)),
    "attack.t1110.004": Technique("Credential Stuffing", ("attack.credential_access",)),
    "attack.t1528": Technique("Steal Application Access Token", ("attack.credential_access",)),
    "attack.t1550.001": Technique("Application Access Token", ("attack.lateral_movement",)),
    "attack.t1556.006": Technique(
        "Multi-Factor Authentication",
        ("attack.defense_impairment", "attack.persistence", "attack.credential_access"),
    ),
    "attack.t1595.003": Technique("Wordlist Scanning", ("attack.reconnaissance",)),
}


def is_verified(tag: str) -> bool:
    """Return whether ``tag`` is a verified ATT&CK tactic or technique tag."""
    return tag in TACTICS or tag in TECHNIQUES
