# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""ATT&CK techniques and tactics used by the built-in rules, verified against a pinned release.

Every entry was checked against the official Enterprise ATT&CK STIX bundle named below (id, name,
tactics, and neither revoked nor deprecated). ``scripts/verify_attack.py`` repeats the check; it
needs network access and is run by hand, never by the test suite.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation.
"""

from typing import NamedTuple

ATTACK_VERSION = "20.0"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "20664a889568dce884a1dac0ec7b12ae3a199f51/enterprise-attack/enterprise-attack-20.0.json"
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
    "attack.t1003": Technique("OS Credential Dumping", ("attack.credential_access",)),
    "attack.t1003.001": Technique("LSASS Memory", ("attack.credential_access",)),
    "attack.t1027.010": Technique("Command Obfuscation", ("attack.stealth",)),
    "attack.t1046": Technique("Network Service Discovery", ("attack.discovery",)),
    "attack.t1048": Technique("Exfiltration Over Alternative Protocol", ("attack.exfiltration",)),
    "attack.t1059": Technique("Command and Scripting Interpreter", ("attack.execution",)),
    "attack.t1059.001": Technique("PowerShell", ("attack.execution",)),
    "attack.t1071": Technique("Application Layer Protocol", ("attack.command_and_control",)),
    "attack.t1078": Technique(
        "Valid Accounts",
        (
            "attack.stealth",
            "attack.persistence",
            "attack.privilege_escalation",
            "attack.initial_access",
        ),
    ),
    "attack.t1078.004": Technique(
        "Cloud Accounts",
        (
            "attack.stealth",
            "attack.persistence",
            "attack.privilege_escalation",
            "attack.initial_access",
        ),
    ),
    "attack.t1087.004": Technique("Cloud Account", ("attack.discovery",)),
    "attack.t1098": Technique(
        "Account Manipulation", ("attack.persistence", "attack.privilege_escalation")
    ),
    "attack.t1098.001": Technique(
        "Additional Cloud Credentials", ("attack.persistence", "attack.privilege_escalation")
    ),
    "attack.t1098.007": Technique(
        "Additional Local or Domain Groups", ("attack.persistence", "attack.privilege_escalation")
    ),
    "attack.t1110": Technique("Brute Force", ("attack.credential_access",)),
    "attack.t1110.001": Technique("Password Guessing", ("attack.credential_access",)),
    "attack.t1110.003": Technique("Password Spraying", ("attack.credential_access",)),
    "attack.t1110.004": Technique("Credential Stuffing", ("attack.credential_access",)),
    "attack.t1190": Technique("Exploit Public-Facing Application", ("attack.initial_access",)),
    "attack.t1204.002": Technique("Malicious File", ("attack.execution",)),
    "attack.t1499.002": Technique("Service Exhaustion Flood", ("attack.impact",)),
    "attack.t1528": Technique("Steal Application Access Token", ("attack.credential_access",)),
    "attack.t1543.003": Technique(
        "Windows Service", ("attack.persistence", "attack.privilege_escalation")
    ),
    "attack.t1550.001": Technique("Application Access Token", ("attack.lateral_movement",)),
    "attack.t1556.006": Technique(
        "Multi-Factor Authentication",
        ("attack.defense_impairment", "attack.persistence", "attack.credential_access"),
    ),
    "attack.t1566.001": Technique("Spearphishing Attachment", ("attack.initial_access",)),
    "attack.t1580": Technique("Cloud Infrastructure Discovery", ("attack.discovery",)),
    "attack.t1595": Technique("Active Scanning", ("attack.reconnaissance",)),
    "attack.t1595.002": Technique("Vulnerability Scanning", ("attack.reconnaissance",)),
    "attack.t1595.003": Technique("Wordlist Scanning", ("attack.reconnaissance",)),
    "attack.t1685": Technique("Disable or Modify Tools", ("attack.defense_impairment",)),
    "attack.t1685.002": Technique("Disable or Modify Cloud Log", ("attack.defense_impairment",)),
    "attack.t1685.005": Technique("Clear Windows Event Logs", ("attack.defense_impairment",)),
    "attack.t1686": Technique("Disable or Modify System Firewall", ("attack.defense_impairment",)),
    "attack.t1686.001": Technique("Cloud Firewall", ("attack.defense_impairment",)),
}


def is_verified(tag: str) -> bool:
    """Return whether ``tag`` is a verified ATT&CK tactic or technique tag."""
    return tag in TACTICS or tag in TECHNIQUES
