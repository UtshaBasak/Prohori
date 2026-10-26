"""ATT&CK mapping and recommended actions from runbooks."""

from pathlib import Path

import pytest

from prohori.incidents import extract_actions, load_guidance, map_attack
from prohori.incidents import runbooks as runbooks_module
from prohori.incidents.attack import technique_id
from prohori.incidents.runbooks import runbook_path
from prohori.rules import builtin_rules_dir, load_rule, load_rules
from prohori.rules.attack import ATTACK_VERSION


def test_tags_are_ordered_tactics_then_techniques() -> None:
    mapping = map_attack(
        ["attack.t1110.001", "attack.credential_access", "attack.initial_access", "attack.t1078"]
        * 2
    )
    assert mapping.tags == (
        "attack.initial_access",
        "attack.credential_access",
        "attack.t1078",
        "attack.t1110.001",
    )
    assert mapping.version == ATTACK_VERSION
    assert mapping.unverified == ()


def test_techniques_sit_under_their_tagged_tactics() -> None:
    mapping = map_attack(["attack.credential_access", "attack.t1110", "attack.t1078"])
    # T1078 has four tactics, none tagged: it is listed under all of them.
    names = {t.name: [x.id for x in t.techniques] for t in mapping.tactics}
    assert names["Credential Access"] == ["T1110"]
    assert names["Initial Access"] == ["T1078"]
    assert names["Stealth"] == ["T1078"]
    order = [t.tag for t in mapping.tactics]
    assert order.index("attack.initial_access") < order.index("attack.credential_access")


def test_unverified_tags_are_kept_and_reported() -> None:
    mapping = map_attack(["attack.t9999", "attack.t1110", "attack.made_up", "not-attack"])
    assert mapping.tags == ("attack.t1110", "attack.made_up", "attack.t9999")
    assert mapping.unverified == ("attack.made_up", "attack.t9999")


def test_technique_id() -> None:
    assert technique_id("attack.t1110.003") == "T1110.003"


def test_extract_actions_joins_wrapped_bullets_and_stops_at_next_heading() -> None:
    markdown = (
        "# Title\n\n## Triage\n\n1. Not an action.\n\n## Recommended actions\n\n"
        "- Block the source IP at the firewall, reverse\n  proxy or application.\n"
        "* Reset the password.\n2. Numbered works too.\n\n   \n## False positives\n\n- Nope.\n"
    )
    assert extract_actions(markdown) == (
        "Block the source IP at the firewall, reverse proxy or application.",
        "Reset the password.",
        "Numbered works too.",
    )


def test_extract_actions_without_the_section() -> None:
    assert extract_actions("# Runbook\n\n- something\n") == ()


def test_extract_actions_caps_the_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runbooks_module, "MAX_ACTIONS_PER_RUNBOOK", 2)
    markdown = "## Recommended actions\n" + "".join(f"- a{n}\n" for n in range(5))
    assert extract_actions(markdown) == ("a0", "a1")


def test_every_builtin_rule_has_complete_actions() -> None:
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    guidance = load_guidance(rules)
    assert set(guidance) == {r.id for r in rules}
    for rule in rules:
        actions = guidance[rule.id].actions
        assert actions, rule.id
        for action in actions:
            # A wrapped bullet that was not joined would leave a fragment without a full stop.
            assert action.endswith((".", ")")), (rule.id, action)
            assert "\n" not in action
        assert guidance[rule.id].false_positives == tuple(rule.meta.falsepositives)


def _custom_rule(directory: Path, response: str | None) -> Path:
    path = directory / "custom.yml"
    lines = [
        "id: ACME-AUTH-001",
        "title: Custom rule",
        "status: test",
        "severity: low",
        "detection:",
        "  selection:",
        "    event.action: auth.signin.failure",
        "  condition: selection",
    ]
    if response:
        lines.append(f"response: {response}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_custom_runbooks_are_relative_to_the_rule_file(tmp_path: Path) -> None:
    (tmp_path / "runbooks").mkdir()
    (tmp_path / "runbooks" / "acme.md").write_text(
        "## Recommended actions\n\n- Call the on-call engineer.\n", encoding="utf-8"
    )
    rule = load_rule(_custom_rule(tmp_path, "runbooks/acme.md")).rule
    assert rule is not None
    assert runbook_path(rule) == tmp_path / "runbooks" / "acme.md"
    assert load_guidance([rule])["ACME-AUTH-001"].actions == ("Call the on-call engineer.",)


def test_missing_or_absent_runbooks_give_no_actions(tmp_path: Path) -> None:
    missing = load_rule(_custom_rule(tmp_path, "runbooks/none.md")).rule
    assert missing is not None
    assert load_guidance([missing])["ACME-AUTH-001"].actions == ()
    none = load_rule(_custom_rule(tmp_path, None)).rule
    assert none is not None
    assert runbook_path(none) is None
    assert load_guidance([none])["ACME-AUTH-001"].actions == ()


def test_long_runbooks_are_read_only_up_to_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runbooks_module, "MAX_RUNBOOK_BYTES", 40)
    (tmp_path / "runbooks").mkdir()
    (tmp_path / "runbooks" / "big.md").write_text(
        "## Recommended actions\n- first\n- second action that is cut\n- third\n",
        encoding="utf-8",
    )
    rule = load_rule(_custom_rule(tmp_path, "runbooks/big.md")).rule
    assert rule is not None
    actions = load_guidance([rule])["ACME-AUTH-001"].actions
    assert actions[0] == "first"
    assert "third" not in actions
