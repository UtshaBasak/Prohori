"""Generated documentation stays in sync with the code."""

from pathlib import Path

from scripts import generate_examples

ROOT = Path(__file__).resolve().parents[2]


def test_example_reports_are_current() -> None:
    assert generate_examples.main(["--check"]) == 0


def test_demo_image_exists_and_is_referenced() -> None:
    image = ROOT / "docs" / "images" / "demo.svg"
    assert image.read_text(encoding="utf-8").startswith("<svg")
    assert "docs/images/demo.svg" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_cli_reference_lists_every_command() -> None:
    from prohori.cli import app

    text = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
    for command in app.registered_commands:
        assert f"`prohori {command.name}" in text, command.name


def test_readme_facts_match_the_code() -> None:
    """README numbers that describe the code, not results, are pinned to the code."""
    from prohori.rules import builtin_rules_dir, load_rules
    from prohori.rules.attack import ATTACK_VERSION
    from prohori.simulate import SCENARIOS

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    assert f"{len(rules)} readable YAML rules" in text
    assert f"Run the {len(rules)} built-in rules" in text
    for rule in rules:
        assert f"| {rule.meta.id} |" in text, rule.meta.id
    assert len(SCENARIOS) == 8
    assert "Eight labelled attack scenarios" in text
    assert f"MITRE ATT&CK v{ATTACK_VERSION}" in text


def test_core_coverage_floor_names_real_packages() -> None:
    """The packages CI holds to the core coverage floor are still there."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    line = next(x for x in workflow.splitlines() if "--include=" in x)
    patterns = line.split("--include=")[1].split()[0].strip("\"'").split(",")
    assert len(patterns) >= 6
    for pattern in patterns:
        assert (ROOT / pattern.removesuffix("/*")).is_dir(), pattern
