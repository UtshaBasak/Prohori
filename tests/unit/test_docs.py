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
