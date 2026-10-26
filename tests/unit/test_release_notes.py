"""The release workflow takes its notes from CHANGELOG.md."""

import pytest

from prohori.version import __version__
from scripts import release_notes

CHANGELOG = """# Changelog

## [Unreleased]

## [0.2.0] - 2027-01-01

### Added

- Two.

## [0.1.0] - 2026-10-27

- One.

[Unreleased]: https://example.invalid/compare
[0.2.0]: https://example.invalid/0.2.0
"""


def test_section_stops_at_the_next_heading_or_link_list() -> None:
    assert release_notes.section(CHANGELOG, "0.2.0") == "### Added\n\n- Two.\n"
    assert release_notes.section(CHANGELOG, "0.1.0") == "- One.\n"
    assert release_notes.section(CHANGELOG, "0.3.0") is None
    assert release_notes.section(CHANGELOG, "0.1") is None  # no prefix matches


def test_the_current_version_has_release_notes(capsys: pytest.CaptureFixture[str]) -> None:
    assert release_notes.main([__version__]) == 0
    notes = capsys.readouterr().out
    assert "### Added" in notes
    assert "## [" not in notes


def test_a_missing_version_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert release_notes.main(["99.0.0"]) == 1
    assert "no section for 99.0.0" in capsys.readouterr().err
