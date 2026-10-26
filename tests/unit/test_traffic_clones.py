"""The all-time clone count behind the README badge."""

import json
from pathlib import Path

import pytest

from scripts import traffic_clones


def _response(*days: tuple[str, int, int]) -> dict[str, object]:
    return {
        "count": sum(d[1] for d in days),
        "uniques": sum(d[2] for d in days),
        "clones": [
            {"timestamp": f"{day}T00:00:00Z", "count": count, "uniques": uniques}
            for day, count, uniques in days
        ],
    }


def test_days_are_kept_after_they_leave_the_window() -> None:
    first = traffic_clones.merge({}, _response(("2026-10-01", 5, 2), ("2026-10-02", 3, 1)))
    assert first["total"] == 8
    # Two weeks later 2026-10-01 is gone from GitHub's answer; 10-02 is updated.
    second = traffic_clones.merge(first, _response(("2026-10-02", 4, 2), ("2026-10-16", 7, 3)))
    assert second["days"] == {
        "2026-10-01": {"count": 5, "uniques": 2},
        "2026-10-02": {"count": 4, "uniques": 2},
        "2026-10-16": {"count": 7, "uniques": 3},
    }
    assert second["total"] == 16
    assert second["since"] == "2026-10-01"


def test_empty_history_and_bad_response() -> None:
    assert traffic_clones.merge({}, {"clones": []}) == {"days": {}, "total": 0, "since": None}
    with pytest.raises(ValueError, match="not a traffic/clones response"):
        traffic_clones.merge({}, {"message": "Must have push access to repository"})


def test_badge_uses_thousands_separators() -> None:
    assert traffic_clones.badge(12345) == {
        "schemaVersion": 1,
        "label": "clones",
        "message": "12,345",
        "color": "blue",
    }


def test_main_writes_record_and_badge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    response = tmp_path / "clones.json"
    response.write_text(json.dumps(_response(("2026-10-27", 9, 4))), encoding="utf-8")
    data = tmp_path / "data"
    assert traffic_clones.main([str(response), str(data)]) == 0
    assert json.loads((data / "clones.json").read_text(encoding="utf-8"))["total"] == 9
    badge = json.loads((data / "clones-badge.json").read_text(encoding="utf-8"))
    assert badge["message"] == "9"
    assert "9 clones since 2026-10-27" in capsys.readouterr().out
    # A second run with the same answer changes nothing.
    before = (data / "clones.json").read_bytes()
    assert traffic_clones.main([str(response), str(data)]) == 0
    assert (data / "clones.json").read_bytes() == before


def test_main_rejects_bad_input(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"message": "Bad credentials"}', encoding="utf-8")
    assert traffic_clones.main([str(bad), str(tmp_path / "d")]) == 1
    assert not (tmp_path / "d" / "clones.json").exists()
    assert traffic_clones.main(["only-one"]) == 2
