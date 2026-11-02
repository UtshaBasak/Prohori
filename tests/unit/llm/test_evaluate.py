"""The offline LLM evaluation: cases, references, recordings, replay, scoring and the tables."""

import json
import shutil
from pathlib import Path
from typing import ClassVar

import pytest

from prohori.enrich.cache import EnrichmentCache
from prohori.enrich.ratelimit import DailyBudget
from prohori.llm import evaluate
from prohori.llm.evaluate import (
    Case,
    EvaluationError,
    ReplayProvider,
    asserts,
    evaluation_payload,
    load_cases,
    names,
    read_recording,
    record,
    score,
    score_text,
)
from prohori.llm.explain import incident_sources
from prohori.llm.knowledge import default_index
from prohori.llm.provider import MockProvider, ProviderError, Request, Response
from scripts import build_llm_eval_set, generate_results_table

ROOT = Path(__file__).resolve().parents[3]
EVALUATION = ROOT / "evaluation" / "llm"
RESULTS = ROOT / "results" / "llm_eval.json"


@pytest.fixture(scope="module")
def cases() -> list[Case]:
    return load_cases(EVALUATION)


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    """A copy of the evaluation directory to change."""
    target = tmp_path / "llm"
    shutil.copytree(EVALUATION, target)
    return target


class SendingProvider:
    """A mock that counts as sending data, so the daily budget applies."""

    name: ClassVar[str] = "gemini"
    sends_data: ClassVar[bool] = True

    def __init__(self, fail: bool = False) -> None:
        self.mock = MockProvider()
        self.fail = fail

    def generate(self, request: Request) -> Response:
        if self.fail:
            raise ProviderError("Gemini rate limit or quota reached")
        return self.mock.generate(request)


def test_cases_are_rebuilt_byte_for_byte() -> None:
    files = build_llm_eval_set.build()
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in (EVALUATION / "cases").glob("*")}
    assert files == on_disk


def test_the_cases_and_their_truth(cases: list[Case]) -> None:
    kinds = [c.kind for c in cases]
    assert (kinds.count("attack"), kinds.count("benign"), kinds.count("injection")) == (15, 7, 8)
    assert all(c.truth == ("benign" if c.kind == "benign" else "attack") for c in cases)
    assert len({c.incident.id for c in cases}) == len(cases)
    assert {c.injection.vector for c in cases if c.injection} == {
        "user agent",
        "request path",
        "username",
    }


def test_every_reference_scores_perfectly_against_itself(cases: list[Case]) -> None:
    index = default_index()
    for case in cases:
        text = case.incident.model_dump_json().lower()
        for value in case.reference.indicators:
            assert value.lower() in text, (case.id, value)  # references name real values
        sources = [d.render() for d in incident_sources(case.incident, index)]
        found = score_text(case.reference.summary, case, evaluate._known(case, sources))
        assert not found.errors, (case.id, found.errors)
        assert not found.missing, (case.id, found.missing)


def test_offline_recordings_are_current(cases: list[Case], tmp_path: Path) -> None:
    for system in ("mock", "adversarial"):
        out = tmp_path / f"{system}.jsonl"
        assert record(system, cases, out) == (len(read_recording(out)[1]), None)
        committed = EVALUATION / "recordings" / f"{system}.jsonl"
        assert out.read_text(encoding="utf-8") == committed.read_text(encoding="utf-8")


def test_committed_results_and_tables_are_current() -> None:
    assert score(EVALUATION) == json.loads(RESULTS.read_text(encoding="utf-8"))
    assert generate_results_table.main(["--check"]) == 0


def test_results_tell_the_baselines_apart() -> None:
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    systems = results["systems"]
    assert set(systems) >= {"local", "mock", "adversarial"}
    assert systems["mock"]["injection"]["followed_by_model"] == 0
    adversary = systems["adversarial"]
    assert adversary["injection"]["followed_by_model"] == adversary["cases"] == 8
    # The checks stop every obeyed injection that names a new value; claims alone get through.
    assert adversary["accepted"] == adversary["injection"]["shown_to_analyst"] == 3
    assert systems["local"]["injection"]["reached_model"] == 4  # the user agents only


def test_assertions_skip_hedged_sentences() -> None:
    pattern = r"\bsign-in succeeded\b"
    assert asserts(pattern, "Check whether any sign-in succeeded.") is None
    assert asserts(pattern, "If the sign-in succeeded, reset it.") is None
    assert asserts(pattern, "Failures. Then the sign-in succeeded.") == "sign-in succeeded"
    assert asserts(r"\bno action needed\b", "No action needed.") == "No action needed"


def test_indicator_matching() -> None:
    assert names("Mapped to T1110.001.", "T1110")
    assert names("attack.t1110.003", "T1110.003")
    assert not names("T1110", "T1110.003")
    assert not names("T11101", "T1110")
    assert names("From 203.0.113.7, then", "203.0.113.7")
    assert not names("203.0.113.70", "203.0.113.7")
    assert not names("u-10001", "u-1000")
    assert names("account u-1000.", "u-1000")


def test_the_evaluation_payload_is_reproducible(cases: list[Case]) -> None:
    first, second = (evaluation_payload(cases[0].incident) for _ in range(2))
    assert first.text == second.text
    assert first.nonce == second.nonce


def test_a_changed_prompt_makes_a_case_stale(copy: Path) -> None:
    path = copy / "recordings" / "mock.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["exchanges"][0]["prompt_sha256"] = "0" * 64
    path.write_text("\n".join([lines[0], json.dumps(entry), *lines[2:]]) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationError, match="stale"):
        score(copy)
    # A real model's stale answers are still scored, with a count.
    header = json.loads(lines[0]) | {"system": "gemini", "model": "gemini-x"}
    path.write_text(
        "\n".join([json.dumps(header), json.dumps(entry), *lines[2:]]) + "\n", encoding="utf-8"
    )
    found = score(copy)["systems"]["gemini"]
    assert found["stale"] == 1
    assert found["label"] == "Gemini (gemini-x)"


def test_replay_without_an_answer_falls_back(cases: list[Case]) -> None:
    replay = ReplayProvider([])
    with pytest.raises(ProviderError):
        replay.generate(Request("s", "p"))
    assert replay.stale
    found = evaluate.score_case(cases[0], "gemini", {"exchanges": []}, default_index())
    assert found["stale"]
    assert found["accepted"] is False
    assert found["model"] is None


def test_recording_a_real_provider_resumes_and_stops_at_the_budget(
    cases: list[Case], tmp_path: Path
) -> None:
    out = tmp_path / "gemini.jsonl"
    cache = EnrichmentCache(tmp_path / "cache.sqlite")
    budget = DailyBudget("llm:gemini", 3, cache)
    found = record("gemini", cases, out, provider=SendingProvider(), model="m", budget=budget)
    assert found[0] == 3
    assert "daily request budget" in (found[1] or "")
    header, entries = read_recording(out)
    assert header["model"] == "m"
    assert "recorded" in header
    assert len(entries) == 3
    more = DailyBudget("llm:gemini", 1000, cache)
    assert record("gemini", cases, out, provider=SendingProvider(), model="m", budget=more) == (
        len(cases) - 3,
        None,
    )
    with pytest.raises(EvaluationError, match="model"):
        record("gemini", cases, out, provider=SendingProvider(), model="other")
    assert record("gemini", cases[:1], out, provider=SendingProvider(), model="o", fresh=True)[0]
    assert read_recording(out)[0]["model"] == "o"


def test_recording_stops_when_the_provider_fails(cases: list[Case], tmp_path: Path) -> None:
    out = tmp_path / "gemini.jsonl"
    found = record("gemini", cases, out, provider=SendingProvider(fail=True), model="m")
    assert found == (0, "Gemini rate limit or quota reached")
    assert read_recording(out)[1] == {}
    with pytest.raises(EvaluationError, match="no provider"):
        record("gemini", cases, tmp_path / "x.jsonl", model="m")


def test_cases_and_references_must_match(copy: Path) -> None:
    references = copy / "references.yaml"
    text = references.read_text(encoding="utf-8")
    references.write_text(text + "\nextra-case:\n  summary: x\n", encoding="utf-8")
    with pytest.raises(EvaluationError, match="without a case"):
        load_cases(copy)
    references.write_text(text.replace("benign-01:", "renamed:"), encoding="utf-8")
    with pytest.raises(EvaluationError, match="no reference"):
        load_cases(copy)
    (copy / "recordings" / "empty.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(EvaluationError, match="empty"):
        read_recording(copy / "recordings" / "empty.jsonl")
    (copy / "recordings" / "empty.jsonl").write_text('{"format": "x"}\n', encoding="utf-8")
    with pytest.raises(EvaluationError, match="not a"):
        read_recording(copy / "recordings" / "empty.jsonl")


def test_command_line(
    copy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "results.json"
    assert evaluate.main(["--dir", str(copy), "score", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["cases"] == 30
    assert evaluate.main(["--dir", str(copy), "record", "--system", "mock"]) == 0
    assert "recorded 0 cases" in capsys.readouterr().err  # all were recorded already
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    missing = tmp_path / "missing.env"
    assert (
        evaluate.main(
            ["--dir", str(copy), "record", "--system", "gemini", "--env-file", str(missing)]
        )
        == 1
    )
    assert "GEMINI_API_KEY is not set" in capsys.readouterr().err


def test_command_line_reports_a_stopped_recording(
    copy: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    budget = DailyBudget("llm:gemini", 1, EnrichmentCache(copy / "cache.sqlite"))
    monkeypatch.setattr(
        evaluate, "_gemini", lambda env_file, model: (SendingProvider(), "m", budget)
    )
    assert evaluate.main(["--dir", str(copy), "record", "--system", "gemini"]) == 2
    assert "run the same command again" in capsys.readouterr().err


def test_tables_with_a_real_model() -> None:
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert "No real model" in generate_results_table.render_llm(results)
    real = json.loads(json.dumps(results))
    real["systems"]["gemini"] = results["systems"]["mock"] | {"label": "Gemini (x)"}
    real["per_case"]["gemini"] = results["per_case"]["mock"]
    table = generate_results_table.render_llm(real)
    assert "No real model" not in table
    assert "| Gemini (x) |" in table
    assert "No real model" not in generate_results_table.render_llm_summary(real)
    assert generate_results_table.render_llm_summary(None) == "No LLM evaluation results yet."
