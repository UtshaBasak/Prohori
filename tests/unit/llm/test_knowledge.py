"""The retrieval corpus, BM25 and the answer validator."""

import json
from importlib.resources import files
from pathlib import Path

import pytest

from prohori.llm.guard import Allowed, techniques, validate
from prohori.llm.knowledge import (
    Document,
    Index,
    attack_documents,
    default_index,
    for_incident,
    runbook_documents,
    tokens,
)
from prohori.rules.attack import ATTACK_VERSION, TECHNIQUES
from scripts.build_attack_corpus import shorten


def test_the_attack_corpus_matches_the_pinned_release() -> None:
    lines = (files("prohori.llm") / "data" / "attack.jsonl").read_text("utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["attack_version"] == ATTACK_VERSION
    assert "The MITRE Corporation" in header["notice"]
    documents = attack_documents()
    assert len(documents) == header["techniques"] > 600
    by_id = {d.id: d for d in documents}
    for tag, entry in TECHNIQUES.items():  # every technique the rules use is present
        technique = tag.removeprefix("attack.").upper()
        assert technique in by_id, technique
        assert entry.name in by_id[technique].title
    assert all(len(d.text) <= 601 for d in documents)
    assert not any("(Citation:" in d.text for d in documents)


def test_runbooks_are_split_into_sections(tmp_path: Path) -> None:
    documents = runbook_documents()
    ids = {d.id for d in documents}
    assert "runbook:brute-force#recommended-actions" in ids
    assert not any(d.id.endswith("#att-ck") for d in documents)
    (tmp_path / "x.md").write_text("# X\n\n## Empty\n\n## Steps\n- do it\n### deeper\n", "utf-8")
    (tmp_path / "README.md").write_text("# ignored\n## A\ntext\n", "utf-8")
    assert [d.id for d in runbook_documents(tmp_path)] == ["runbook:x#steps"]


def test_bm25_ranks_and_named_techniques_come_first() -> None:
    index = Index(
        [
            Document("a", "attack", "Password spraying", "one password many accounts"),
            Document("b", "attack", "Brute force", "many passwords one account"),
            Document("T1110", "attack", "T1110 Brute Force", "guessing"),
        ]
    )
    assert [d.id for d in index.search("spraying one password")][:1] == ["a"]
    assert index.search("unrelated words") == []
    assert index.search("what about t1110 and spraying")[0].id == "T1110"
    assert index.get("nope") is None
    assert tokens("The T1110.003 and SQL") == ["t1110.003", "sql"]
    real = default_index()
    assert real.search("password spraying many accounts", k=1)[0].id in {
        "T1110.003",
        "runbook:password-spraying#what-it-means",
    }
    found = for_incident(real, ["T1078", "T9999"], ["brute-force", "missing"])
    assert [d.id for d in found] == ["T1078", "runbook:brute-force#recommended-actions"]


def test_shortening_descriptions() -> None:
    text = "First [link](https://x) <code>cmd</code>.(Citation: A) More.\n\nSecond paragraph."
    assert shorten(text) == "First link cmd. More."
    long = ("Sentence one is here. " * 40).strip()
    assert shorten(long).endswith(".")
    assert len(shorten(long)) <= 600
    assert shorten("x" * 700).endswith("…")


def test_validator_catches_each_kind() -> None:
    allowed = Allowed()
    allowed.add_text(
        "203.0.113.7 2001:db8::1 a@b.example [user:0123456789] INC-abcdef12 PRH-AUTH-001 T1110"
    )
    assert validate(
        "From 203.0.113.7 and 2001:db8::1, a@b.example, [user:0123456789], INC-abcdef12, "
        "PRH-AUTH-001, T1110; https://attack.mitre.org/techniques/T1110/",
        allowed,
    ).ok
    verdict = validate(
        "From 198.51.100.9, 2001:db8::99, x@y.example, [ip:0123456789], INC-ffffffff00, "
        "PRH-WEB-999, T1059.001, https://evil.example/a, "
        "https://attack.mitre.org/techniques/T1566/",
        allowed,
    )
    assert set(verdict.unknown) == {
        "links",
        "IP addresses",
        "email addresses",
        "pseudonyms",
        "incident ids",
        "rule ids",
        "ATT&CK techniques",
    }
    assert "T1566" in verdict.unknown["ATT&CK techniques"]
    assert "links https://evil.example/a" in verdict.describe()
    assert techniques("attack.t1110.001 and T1078.") == {"T1110.001", "T1078"}
    assert validate("Version 1.2.3.4.5 and 999.1.1.1 are not addresses.", Allowed()).ok


@pytest.mark.parametrize(
    "answer",
    [
        "Block 2001:db8::dead:beef now.",  # compressed IPv6
        "Block fe80::1 and ::1.",
        "Block 198[.]51[.]100[.]9.",  # defanged
        "Block 198.051.100.009.",  # leading zeros, read as octal by some tools
        "Block １９８.51.100.9.",  # noqa: RUF001 - full-width digits
        "Block 198。51。100。9.",  # ideographic full stops
        r"See https://evil.example\@attack.mitre.org/techniques/T1110/",  # backslash host trick
        "See //evil.example/x",
        "See ![x](//evil.example/p.png?q=1)",
        "See [docs](javascript:alert(1))",
        "See ftp://evil.example/x",
        "See hxxp://evil.example/x",
        "See http://attack.mitre.org/techniques/T1110/",  # not https
        "Rule prh-auth-999 fired.",
        "Rule PRH-ML-FAKE fired.",
        "Mail josé@example.com.",
    ],
)
def test_validator_sees_through_disguised_values(answer: str) -> None:
    allowed = Allowed()
    allowed.add_text("203.0.113.7 PRH-AUTH-001 PRH-ML-ZSCORE T1110")
    assert not validate(answer, allowed).ok, answer


def test_validator_accepts_allowed_values_in_other_forms() -> None:
    allowed = Allowed()
    allowed.add_text("2001:db8::1 PRH-ML-ZSCORE PRH-AUTH-001 T1110")
    answer = (
        "2001:0db8:0000:0000:0000:0000:0000:0001, prh-ml-zscore and PRH-AUTH-001; "
        "[T1110](https://attack.mitre.org/techniques/T1110/), [above](#summary)"
    )
    assert validate(answer, allowed).ok
