"""What the analyst can look things up in: ATT&CK techniques and Prohori's runbooks, with BM25.

The ATT&CK corpus (``data/attack.jsonl``) is built from the pinned Enterprise ATT&CK release by
``scripts/build_attack_corpus.py``: id, name, tactics and a shortened description of every active
technique. Runbooks are split into one document per section. :class:`Index` ranks documents with
Okapi BM25 (k1 = 1.5, b = 0.75); a query that names a technique id finds that technique first.

ATT&CK: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission
of The MITRE Corporation.
"""

import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from pathlib import Path

from prohori.incidents.runbooks import MAX_RUNBOOK_BYTES

_TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]{3})?")
_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*$", re.MULTILINE)
_STOP = frozenset(
    "a an and are as at be by can for from has have how i if in into is it its may of on or "  # noqa: SIM905
    "that the their this to was what when which who why will with you your does do should".split()
)
K1, B = 1.5, 0.75


@dataclass(frozen=True)
class Document:
    id: str  # "T1110.003" or "runbook:brute-force#recommended-actions"
    kind: str  # "attack" or "runbook"
    title: str
    text: str

    def render(self) -> str:
        return f"{self.title}\n{self.text}"


def tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]


def attack_documents() -> list[Document]:
    lines = (files("prohori.llm") / "data" / "attack.jsonl").read_text(encoding="utf-8")
    documents = []
    for line in lines.splitlines()[1:]:  # the first line is the notice
        entry = json.loads(line)
        tactics = ", ".join(t.removeprefix("attack.").replace("_", " ") for t in entry["tactics"])
        documents.append(
            Document(
                id=entry["id"],
                kind="attack",
                title=f"{entry['id']} {entry['name']} (ATT&CK; tactics: {tactics})",
                text=entry["description"],
            )
        )
    return documents


def runbook_documents(directory: Path | None = None) -> list[Document]:
    """One document per ``##`` section of every runbook (the built-in ones by default)."""
    folder = directory or Path(str(files("prohori"))) / "runbooks"
    documents = []
    for path in sorted(folder.glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        text = path.read_bytes()[:MAX_RUNBOOK_BYTES].decode("utf-8", errors="replace")
        headings = list(_HEADING.finditer(text))
        title = headings[0].group(2) if headings else path.stem
        for index, heading in enumerate(headings):
            if len(heading.group(1)) != 2 or heading.group(2).strip() == "ATT&CK":
                continue  # "##" sections only; the technique list duplicates the ATT&CK corpus
            end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
            body = " ".join(text[heading.end() : end].split())
            if not body:
                continue
            section = re.sub(r"[^a-z0-9]+", "-", heading.group(2).lower()).strip("-")
            documents.append(
                Document(
                    id=f"runbook:{path.stem}#{section}",
                    kind="runbook",
                    title=f"Runbook: {title}, {heading.group(2)}",
                    text=body[:1500],
                )
            )
    return documents


class Index:
    """Okapi BM25 over a fixed set of documents."""

    def __init__(self, documents: Sequence[Document]) -> None:
        self.documents = list(documents)
        self._by_id = {d.id: d for d in self.documents}
        self._terms = [Counter(tokens(d.render())) for d in self.documents]
        self._lengths = [sum(t.values()) for t in self._terms]
        self._average = sum(self._lengths) / max(len(self._lengths), 1)
        frequency: Counter[str] = Counter()
        for terms in self._terms:
            frequency.update(terms.keys())
        n = len(self.documents)
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in frequency.items()}

    def get(self, document_id: str) -> Document | None:
        return self._by_id.get(document_id)

    def search(self, query: str, k: int = 5) -> list[Document]:
        """The ``k`` best documents for ``query``; named technique ids come first."""
        wanted = [t.upper() for t in re.findall(r"\b[Tt]\d{4}(?:\.\d{3})?\b", query)]
        exact = [self._by_id[t] for t in dict.fromkeys(wanted) if t in self._by_id]
        terms = tokens(query)
        scores = []
        for position, counts in enumerate(self._terms):
            score = 0.0
            length = self._lengths[position]
            for term in terms:
                tf = counts.get(term, 0)
                if tf:
                    norm = tf + K1 * (1 - B + B * length / self._average)
                    score += self._idf[term] * tf * (K1 + 1) / norm
            if score > 0:
                scores.append((score, position))
        ranked = [self.documents[p] for _, p in sorted(scores, key=lambda s: (-s[0], s[1]))]
        return list(dict.fromkeys([*exact, *ranked]))[:k]


@cache
def default_index() -> Index:
    """ATT&CK techniques and the built-in runbooks (built once per process)."""
    return Index([*attack_documents(), *runbook_documents()])


def for_incident(
    index: Index, technique_ids: Iterable[str], rule_runbooks: Iterable[str]
) -> list[Document]:
    """The incident's own techniques and the recommended actions of its rules' runbooks."""
    found = [index.get(t) for t in technique_ids]
    found += [index.get(f"runbook:{r}#recommended-actions") for r in rule_runbooks]
    return list(dict.fromkeys(d for d in found if d is not None))
