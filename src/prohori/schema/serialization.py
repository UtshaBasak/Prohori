"""JSON and JSON Lines helpers for schema models."""

from collections.abc import Iterable, Iterator
from typing import IO, TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)


def to_json(model: BaseModel, *, indent: int | None = None) -> str:
    """Serialise a model to JSON, omitting nothing (unset optional fields become ``null``)."""
    return model.model_dump_json(indent=indent)


def from_json(cls: type[M], data: str | bytes) -> M:
    """Parse and validate JSON into ``cls``."""
    return cls.model_validate_json(data)


def write_jsonl(models: Iterable[BaseModel], stream: IO[str]) -> int:
    """Write one JSON document per line to ``stream``. Returns the number of lines written."""
    count = 0
    for model in models:
        stream.write(model.model_dump_json())
        stream.write("\n")
        count += 1
    return count


def read_jsonl(cls: type[M], stream: Iterable[str]) -> Iterator[M]:
    """Lazily parse JSON Lines into ``cls``. Blank lines are skipped; invalid lines raise."""
    for line in stream:
        if line.strip():
            yield cls.model_validate_json(line)
