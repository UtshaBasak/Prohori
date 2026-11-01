"""Transports move keyed JSON messages between stages.

A transport keeps one ordered log per topic and one read position per (consumer group, topic).
Consumers read a batch, publish what it produced, :meth:`Transport.flush` and only then
:meth:`Transport.commit`, so delivery is **at least once**: after a crash, the uncommitted batch is
read again. Every writer downstream is idempotent (writes are keyed by content-derived ids), so a
message delivered twice is stored once.

Two implementations exist for lite mode: :class:`MemoryTransport` (one process, nothing on disk,
for tests and one-off replays) and :class:`FileTransport` (JSON Lines on disk, survives restarts).
The Kafka transport in the Docker stack implements the same protocol.
"""

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from prohori.pipeline.messages import MAX_DEAD_LETTER_PAYLOAD, Topic

#: Longest message line the file transport reads; longer lines are delivered as errors.
MAX_MESSAGE_BYTES = 1024 * 1024

JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class Record:
    """One message read from a topic.

    ``position`` is where the next message starts; committing a record commits everything up to
    and including it. A message that is not a JSON object with a string key has ``value`` set to
    ``None``, the reason in ``error`` and the beginning of the raw text in ``raw``.
    """

    topic: Topic
    position: int
    key: str | None
    value: JsonObject | None
    error: str | None = None
    raw: str = ""


class Transport(Protocol):
    """What the stages need from a message transport."""

    def publish(self, topic: Topic, key: str, value: Mapping[str, Any]) -> None:
        """Append one message to ``topic``."""

    def flush(self) -> None:
        """Make every published message durable and visible to readers."""

    def poll(self, topic: Topic, group: str, max_records: int) -> list[Record]:
        """Return up to ``max_records`` messages after the group's read position, advancing it."""

    def batches_to_end(self, topic: Topic, group: str, max_records: int) -> Iterator[list[Record]]:
        """Yield batches of messages up to the end of ``topic`` as it was when called.

        Unlike an empty :meth:`poll`, which may only mean that nothing arrived in time, this
        reaches every message published before the call. Batches are yielded one at a time, so
        a long backlog is never held in memory at once.
        """

    def commit(self, record: Record, group: str) -> None:
        """Record that ``group`` has processed everything up to and including ``record``."""

    def rewind(self, topic: Topic, group: str) -> None:
        """Move the group's read position back to the start of the topic."""

    def close(self) -> None:
        """Release files and other resources."""


def decode(topic: Topic, position: int, line: bytes) -> Record:
    """Turn one stored line into a :class:`Record`, never raising on bad input."""
    raw = line.decode("utf-8", errors="replace")
    try:
        message = json.loads(raw)
    except (ValueError, RecursionError):
        return Record(topic, position, None, None, "not valid JSON", raw[:MAX_DEAD_LETTER_PAYLOAD])
    if (
        not isinstance(message, dict)
        or not isinstance(message.get("key"), str)
        or not isinstance(message.get("value"), dict)
    ):
        return Record(
            topic, position, None, None, "not a keyed message", raw[:MAX_DEAD_LETTER_PAYLOAD]
        )
    return Record(topic, position, message["key"], message["value"])


def drain(
    transport: Transport, topic: Topic, group: str, max_records: int
) -> Iterator[list[Record]]:
    """Poll until nothing is left: enough for transports where an empty poll means the end."""
    while batch := transport.poll(topic, group, max_records):
        yield batch


def encode(key: str, value: Mapping[str, Any]) -> bytes:
    """One stored line: ``{"key": ..., "value": {...}}`` and a newline."""
    return json.dumps({"key": key, "value": value}, separators=(",", ":")).encode() + b"\n"


class MemoryTransport:
    """In-process transport: lists of encoded messages, positions in memory."""

    def __init__(self) -> None:
        self._topics: dict[Topic, list[bytes]] = {topic: [] for topic in Topic}
        self._positions: dict[tuple[str, Topic], int] = {}
        self.committed: dict[tuple[str, Topic], int] = {}

    def publish(self, topic: Topic, key: str, value: Mapping[str, Any]) -> None:
        self._topics[topic].append(encode(key, value))

    def append_raw(self, topic: Topic, line: bytes) -> None:
        """Append a line as stored, valid or not (for tests of malformed messages)."""
        self._topics[topic].append(line)

    def flush(self) -> None:
        """Nothing to do: messages are visible as soon as they are published."""

    def poll(self, topic: Topic, group: str, max_records: int) -> list[Record]:
        start = self._positions.get((group, topic), self.committed.get((group, topic), 0))
        lines = self._topics[topic][start : start + max_records]
        self._positions[(group, topic)] = start + len(lines)
        return [
            decode(topic, start + index + 1, line.rstrip(b"\n")) for index, line in enumerate(lines)
        ]

    def batches_to_end(self, topic: Topic, group: str, max_records: int) -> Iterator[list[Record]]:
        return drain(self, topic, group, max_records)

    def commit(self, record: Record, group: str) -> None:
        self.committed[(group, record.topic)] = record.position

    def rewind(self, topic: Topic, group: str) -> None:
        self._positions[(group, topic)] = 0
        self.committed[(group, topic)] = 0

    def size(self, topic: Topic) -> int:
        """Number of messages in ``topic``."""
        return len(self._topics[topic])

    def close(self) -> None:
        """Nothing to release."""


class FileTransport:
    """Durable lite-mode transport: one JSON Lines file per topic under ``directory``.

    Positions are byte offsets. Committed positions live in ``offsets/<group>.<topic>`` and are
    replaced atomically. A final line without a newline is a write that did not finish: readers
    stop before it, and the next writer ends it with a newline so it becomes one malformed
    message (sent to the dead-letter topic) instead of corrupting the next message.

    Only one process may write to a directory at a time.
    """

    def __init__(self, directory: Path, *, fsync: bool = True) -> None:
        self.directory = directory
        self.fsync = fsync
        (directory / "topics").mkdir(parents=True, exist_ok=True)
        (directory / "offsets").mkdir(parents=True, exist_ok=True)
        self._writers: dict[Topic, BinaryIO] = {}
        self._readers: dict[tuple[str, Topic], BinaryIO] = {}
        self._dirty: set[Topic] = set()

    def topic_path(self, topic: Topic) -> Path:
        return self.directory / "topics" / f"{topic.value}.jsonl"

    def _offset_path(self, group: str, topic: Topic) -> Path:
        return self.directory / "offsets" / f"{group}.{topic.value}"

    # ------------------------------------------------------------------ writing

    def _writer(self, topic: Topic) -> BinaryIO:
        writer = self._writers.get(topic)
        if writer is None:
            path = self.topic_path(topic)
            writer = path.open("ab")
            if writer.tell() > 0:
                with path.open("rb") as check:
                    check.seek(-1, os.SEEK_END)
                    if check.read(1) != b"\n":
                        writer.write(b"\n")  # close a line left unfinished by a crash
            self._writers[topic] = writer
        return writer

    def publish(self, topic: Topic, key: str, value: Mapping[str, Any]) -> None:
        self._writer(topic).write(encode(key, value))
        self._dirty.add(topic)

    def append_raw(self, topic: Topic, line: bytes) -> None:
        """Append bytes as stored, valid or not (for tests of malformed or unfinished lines)."""
        self._writer(topic).write(line)
        self._dirty.add(topic)

    def flush(self) -> None:
        for topic in sorted(self._dirty):
            writer = self._writers[topic]
            writer.flush()
            if self.fsync:
                os.fsync(writer.fileno())
        self._dirty.clear()

    # ------------------------------------------------------------------ reading

    def committed(self, group: str, topic: Topic) -> int:
        try:
            return int(self._offset_path(group, topic).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return 0

    def _reader(self, group: str, topic: Topic) -> BinaryIO | None:
        reader = self._readers.get((group, topic))
        if reader is None:
            path = self.topic_path(topic)
            if not path.exists():
                return None
            reader = path.open("rb")
            reader.seek(self.committed(group, topic))
            self._readers[(group, topic)] = reader
        return reader

    def poll(self, topic: Topic, group: str, max_records: int) -> list[Record]:
        reader = self._reader(group, topic)
        if reader is None:
            return []
        records: list[Record] = []
        while len(records) < max_records:
            start = reader.tell()
            line = reader.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if not line.endswith(b"\n"):
                if len(line) <= MAX_MESSAGE_BYTES:
                    reader.seek(start)  # unfinished write: read it once it is complete
                    break
                while line and not line.endswith(b"\n"):  # skip the rest of an oversized line
                    line = reader.readline(MAX_MESSAGE_BYTES)
                records.append(Record(topic, reader.tell(), None, None, "message too large", ""))
                continue
            records.append(decode(topic, reader.tell(), line.rstrip(b"\n")))
        return records

    def batches_to_end(self, topic: Topic, group: str, max_records: int) -> Iterator[list[Record]]:
        return drain(self, topic, group, max_records)

    def commit(self, record: Record, group: str) -> None:
        self._write_offset(group, record.topic, record.position)

    def rewind(self, topic: Topic, group: str) -> None:
        reader = self._readers.pop((group, topic), None)
        if reader is not None:
            reader.close()
        self._write_offset(group, topic, 0)

    def _write_offset(self, group: str, topic: Topic, position: int) -> None:
        path = self._offset_path(group, topic)
        temp = path.with_name(path.name + ".tmp")
        temp.write_text(str(position), encoding="ascii")
        temp.replace(path)

    def close(self) -> None:
        self.flush()
        for handle in [*self._writers.values(), *self._readers.values()]:
            handle.close()
        self._writers.clear()
        self._readers.clear()
