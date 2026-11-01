"""Transports: ordering, positions, at-least-once redelivery and malformed lines."""

from pathlib import Path

import pytest

from prohori.pipeline.messages import Topic
from prohori.pipeline.transport import (
    MAX_MESSAGE_BYTES,
    FileTransport,
    MemoryTransport,
    Transport,
    decode,
    encode,
)


@pytest.fixture(params=["memory", "file"])
def transport(request: pytest.FixtureRequest, tmp_path: Path) -> Transport:
    if request.param == "memory":
        return MemoryTransport()
    return FileTransport(tmp_path / "state", fsync=False)


def test_encode_decode_round_trip() -> None:
    line = encode("k1", {"a": 1, "text": "tab\there"})
    assert line.endswith(b"\n")
    record = decode(Topic.EVENTS, 7, line.rstrip(b"\n"))
    assert (record.key, record.value, record.error, record.position) == (
        "k1",
        {"a": 1, "text": "tab\there"},
        None,
        7,
    )


@pytest.mark.parametrize(
    ("line", "error"),
    [
        (b"not json", "not valid JSON"),
        (b"[1, 2]", "not a keyed message"),
        (b'{"key": 1, "value": {}}', "not a keyed message"),
        (b'{"key": "k", "value": "text"}', "not a keyed message"),
        (b"[" * 100_000, "not valid JSON"),
    ],
)
def test_decode_never_raises(line: bytes, error: str) -> None:
    record = decode(Topic.EVENTS, 1, line)
    assert record.value is None
    assert record.error == error
    assert len(record.raw) <= 4096


def test_poll_returns_messages_in_order_in_batches(transport: Transport) -> None:
    for number in range(5):
        transport.publish(Topic.EVENTS, f"k{number}", {"n": number})
    transport.flush()
    first = transport.poll(Topic.EVENTS, "g", 3)
    second = transport.poll(Topic.EVENTS, "g", 3)
    assert [r.value for r in first + second] == [{"n": n} for n in range(5)]
    assert transport.poll(Topic.EVENTS, "g", 3) == []
    # Another group reads independently.
    assert len(transport.poll(Topic.EVENTS, "other", 10)) == 5
    assert transport.poll(Topic.ALERTS, "g", 10) == []
    transport.close()


def test_uncommitted_messages_are_redelivered_after_a_restart(tmp_path: Path) -> None:
    state = tmp_path / "state"
    first = FileTransport(state, fsync=False)
    for number in range(4):
        first.publish(Topic.EVENTS, f"k{number}", {"n": number})
    first.flush()
    batch = first.poll(Topic.EVENTS, "g", 2)
    first.commit(batch[-1], "g")
    first.poll(Topic.EVENTS, "g", 2)  # read but never committed: the process "crashes"
    first.close()

    second = FileTransport(state, fsync=False)
    assert [r.value for r in second.poll(Topic.EVENTS, "g", 10)] == [{"n": 2}, {"n": 3}]
    second.close()


def test_memory_transport_redelivers_from_the_commit_after_rewind() -> None:
    transport = MemoryTransport()
    for number in range(3):
        transport.publish(Topic.ALERTS, "k", {"n": number})
    records = transport.poll(Topic.ALERTS, "g", 10)
    transport.commit(records[0], "g")
    assert transport.committed[("g", Topic.ALERTS)] == 1
    transport.rewind(Topic.ALERTS, "g")
    assert len(transport.poll(Topic.ALERTS, "g", 10)) == 3
    assert transport.size(Topic.ALERTS) == 3


def test_rewind_reads_a_file_topic_from_the_start(tmp_path: Path) -> None:
    transport = FileTransport(tmp_path, fsync=False)
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    transport.flush()
    records = transport.poll(Topic.EVENTS, "g", 10)
    transport.commit(records[-1], "g")
    transport.rewind(Topic.EVENTS, "g")
    assert transport.committed("g", Topic.EVENTS) == 0
    assert len(transport.poll(Topic.EVENTS, "g", 10)) == 1
    transport.close()


def test_unfinished_line_is_not_read_until_complete(tmp_path: Path) -> None:
    transport = FileTransport(tmp_path, fsync=True)
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    transport.append_raw(Topic.EVENTS, b'{"key": "k", "val')
    transport.flush()
    assert [r.value for r in transport.poll(Topic.EVENTS, "g", 10)] == [{"n": 1}]
    transport.append_raw(Topic.EVENTS, b'ue": {"n": 2}}\n')
    transport.flush()
    assert [r.value for r in transport.poll(Topic.EVENTS, "g", 10)] == [{"n": 2}]
    transport.close()


def test_a_crash_mid_write_becomes_one_malformed_message(tmp_path: Path) -> None:
    crashed = FileTransport(tmp_path, fsync=False)
    crashed.append_raw(Topic.EVENTS, b'{"key": "k", "va')  # the process dies here
    crashed.close()
    restarted = FileTransport(tmp_path, fsync=False)
    restarted.publish(Topic.EVENTS, "k2", {"n": 2})
    restarted.flush()
    records = restarted.poll(Topic.EVENTS, "g", 10)
    assert [r.error for r in records] == ["not valid JSON", None]
    assert records[1].value == {"n": 2}
    restarted.close()


def test_oversized_message_is_delivered_as_an_error(tmp_path: Path) -> None:
    transport = FileTransport(tmp_path, fsync=False)
    transport.append_raw(Topic.EVENTS, b"x" * (MAX_MESSAGE_BYTES * 2 + 10) + b"\n")
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    transport.flush()
    records = transport.poll(Topic.EVENTS, "g", 10)
    assert [r.error for r in records] == ["message too large", None]
    transport.close()


def test_corrupt_offset_file_starts_from_the_beginning(tmp_path: Path) -> None:
    transport = FileTransport(tmp_path, fsync=False)
    transport.publish(Topic.EVENTS, "k", {"n": 1})
    transport.flush()
    (tmp_path / "offsets" / "g.events").write_text("garbage", encoding="ascii")
    assert transport.committed("g", Topic.EVENTS) == 0
    assert len(transport.poll(Topic.EVENTS, "g", 10)) == 1
    transport.close()
