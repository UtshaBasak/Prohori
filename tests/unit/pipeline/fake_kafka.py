"""An in-memory stand-in for the parts of ``confluent_kafka`` the Kafka transport uses."""

from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

INVALID = -1001


class FakeKafkaError:
    TOPIC_ALREADY_EXISTS = 36
    UNKNOWN_TOPIC_OR_PART = 3
    LEADER_NOT_AVAILABLE = 5

    def __init__(self, code: int, text: str = "") -> None:
        self._code = code
        self.text = text or f"error {code}"

    def code(self) -> int:
        return self._code

    def __str__(self) -> str:
        return self.text


class FakeKafkaException(Exception):  # noqa: N818 - the name confluent_kafka uses
    pass


@dataclass
class FakeTopicPartition:
    topic: str
    partition: int
    offset: int = INVALID


@dataclass
class FakeMessage:
    _offset: int
    _key: bytes | None
    _value: bytes | None
    _error: FakeKafkaError | None = None

    def error(self) -> FakeKafkaError | None:
        return self._error

    def offset(self) -> int:
        return self._offset

    def key(self) -> bytes | None:
        return self._key

    def value(self) -> bytes | None:
        return self._value


@dataclass
class Broker:
    """Topics, committed offsets and switches for failure tests."""

    topics: dict[str, list[tuple[bytes | None, bytes | None]]] = field(default_factory=dict)
    configs: dict[str, dict[str, str]] = field(default_factory=dict)
    committed: dict[tuple[str, str], int] = field(default_factory=dict)
    fail_delivery: bool = False
    unreachable: bool = False
    undelivered: int = 0
    create_error: int | None = None
    leaderless_lookups: int = 0  # list_topics calls that still report no leader
    unknown_watermarks: int = 0  # get_watermark_offsets calls that fail with an unknown topic

    def append(self, topic: str, key: bytes | None, value: bytes | None) -> None:
        self.topics.setdefault(topic, []).append((key, value))


class _Future:
    def __init__(self, error: Exception | None) -> None:
        self.error = error

    def result(self, timeout: float | None = None) -> None:
        del timeout
        if self.error is not None:
            raise self.error


def fake_kafka(broker: Broker) -> SimpleNamespace:
    """A ``confluent_kafka`` look-alike over ``broker``."""

    class NewTopic:
        def __init__(
            self, name: str, num_partitions: int, replication_factor: int, config: dict[str, str]
        ) -> None:
            assert (num_partitions, replication_factor) == (1, 1)
            self.topic = name
            self.config = config

    class AdminClient:
        def __init__(self, config: dict[str, Any]) -> None:
            self.config = config

        def create_topics(
            self, topics: list[NewTopic], request_timeout: float
        ) -> dict[str, _Future]:
            del request_timeout
            futures: dict[str, _Future] = {}
            for topic in topics:
                if broker.unreachable:
                    futures[topic.topic] = _Future(TimeoutError("timed out"))
                elif broker.create_error is not None:
                    error = FakeKafkaError(broker.create_error, "not allowed")
                    futures[topic.topic] = _Future(FakeKafkaException(error))
                elif topic.topic in broker.topics:
                    error = FakeKafkaError(FakeKafkaError.TOPIC_ALREADY_EXISTS)
                    futures[topic.topic] = _Future(FakeKafkaException(error))
                else:
                    broker.topics[topic.topic] = []
                    broker.configs[topic.topic] = topic.config
                    futures[topic.topic] = _Future(None)
            return futures

        def list_topics(self, timeout: float) -> SimpleNamespace:
            del timeout
            leader = -1 if broker.leaderless_lookups > 0 else 1
            broker.leaderless_lookups -= 1
            return SimpleNamespace(
                topics={
                    name: SimpleNamespace(
                        error=None, partitions={0: SimpleNamespace(leader=leader)}
                    )
                    for name in broker.topics
                }
            )

    class Producer:
        def __init__(self, config: dict[str, Any]) -> None:
            assert config["enable.idempotence"] is True
            self.pending: list[tuple[Callable[..., None], FakeKafkaError | None]] = []
            self.full_once = False

        def produce(
            self, topic: str, key: bytes, value: bytes, on_delivery: Callable[..., None]
        ) -> None:
            if self.full_once:
                self.full_once = False
                raise BufferError
            error = FakeKafkaError(1, "broker down") if broker.fail_delivery else None
            if error is None:
                broker.append(topic, key, value)
            self.pending.append((on_delivery, error))

        def poll(self, timeout: float = 0) -> int:
            del timeout
            pending, self.pending = self.pending, []
            for callback, error in pending:
                callback(error, None)
            return len(pending)

        def flush(self, timeout: float = -1) -> int:
            self.poll(timeout)
            return broker.undelivered

    class Consumer:
        def __init__(self, config: dict[str, Any]) -> None:
            assert config["enable.auto.commit"] is False
            self.group = str(config["group.id"])
            self.position_: dict[str, int] = {}
            self.assigned = ""
            self.closed = False

        def assign(self, partitions: list[FakeTopicPartition]) -> None:
            self.assigned = partitions[0].topic
            for partition in partitions:
                if partition.offset >= 0:
                    self.position_[partition.topic] = partition.offset
                else:
                    self.position_.pop(partition.topic, None)

        def _start(self, topic: str) -> int:
            if topic in self.position_:
                return self.position_[topic]
            return broker.committed.get((self.group, topic), 0)

        def consume(self, num_messages: int = 1, timeout: float = -1) -> list[FakeMessage]:
            del timeout
            topic = self.assigned
            if topic not in broker.topics:
                return [FakeMessage(0, None, None, FakeKafkaError(3, "unknown topic"))]
            start = self._start(topic)
            items = broker.topics[topic][start : start + num_messages]
            self.position_[topic] = start + len(items)
            return [FakeMessage(start + i, k, v) for i, (k, v) in enumerate(items)]

        def get_watermark_offsets(
            self, partition: FakeTopicPartition, timeout: float = -1, cached: bool = False
        ) -> tuple[int, int]:
            del timeout, cached
            if broker.unknown_watermarks > 0:
                broker.unknown_watermarks -= 1
                error = FakeKafkaError(FakeKafkaError.UNKNOWN_TOPIC_OR_PART)
                raise FakeKafkaException(error)
            return 0, len(broker.topics.get(partition.topic, []))

        def position(self, partitions: list[FakeTopicPartition]) -> list[FakeTopicPartition]:
            return [
                FakeTopicPartition(p.topic, 0, self.position_.get(p.topic, INVALID))
                for p in partitions
            ]

        def committed(
            self, partitions: list[FakeTopicPartition], timeout: float = -1
        ) -> list[FakeTopicPartition]:
            del timeout
            return [
                FakeTopicPartition(p.topic, 0, broker.committed.get((self.group, p.topic), INVALID))
                for p in partitions
            ]

        def commit(self, *, offsets: list[FakeTopicPartition], asynchronous: bool = True) -> None:
            assert asynchronous is False
            for partition in offsets:
                broker.committed[(self.group, partition.topic)] = partition.offset

        def close(self) -> None:
            self.closed = True

    return SimpleNamespace(
        Producer=Producer,
        Consumer=Consumer,
        TopicPartition=FakeTopicPartition,
        KafkaError=FakeKafkaError,
        KafkaException=FakeKafkaException,
        AdminClient=AdminClient,
        NewTopic=NewTopic,
    )
