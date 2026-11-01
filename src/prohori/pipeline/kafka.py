"""Kafka transport for the Docker stack (Redpanda, or any Kafka-compatible broker).

The same protocol as the lite-mode transports, over a broker:

- A message's key is the Kafka key and its value is the payload as JSON.
- Every topic has one partition, and each consumer group is assigned to it directly (no
  rebalancing). Positions are Kafka offsets, committed synchronously after a batch has been
  processed and its output flushed.
- The producer is idempotent and waits for every replica (``acks=all``); ``flush`` raises if any
  message was not delivered, so a stage never commits input whose output was lost.
- Topics are created with unlimited retention if they do not exist: the stateful stages rebuild
  their state by reading their topics from the start, so nothing may be deleted under them.

The client is ``confluent-kafka`` (librdkafka), part of the ``pipeline`` extra.
"""

import json
import time
from collections.abc import Iterator, Mapping
from types import SimpleNamespace
from typing import Any, Protocol

from prohori.pipeline import MissingExtraError
from prohori.pipeline.messages import MAX_DEAD_LETTER_PAYLOAD, Topic
from prohori.pipeline.transport import Record

#: Settings for the topics Prohori creates.
TOPIC_CONFIG = {"retention.ms": "-1", "retention.bytes": "-1", "cleanup.policy": "delete"}
#: Seconds to wait for the broker when creating topics, flushing or reading offsets.
BROKER_TIMEOUT = 30.0


class _Partition(Protocol):
    offset: int


class _Consumer(Protocol):
    """The ``confluent_kafka.Consumer`` methods the transport calls."""

    def assign(self, partitions: list[object], /) -> None:
        """Read these partitions, from the given offsets or the committed ones."""

    def consume(self, num_messages: int = 1, timeout: float = -1) -> list[Any]:
        """Up to ``num_messages`` messages, waiting at most ``timeout`` seconds."""

    def get_watermark_offsets(
        self, partition: object, timeout: float = -1, cached: bool = False
    ) -> tuple[int, int]:
        """The first and the next offset of a partition."""

    def position(self, partitions: list[object], /) -> list[_Partition]:
        """The offsets the next reads start from."""

    def committed(self, partitions: list[object], timeout: float = -1) -> list[_Partition]:
        """The group's committed offsets."""

    def commit(self, *, offsets: list[object], asynchronous: bool = True) -> object:
        """Commit offsets for the group."""

    def close(self) -> None:
        """Leave and release the connection."""


class TransportError(RuntimeError):
    """The broker could not be reached or refused a request."""


def client() -> SimpleNamespace:
    """The parts of ``confluent_kafka`` the transport uses (tests pass a fake instead)."""
    try:
        import confluent_kafka
        import confluent_kafka.admin
        import confluent_kafka.cimpl
    except ImportError as exc:
        raise MissingExtraError("the Kafka transport") from exc
    return SimpleNamespace(
        Producer=confluent_kafka.Producer,
        Consumer=confluent_kafka.Consumer,
        TopicPartition=confluent_kafka.TopicPartition,
        KafkaError=confluent_kafka.KafkaError,
        KafkaException=confluent_kafka.KafkaException,
        AdminClient=confluent_kafka.admin.AdminClient,
        NewTopic=confluent_kafka.cimpl.NewTopic,
    )


def decode_message(topic: Topic, position: int, key: bytes | None, value: bytes | None) -> Record:
    """Turn a Kafka message into a :class:`Record`, never raising on bad input."""
    text = (value or b"").decode("utf-8", errors="replace")
    key_text = key.decode("utf-8", errors="replace") if key is not None else None
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        return Record(
            topic, position, key_text, None, "not valid JSON", text[:MAX_DEAD_LETTER_PAYLOAD]
        )
    if not isinstance(payload, dict) or key_text is None:
        return Record(
            topic, position, key_text, None, "not a keyed message", text[:MAX_DEAD_LETTER_PAYLOAD]
        )
    return Record(topic, position, key_text, payload)


class KafkaTransport:
    """Topics on a Kafka-compatible broker.

    Args:
        bootstrap: ``host:port`` of the broker, such as ``localhost:19092``.
        timeout: Seconds a poll waits for messages when none are ready.
        create_topics: Create missing topics (with unlimited retention) on start.
        kafka: The client library (see :func:`client`); tests pass a fake.
    """

    def __init__(
        self,
        bootstrap: str,
        *,
        timeout: float = 0.2,
        create_topics: bool = True,
        kafka: SimpleNamespace | None = None,
    ) -> None:
        self.kafka = kafka if kafka is not None else client()
        self.bootstrap = bootstrap
        self.timeout = timeout
        self._errors: list[str] = []
        self._consumers: dict[tuple[str, Topic], _Consumer] = {}
        self.producer = self.kafka.Producer(
            {
                "bootstrap.servers": bootstrap,
                "client.id": "prohori",
                "enable.idempotence": True,
                "acks": "all",
                "linger.ms": 5,
            }
        )
        if create_topics:
            self.ensure_topics()

    # ------------------------------------------------------------------ topics

    def ensure_topics(self) -> None:
        """Create every topic that does not exist yet: one partition, unlimited retention."""
        admin = self.kafka.AdminClient({"bootstrap.servers": self.bootstrap})
        topics = [
            self.kafka.NewTopic(
                t.value, num_partitions=1, replication_factor=1, config=TOPIC_CONFIG
            )
            for t in Topic
        ]
        futures = admin.create_topics(topics, request_timeout=BROKER_TIMEOUT)
        for name, future in futures.items():
            try:
                future.result(timeout=BROKER_TIMEOUT)
            except self.kafka.KafkaException as exc:
                error = exc.args[0] if exc.args else None
                code = error.code() if error is not None and hasattr(error, "code") else None
                if code == self.kafka.KafkaError.TOPIC_ALREADY_EXISTS:
                    continue
                msg = f"cannot create topic {name} on {self.bootstrap}: {exc}"
                raise TransportError(msg) from exc
            except Exception as exc:  # a timeout: the broker is not reachable
                msg = f"cannot reach the Kafka broker at {self.bootstrap}: {exc}"
                raise TransportError(msg) from exc

    # ------------------------------------------------------------------ writing

    def _delivered(self, error: object, message: object) -> None:
        del message
        if error is not None:
            self._errors.append(str(error))

    def publish(self, topic: Topic, key: str, value: Mapping[str, Any]) -> None:
        data = json.dumps(value, separators=(",", ":")).encode()
        while True:
            try:
                self.producer.produce(
                    topic.value, key=key.encode(), value=data, on_delivery=self._delivered
                )
                break
            except BufferError:  # the local queue is full: let it drain
                self.producer.poll(1.0)
        self.producer.poll(0)

    def flush(self) -> None:
        remaining = self.producer.flush(BROKER_TIMEOUT)
        errors, self._errors = self._errors, []
        if remaining:
            msg = f"{remaining} message(s) not delivered to {self.bootstrap} in time"
            raise TransportError(msg)
        if errors:
            msg = f"{len(errors)} message(s) not delivered: {errors[0]}"
            raise TransportError(msg)

    # ------------------------------------------------------------------ reading

    def _partition(self, topic: Topic, offset: int | None = None) -> object:
        if offset is None:
            return self.kafka.TopicPartition(topic.value, 0)
        return self.kafka.TopicPartition(topic.value, 0, offset)

    def _consumer(self, group: str, topic: Topic) -> _Consumer:
        consumer = self._consumers.get((group, topic))
        if consumer is None:
            consumer = self.kafka.Consumer(
                {
                    "bootstrap.servers": self.bootstrap,
                    "group.id": f"prohori-{group}",
                    "client.id": f"prohori-{group}",
                    "enable.auto.commit": False,
                    "auto.offset.reset": "earliest",
                    "enable.partition.eof": False,
                }
            )
            consumer.assign([self._partition(topic)])  # from the committed offset
            self._consumers[(group, topic)] = consumer
        return consumer

    def poll(self, topic: Topic, group: str, max_records: int) -> list[Record]:
        consumer = self._consumer(group, topic)
        records: list[Record] = []
        for message in consumer.consume(num_messages=max_records, timeout=self.timeout):
            error = message.error()
            if error is not None:
                if error.code() == self.kafka.KafkaError.UNKNOWN_TOPIC_OR_PART:
                    continue
                msg = f"cannot read {topic.value}: {error}"
                raise TransportError(msg)
            records.append(
                decode_message(topic, message.offset() + 1, message.key(), message.value())
            )
        return records

    def _end(self, consumer: _Consumer, topic: Topic) -> tuple[int, int]:
        low, high = consumer.get_watermark_offsets(
            self._partition(topic), timeout=BROKER_TIMEOUT, cached=False
        )
        return int(low), int(high)

    def _position(self, consumer: _Consumer, topic: Topic, low: int) -> int:
        (current,) = consumer.position([self._partition(topic)])
        if current.offset >= 0:
            return int(current.offset)
        (committed,) = consumer.committed([self._partition(topic)], timeout=BROKER_TIMEOUT)
        return int(committed.offset) if committed.offset >= 0 else low

    def batches_to_end(self, topic: Topic, group: str, max_records: int) -> Iterator[list[Record]]:
        consumer = self._consumer(group, topic)
        low, high = self._end(consumer, topic)
        deadline = time.monotonic() + BROKER_TIMEOUT
        position = self._position(consumer, topic, low)
        while position < high:
            batch = self.poll(topic, group, max_records)
            if batch:
                position = batch[-1].position
                deadline = time.monotonic() + BROKER_TIMEOUT
                yield batch
            elif time.monotonic() > deadline:
                msg = f"timed out reading {topic.value} up to offset {high}"
                raise TransportError(msg)

    def commit(self, record: Record, group: str) -> None:
        consumer = self._consumer(group, record.topic)
        offset = self._partition(record.topic, record.position)
        consumer.commit(offsets=[offset], asynchronous=False)

    def rewind(self, topic: Topic, group: str) -> None:
        consumer = self._consumer(group, topic)
        low, _ = self._end(consumer, topic)
        consumer.assign([self._partition(topic, low)])
        consumer.commit(offsets=[self._partition(topic, low)], asynchronous=False)

    def close(self) -> None:
        try:
            self.flush()
        finally:
            for consumer in self._consumers.values():
                consumer.close()
            self._consumers.clear()
