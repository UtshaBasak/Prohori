# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
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
from collections.abc import Callable, Iterator, Mapping
from types import SimpleNamespace
from typing import Any, Protocol, TypeVar

from prohori.pipeline import MissingExtraError
from prohori.pipeline.messages import MAX_DEAD_LETTER_PAYLOAD, Topic, dead_letter
from prohori.pipeline.transport import Record

#: Settings for the topics Prohori creates.
TOPIC_CONFIG = {"retention.ms": "-1", "retention.bytes": "-1", "cleanup.policy": "delete"}
#: Seconds to wait for the broker when creating topics, flushing or reading offsets.
BROKER_TIMEOUT = 30.0
#: Broker errors that only mean a topic or a consumer group is still settling, as it does just
#: after the broker starts or another stage creates a topic: the topic is not known yet, its
#: partition has no leader yet, or the group has no coordinator yet. They are retried until
#: :data:`BROKER_TIMEOUT` and only then reported.
SETTLING_ERRORS = (
    "UNKNOWN_TOPIC_OR_PART",
    "LEADER_NOT_AVAILABLE",
    "NOT_LEADER_FOR_PARTITION",
    "COORDINATOR_LOAD_IN_PROGRESS",
    "COORDINATOR_NOT_AVAILABLE",
    "NOT_COORDINATOR",
)

#: Errors about one message, not the broker: the message is too large or malformed. It becomes a
#: dead letter instead of failing the batch, which would be delivered again and fail again.
REJECTED_ERRORS = ("MSG_SIZE_TOO_LARGE", "RECORD_LIST_TOO_LARGE", "INVALID_RECORD", "INVALID_MSG")
#: The ``stage`` of a dead letter for a message the Kafka client or broker refused.
REJECTED_BY = "kafka-producer"

_T = TypeVar("_T")


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


def _has_leader(metadata: Any) -> bool:  # noqa: ANN401 - confluent_kafka metadata
    """Whether topic metadata from ``list_topics`` shows the topic ready to use."""
    if metadata is None or metadata.error is not None or not metadata.partitions:
        return False
    return all(p.leader >= 0 for p in metadata.partitions.values())


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


def security_config(credentials: tuple[str, str] | None) -> dict[str, str]:
    """librdkafka settings for a SASL/SCRAM-SHA-256 login; empty without credentials."""
    if credentials is None:
        return {}
    user, password = credentials
    return {
        "security.protocol": "SASL_PLAINTEXT",
        "sasl.mechanisms": "SCRAM-SHA-256",
        "sasl.username": user,
        "sasl.password": password,
    }


class KafkaTransport:
    """Topics on a Kafka-compatible broker.

    Args:
        bootstrap: ``host:port`` of the broker, such as ``localhost:19092``.
        timeout: Seconds a poll waits for messages when none are ready.
        create_topics: Create missing topics (with unlimited retention) on start.
        kafka: The client library (see :func:`client`); tests pass a fake.
        credentials: SASL/SCRAM-SHA-256 user and password, for a broker that requires a login
            (the Docker stack since 1.1); ``None`` connects without SASL.
    """

    def __init__(
        self,
        bootstrap: str,
        *,
        timeout: float = 0.2,
        create_topics: bool = True,
        kafka: SimpleNamespace | None = None,
        credentials: tuple[str, str] | None = None,
    ) -> None:
        self.kafka = kafka if kafka is not None else client()
        self.bootstrap = bootstrap
        self._security = security_config(credentials)
        self.timeout = timeout
        self._errors: list[str] = []
        self._consumers: dict[tuple[str, Topic], _Consumer] = {}
        self._settling = frozenset(
            getattr(self.kafka.KafkaError, name)
            for name in SETTLING_ERRORS
            if hasattr(self.kafka.KafkaError, name)
        )
        self._settling_since: dict[tuple[str, Topic], float] = {}
        self._rejecting = frozenset(
            getattr(self.kafka.KafkaError, name)
            for name in REJECTED_ERRORS
            if hasattr(self.kafka.KafkaError, name)
        )
        self._rejected: list[tuple[str, bytes | None, bytes | None, str]] = []
        self.producer = self.kafka.Producer(
            {
                **self._security,
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
        """Create every topic that does not exist yet: one partition, unlimited retention.

        Returns once every topic has a leader: a topic another stage has only just created can
        still be unknown to the broker that answers the next request.
        """
        admin = self.kafka.AdminClient({**self._security, "bootstrap.servers": self.bootstrap})
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
                hint = (
                    " (if it requires a login, set PROHORI_KAFKA_USER and PROHORI_KAFKA_PASSWORD)"
                    if not self._security
                    else " (or it refused the login)"
                )
                msg = f"cannot reach the Kafka broker at {self.bootstrap}{hint}: {exc}"
                raise TransportError(msg) from exc
        self._await_topics(admin, [t.value for t in Topic])

    def _await_topics(self, admin: Any, names: list[str]) -> None:  # noqa: ANN401 - AdminClient
        deadline = time.monotonic() + BROKER_TIMEOUT
        while True:
            topics = admin.list_topics(timeout=BROKER_TIMEOUT).topics
            waiting = [name for name in names if not _has_leader(topics.get(name))]
            if not waiting:
                return
            if time.monotonic() >= deadline:
                msg = f"topics {', '.join(waiting)} have no leader on {self.bootstrap}"
                raise TransportError(msg)
            time.sleep(0.2)

    # ------------------------------------------------------------------ writing

    def _is_rejection(self, error: Any, topic: str) -> bool:  # noqa: ANN401 - a KafkaError
        """Whether ``error`` is about this one message (and the message is not a dead letter)."""
        code = error.code() if hasattr(error, "code") else None
        fatal = bool(error.fatal()) if hasattr(error, "fatal") else False
        return code in self._rejecting and not fatal and topic != Topic.DEAD_LETTER.value

    def _delivered(self, error: Any, message: Any) -> None:  # noqa: ANN401 - confluent_kafka
        if error is None:
            return
        if message is not None and self._is_rejection(error, message.topic()):
            self._rejected.append((message.topic(), message.key(), message.value(), str(error)))
        else:
            self._errors.append(str(error))

    def publish(self, topic: Topic, key: str, value: Mapping[str, Any]) -> None:
        data = json.dumps(value, separators=(",", ":")).encode()
        self._produce(topic.value, key.encode(), data)

    def _produce(self, topic: str, key: bytes, data: bytes) -> None:
        while True:
            try:
                self.producer.produce(topic, key=key, value=data, on_delivery=self._delivered)
                break
            except BufferError:  # the local queue is full: let it drain
                self.producer.poll(1.0)
            except self.kafka.KafkaException as exc:
                error = exc.args[0] if exc.args else None
                if error is None or not self._is_rejection(error, topic):
                    raise
                self._rejected.append((topic, key, data, str(error)))
                break
        self.producer.poll(0)

    def _dead_letter_rejected(self) -> None:
        """Publish a dead letter for every message the client or the broker refused."""
        rejected, self._rejected = self._rejected, []
        for topic, key, data, reason in rejected:
            text = (data or b"").decode("utf-8", errors="replace")
            key_text = key.decode("utf-8", errors="replace") if key is not None else None
            letter = dead_letter(REJECTED_BY, topic, key_text, f"refused: {reason}", text)
            payload = json.dumps(letter.model_dump(mode="json"), separators=(",", ":")).encode()
            self._produce(Topic.DEAD_LETTER.value, letter.id.encode(), payload)

    def flush(self) -> None:
        """Wait until every message is delivered. A message refused for its own sake (too large,
        malformed) is replaced by a dead letter, delivered before this returns; any other failure
        raises, so the input is not committed and is read again."""
        while True:
            remaining = self.producer.flush(BROKER_TIMEOUT)
            errors, self._errors = self._errors, []
            if remaining:
                msg = f"{remaining} message(s) not delivered to {self.bootstrap} in time"
                raise TransportError(msg)
            if errors:
                msg = f"{len(errors)} message(s) not delivered: {errors[0]}"
                raise TransportError(msg)
            if not self._rejected:
                return
            self._dead_letter_rejected()

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
                    **self._security,
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
        settling = False
        for message in consumer.consume(num_messages=max_records, timeout=self.timeout):
            error = message.error()
            if error is not None:
                if error.code() in self._settling and not self._settling_too_long(group, topic):
                    settling = True
                    continue  # read as empty until the topic or the group has settled
                msg = f"cannot read {topic.value}: {error}"
                raise TransportError(msg)
            records.append(
                decode_message(topic, message.offset() + 1, message.key(), message.value())
            )
        if settling:
            # A consumer whose first fetch of the group's committed offset failed (for example
            # "Not coordinator" just after the broker started) may never fetch it again and then
            # reads nothing, silently. Start a fresh one; it reads from the committed offset, and
            # every record returned before has been committed by the stage, or is returned now.
            self._consumers.pop((group, topic)).close()
        else:  # settled, even if nothing was there to read
            self._settling_since.pop((group, topic), None)
        return records

    def _settling_too_long(self, group: str, topic: Topic) -> bool:
        """Whether reads of ``topic`` for ``group`` have met only settling errors for longer than
        the broker timeout."""
        since = self._settling_since.setdefault((group, topic), time.monotonic())
        return time.monotonic() - since > BROKER_TIMEOUT

    def _retry(self, call: Callable[[], _T], what: str) -> _T:
        """``call()``, retried while the broker answers with a settling error, until the broker
        timeout. Any other error is raised at once."""
        deadline = time.monotonic() + BROKER_TIMEOUT
        while True:
            try:
                return call()
            except self.kafka.KafkaException as exc:
                error = exc.args[0] if exc.args else None
                code = error.code() if error is not None and hasattr(error, "code") else None
                if code not in self._settling:
                    raise
                if time.monotonic() >= deadline:
                    msg = f"{what} did not settle on the broker at {self.bootstrap}: {error}"
                    raise TransportError(msg) from exc
                time.sleep(0.5)

    def _end(self, consumer: _Consumer, topic: Topic) -> tuple[int, int]:
        """The topic's first and next offsets.

        A consumer that has just been created can find the topic unknown, or its partition
        without a leader, for a moment after the broker started or another stage created it.
        """
        low, high = self._retry(
            lambda: consumer.get_watermark_offsets(
                self._partition(topic), timeout=BROKER_TIMEOUT, cached=False
            ),
            f"topic {topic.value}",
        )
        return int(low), int(high)

    def _position(self, consumer: _Consumer, topic: Topic, low: int) -> int:
        (current,) = consumer.position([self._partition(topic)])
        if current.offset >= 0:
            return int(current.offset)
        (committed,) = self._retry(
            lambda: consumer.committed([self._partition(topic)], timeout=BROKER_TIMEOUT),
            f"the committed offset of {topic.value}",
        )
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
        self._retry(
            lambda: consumer.commit(offsets=[offset], asynchronous=False),
            f"a commit to {record.topic.value}",
        )

    def rewind(self, topic: Topic, group: str) -> None:
        consumer = self._consumer(group, topic)
        low, _ = self._end(consumer, topic)
        consumer.assign([self._partition(topic, low)])
        start = self._partition(topic, low)
        self._retry(
            lambda: consumer.commit(offsets=[start], asynchronous=False),
            f"rewinding {topic.value}",
        )

    def close(self) -> None:
        try:
            self.flush()
        finally:
            for consumer in self._consumers.values():
                consumer.close()
            self._consumers.clear()
