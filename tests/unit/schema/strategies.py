"""Hypothesis strategies that generate valid schema objects."""

from datetime import UTC, datetime, timedelta, timezone

from hypothesis import strategies as st

from prohori.schema import (
    Event,
    EventCategory,
    EventInfo,
    HttpInfo,
    Outcome,
    Severity,
    SourceInfo,
    UserInfo,
)

# Text that survives a JSON round trip unchanged (no lone surrogates).
text = st.text(st.characters(exclude_categories=["Cs"]), max_size=300)
short_text = st.text(st.characters(exclude_categories=["Cs"]), max_size=40)

timezones = st.builds(
    timezone, st.integers(min_value=-14 * 60, max_value=14 * 60).map(lambda m: timedelta(minutes=m))
)
aware_datetimes = st.datetimes(
    min_value=datetime(1990, 1, 2),  # noqa: DTZ001 - bounds for hypothesis, tz added below
    max_value=datetime(2100, 1, 1),  # noqa: DTZ001
    timezones=st.one_of(st.just(UTC), timezones),
)

actions = st.from_regex(r"[a-z0-9_]{1,10}(\.[a-z0-9_]{1,10}){0,3}", fullmatch=True)
ips = st.one_of(st.none(), st.ip_addresses())

event_infos = st.builds(
    EventInfo,
    action=actions,
    category=st.sampled_from(EventCategory),
    outcome=st.sampled_from(Outcome),
    severity=st.one_of(st.none(), st.sampled_from(Severity)),
    reason=st.one_of(st.none(), short_text),
)

http_infos = st.builds(
    HttpInfo,
    method=st.one_of(st.none(), st.sampled_from(["GET", "POST", "put", "DELETE"])),
    path=st.one_of(st.none(), text),
    status=st.one_of(st.none(), st.integers(100, 599)),
    bytes=st.one_of(st.none(), st.integers(0, 2**40)),
)

user_infos = st.builds(
    UserInfo,
    name=st.one_of(st.none(), short_text),
    id=st.one_of(st.none(), short_text),
    email_hash=st.one_of(st.none(), st.text("0123456789abcdef", min_size=64, max_size=64)),
)

extra_values = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**53), 2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    short_text,
)

events = st.builds(
    Event,
    timestamp=aware_datetimes,
    log_source=st.sampled_from(["sshd", "nginx", "apache", "app-security", "generic"]),
    event=event_infos,
    source=st.builds(SourceInfo, ip=ips),
    user=user_infos,
    http=http_infos,
    user_agent=st.one_of(st.none(), text),
    client=st.one_of(st.none(), short_text),
    host=st.one_of(st.none(), short_text),
    request_id=st.one_of(st.none(), short_text),
    raw=text,
    extra=st.dictionaries(short_text, extra_values, max_size=5),
)
