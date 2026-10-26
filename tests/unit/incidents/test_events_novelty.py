"""The bounded event memory and the per-account sign-in history."""

import pytest
from tests.unit.incidents.factories import at, event

from prohori.incidents import EventContext, EventSummary, NoveltyStatus, SignInHistory
from prohori.incidents import novelty as novelty_module


def _signin(minutes: float, ip: str, client: str = "web", user: str = "u-1") -> EventSummary:
    return EventSummary.from_event(
        event(at(minutes), "auth.signin.success", ip=ip, user_id=user, client=client)
    )


def test_summary_keeps_the_fields_the_builder_needs() -> None:
    source = event(
        at(0),
        "auth.signin.success",
        user_id="u-1",
        client="android/1",
        request_id="req-1",
        extra={"session_id": "s-9"},
        user_agent="okhttp/4",
        method="post",
        path="/api/auth/signin",
        status=200,
    )
    summary = EventSummary.from_event(source)
    assert summary.id == source.id
    assert summary.link_value("source.ip") == "203.0.113.7"
    assert summary.link_value("extra.session_id") == "s-9"
    assert summary.link_value("request_id") == "req-1"
    assert (summary.http_method, summary.http_status) == ("POST", 200)
    assert summary.account == "u-1"
    assert not hasattr(summary, "raw")


def test_account_falls_back_to_user_name() -> None:
    ssh = EventSummary.from_event(event(at(0), "ssh.login.success", user_name="root"))
    assert ssh.account == "root"


def test_context_drops_the_oldest_events_beyond_its_limit() -> None:
    context = EventContext(max_events=3)
    events = [event(at(n)) for n in range(5)]
    assert list(context.observe(events)) == events  # passes events through unchanged
    assert len(context) == 3
    assert context.dropped == 2
    assert context.get(events[0].id) is None
    assert context.get(events[4].id) is not None


def test_context_ignores_repeated_events() -> None:
    context = EventContext(max_events=2)
    one = event(at(0))
    context.add(one)
    context.add(one)
    assert len(context) == 1
    assert context.dropped == 0


def test_context_rejects_a_zero_limit() -> None:
    with pytest.raises(ValueError, match="max_events"):
        EventContext(max_events=0)


def test_known_new_and_no_history() -> None:
    history = SignInHistory()
    for item in (_signin(0, "192.0.2.44", "android"), _signin(60, "203.0.113.7")):
        history.add(item)
    first = history.check(_signin(0, "192.0.2.44", "android"))
    assert first is not None
    assert first.ip_status is NoveltyStatus.NO_HISTORY
    attacker = history.check(_signin(60, "203.0.113.7"))
    assert attacker is not None
    assert (attacker.ip_status, attacker.client_status) == (NoveltyStatus.NEW, NoveltyStatus.NEW)
    assert attacker.earlier_ips == 1
    history.add(_signin(90, "192.0.2.44", "android"))
    again = history.check(_signin(90, "192.0.2.44", "android"))
    assert again is not None
    assert (again.ip_status, again.client_status) == (NoveltyStatus.KNOWN, NoveltyStatus.KNOWN)


def test_earlier_is_decided_by_timestamp_not_arrival_order() -> None:
    history = SignInHistory()
    history.add(_signin(60, "203.0.113.7"))
    history.add(_signin(0, "203.0.113.7"))  # arrives late but happened first
    result = history.check(_signin(60, "203.0.113.7"))
    assert result is not None
    assert result.ip_status is NoveltyStatus.KNOWN


def test_only_successful_signins_count() -> None:
    history = SignInHistory()
    history.add(EventSummary.from_event(event(at(0), user_id="u-1")))  # a failure
    result = history.check(_signin(10, "203.0.113.7"))
    assert result is not None
    assert result.ip_status is NoveltyStatus.NO_HISTORY
    assert history.check(EventSummary.from_event(event(at(0), user_id="u-1"))) is None
    no_account = EventSummary.from_event(event(at(0), "auth.signin.success"))
    history.add(no_account)
    assert history.check(no_account) is None


def test_full_account_history_gives_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(novelty_module, "MAX_VALUES_PER_ACCOUNT", 2)
    history = SignInHistory()
    for n in range(3):
        history.add(_signin(n, f"192.0.2.{n}", client="web"))
    known = history.check(_signin(5, "192.0.2.0"))
    assert known is not None
    assert known.ip_status is NoveltyStatus.KNOWN
    dropped = history.check(_signin(5, "192.0.2.2"))
    assert dropped is not None
    assert dropped.ip_status is NoveltyStatus.UNKNOWN  # might have been seen, but was not kept


def test_dropped_accounts_give_unknown() -> None:
    history = SignInHistory(max_accounts=1)
    history.add(_signin(0, "192.0.2.1", user="u-1"))
    history.add(_signin(1, "192.0.2.1", user="u-2"))
    assert history.accounts_dropped == 1
    result = history.check(_signin(2, "192.0.2.9", user="u-2"))
    assert result is not None
    assert result.ip_status is NoveltyStatus.UNKNOWN


def test_missing_ip_or_client_is_unknown() -> None:
    history = SignInHistory()
    history.add(_signin(0, "192.0.2.1"))
    no_client = EventSummary.from_event(
        event(at(5), "auth.signin.success", ip="192.0.2.1", user_id="u-1")
    )
    result = history.check(no_client)
    assert result is not None
    assert (result.ip_status, result.client_status) == (NoveltyStatus.KNOWN, NoveltyStatus.UNKNOWN)
