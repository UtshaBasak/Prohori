"""Account novelty: was a sign-in's IP address or client seen earlier for the same account?

Rules stay history-free; this bounded history is incident context. It records every successful
sign-in in the input, not only the ones in alerts, and answers "earlier" by timestamp, so slightly
out-of-order input gives the same answer.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from prohori.incidents.summary import EventSummary

#: Actions that count as a successful sign-in.
SIGNIN_SUCCESS_ACTIONS = frozenset({"auth.signin.success", "ssh.login.success"})
#: Actions that count as a failed sign-in.
SIGNIN_FAILURE_ACTIONS = frozenset({"auth.signin.failure", "ssh.login.failure"})

#: Accounts tracked by default; sign-ins to further accounts are not recorded.
MAX_ACCOUNTS = 50_000
#: Distinct IP addresses (and, separately, clients) remembered per account.
MAX_VALUES_PER_ACCOUNT = 64


class NoveltyStatus(StrEnum):
    """What the history can say about one sign-in."""

    KNOWN = "known"  # the account signed in from this IP before
    NEW = "new"  # the account signed in before, but never from this IP
    NO_HISTORY = "no_history"  # no earlier sign-in to the account in the input
    UNKNOWN = "unknown"  # the history limits were reached for this account


@dataclass(frozen=True, slots=True)
class Novelty:
    """The answer for one sign-in."""

    account: str
    ip: str | None
    ip_status: NoveltyStatus
    client: str | None
    client_status: NoveltyStatus
    earlier_ips: int  # distinct IPs the account signed in from before this sign-in


@dataclass
class _Account:
    ips: dict[str, datetime] = field(default_factory=dict)
    clients: dict[str, datetime] = field(default_factory=dict)
    full: bool = False


def _remember(values: dict[str, datetime], value: str | None, at: datetime) -> bool:
    """Record the earliest time ``value`` was seen; return False if there was no room."""
    if value is None:
        return True
    if value in values:
        values[value] = min(values[value], at)
        return True
    if len(values) >= MAX_VALUES_PER_ACCOUNT:
        return False
    values[value] = at
    return True


def _status(
    values: Mapping[str, datetime], value: str | None, at: datetime, full: bool
) -> NoveltyStatus:
    if value is None:
        return NoveltyStatus.UNKNOWN
    first = values.get(value)
    if first is not None and first < at:
        return NoveltyStatus.KNOWN
    return NoveltyStatus.UNKNOWN if full else NoveltyStatus.NEW


class SignInHistory:
    """Earliest sign-in time per account and IP address (and per account and client)."""

    def __init__(self, *, max_accounts: int = MAX_ACCOUNTS) -> None:
        self.max_accounts = max_accounts
        self.accounts_dropped = 0
        self._accounts: dict[str, _Account] = {}

    def add(self, event: EventSummary) -> None:
        """Record ``event`` if it is a successful sign-in with a known account."""
        account = event.account
        if event.action not in SIGNIN_SUCCESS_ACTIONS or account is None:
            return
        state = self._accounts.get(account)
        if state is None:
            if len(self._accounts) >= self.max_accounts:
                self.accounts_dropped += 1
                return
            state = self._accounts[account] = _Account()
        fitted = _remember(state.ips, event.source_ip, event.timestamp)
        fitted = _remember(state.clients, event.client, event.timestamp) and fitted
        if not fitted:
            state.full = True

    def check(self, event: EventSummary) -> Novelty | None:
        """Say whether a successful sign-in came from an IP and client new to the account.

        Returns None for events that are not successful sign-ins with a known account.
        """
        account = event.account
        if event.action not in SIGNIN_SUCCESS_ACTIONS or account is None:
            return None
        state = self._accounts.get(account)
        unknown = NoveltyStatus.UNKNOWN if self.accounts_dropped else NoveltyStatus.NO_HISTORY
        if state is None:
            return Novelty(account, event.source_ip, unknown, event.client, unknown, 0)
        earlier = [ip for ip, first in state.ips.items() if first < event.timestamp]
        earlier_clients = [c for c, first in state.clients.items() if first < event.timestamp]
        if not earlier and not earlier_clients:
            status = NoveltyStatus.UNKNOWN if state.full else NoveltyStatus.NO_HISTORY
            return Novelty(account, event.source_ip, status, event.client, status, 0)
        return Novelty(
            account=account,
            ip=event.source_ip,
            ip_status=_status(state.ips, event.source_ip, event.timestamp, state.full),
            client=event.client,
            client_status=_status(state.clients, event.client, event.timestamp, state.full),
            earlier_ips=len(earlier),
        )
