"""Group alerts that share an entity within a time gap.

Two alerts are linked when they share a ``(field, value)`` pair from :data:`LINK_FIELDS` and the
later one starts no more than ``gap`` after the last alert with that pair ended (the boundary is
inclusive). Links are transitive: an incident is a connected group of alerts.

An alert's pairs are its own entities plus every link field that has exactly one value across
its matched events; a brute-force alert grouped by IP therefore also links on the one account
it targeted, but not on the dozen user names an SSH scan tried.

Shared addresses (NAT gateways, proxies) would merge unrelated people's alerts. Once an IP has
linked alerts about more than ``max_ip_fanout`` distinct accounts it is treated as shared and
links nothing further.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from prohori.incidents.events import LINK_FIELDS, USER_FIELDS, EventContext
from prohori.schema import Alert

#: Default gap: alerts more than this far apart do not join one incident through an entity.
DEFAULT_GAP = timedelta(minutes=30)
#: Default number of distinct accounts one IP address may link.
DEFAULT_MAX_IP_FANOUT = 10

Key = tuple[str, str]


@dataclass(frozen=True)
class AlertGroup:
    """Alerts that form one incident, sorted by first_seen then id."""

    alerts: tuple[Alert, ...]
    keys: tuple[Key, ...]  # every link pair of every alert, sorted
    shared_ips: tuple[tuple[str, int], ...] = ()  # (ip, accounts) treated as shared


def link_keys(alert: Alert, context: EventContext | None) -> set[Key]:
    """Return the ``(field, value)`` pairs ``alert`` can link on."""
    keys = {(f, v) for f, v in alert.entities.items() if f in LINK_FIELDS and v}
    if context is None:
        return keys
    summaries = [s for s in map(context.get, alert.event_ids) if s is not None]
    for field in LINK_FIELDS:
        values = {s.link_value(field) for s in summaries} - {None}
        if len(values) == 1:
            keys.add((field, str(values.pop())))
    return keys


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Keep the smaller index as the root so results do not depend on union order.
            self.parent[max(ra, rb)] = min(ra, rb)


@dataclass
class _Chain:
    """The latest run of alerts linked through one key."""

    member: int
    last_seen: datetime
    accounts: set[Key]


def group_alerts(
    alerts: Iterable[Alert],
    context: EventContext | None = None,
    *,
    gap: timedelta = DEFAULT_GAP,
    max_ip_fanout: int = DEFAULT_MAX_IP_FANOUT,
) -> list[AlertGroup]:
    """Group ``alerts`` into incidents. The result is the same for any input order."""
    if gap < timedelta(0):
        msg = "gap must not be negative"
        raise ValueError(msg)
    if max_ip_fanout < 1:
        msg = "max_ip_fanout must be at least 1"
        raise ValueError(msg)
    ordered = sorted({a.id: a for a in alerts}.values(), key=lambda a: (a.first_seen, a.id))
    keys = [link_keys(alert, context) for alert in ordered]
    sets = _UnionFind(len(ordered))
    chains: dict[Key, _Chain] = {}
    shared: dict[str, int] = {}
    for index, alert in enumerate(ordered):
        accounts = {k for k in keys[index] if k[0] in USER_FIELDS}
        for key in sorted(keys[index]):
            if key[0] == "source.ip" and key[1] in shared:
                continue
            chain = chains.get(key)
            if chain is not None and alert.first_seen - chain.last_seen <= gap:
                if key[0] == "source.ip":
                    combined = chain.accounts | accounts
                    if len(combined) > max_ip_fanout:
                        shared[key[1]] = len(combined)
                        continue
                    chain.accounts = combined
                sets.union(chain.member, index)
                chain.last_seen = max(chain.last_seen, alert.last_seen)
            else:
                chains[key] = _Chain(index, alert.last_seen, set(accounts))
    members: dict[int, list[int]] = {}
    for index in range(len(ordered)):
        members.setdefault(sets.find(index), []).append(index)
    return [_group(ordered, keys, indexes, shared) for indexes in members.values()]


def _group(
    ordered: Sequence[Alert], keys: Sequence[set[Key]], indexes: list[int], shared: dict[str, int]
) -> AlertGroup:
    group_keys = set().union(*(keys[i] for i in indexes))
    ips = {value for field, value in group_keys if field == "source.ip"}
    return AlertGroup(
        alerts=tuple(ordered[i] for i in indexes),
        keys=tuple(sorted(group_keys)),
        shared_ips=tuple(sorted((ip, n) for ip, n in shared.items() if ip in ips)),
    )
