"""The incident score: a documented points system with a breakdown, not machine learning.

Every component is an integer number of points with a reason, so the breakdown always adds up to
the score and a report can explain it line by line. ``docs/INCIDENTS.md`` has the table.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from prohori.incidents.novelty import (
    SIGNIN_FAILURE_ACTIONS,
    SIGNIN_SUCCESS_ACTIONS,
    Novelty,
    NoveltyStatus,
)
from prohori.incidents.summary import USER_FIELDS, EventSummary
from prohori.schema import Alert, EnrichmentResult, ScoreComponent, Severity

#: Points for the most severe alert in the incident.
SEVERITY_POINTS = {Severity.LOW: 10, Severity.MEDIUM: 20, Severity.HIGH: 35, Severity.CRITICAL: 50}
EXTRA_RULE_POINTS = 10  # per distinct rule after the first
EXTRA_RULE_CAP = 30
SUCCESS_AFTER_FAILURE_POINTS = 20
SENSITIVE_ACTION_POINTS = 15
#: Reputation of the worst IP address: AbuseIPDB-style confidence score and vendor verdicts.
ABUSE_HIGH, ABUSE_HIGH_POINTS = 75, 15
ABUSE_MEDIUM, ABUSE_MEDIUM_POINTS = 25, 8
MALICIOUS_HIGH, MALICIOUS_HIGH_POINTS = 3, 15
MALICIOUS_LOW_POINTS = 8  # at least one vendor
TOR_POINTS = 5
REPUTATION_CAP = 20
SPREAD_POINTS = 5  # per source IP or account after the first
SPREAD_CAP = 15
NEW_IP_POINTS = 10
NEW_CLIENT_POINTS = 5
MAX_SCORE = 100

#: Score bands; the incident is never less severe than its most severe alert.
SEVERITY_BANDS = ((75, Severity.CRITICAL), (50, Severity.HIGH), (25, Severity.MEDIUM))

#: Rules whose alerts mean "a sign-in succeeded after failures", even without the events.
SUCCESS_AFTER_FAILURE_RULES = frozenset({"PRH-AUTH-003"})
#: Actions that change who controls an account or what it may do.
SENSITIVE_ACTIONS = frozenset(
    {
        "account.password.changed",
        "account.bkash.changed",
        "account.2fa.disabled",
        "admin.role.granted",
    }
)
#: How providers are named in reasons.
_PROVIDER_NAMES = {"offline": "bundled demo data"}
#: Rules whose alerts always involve a sensitive action.
SENSITIVE_RULES = frozenset({"PRH-ACCT-001", "PRH-ADMIN-001"})


@dataclass(frozen=True)
class Score:
    """The result of scoring one incident."""

    components: tuple[ScoreComponent, ...]
    total: int
    severity: Severity
    success_after_failure: bool
    reputation_points: int


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _flagged(vendors: int) -> str:
    return f"{_plural(vendors, 'vendor')} flag{'s' if vendors == 1 else ''} it as malicious"


def _number(data: Mapping[str, object], key: str) -> int | None:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value)


def reputation(ip: str, results: Sequence[EnrichmentResult]) -> tuple[int, str]:
    """Points and a reason for one IP address's reputation (0 and "" when nothing is known)."""
    abuse = max(
        (n for r in results if (n := _number(r.data, "abuse_score")) is not None), default=None
    )
    malicious = max(
        (n for r in results if (n := _number(r.data, "malicious")) is not None), default=None
    )
    tor = any(r.data.get("is_tor") is True for r in results)
    points = 0
    evidence: list[str] = []
    if abuse is not None and abuse >= ABUSE_HIGH:
        points += ABUSE_HIGH_POINTS
        evidence.append(f"abuse confidence {abuse}")
    elif abuse is not None and abuse >= ABUSE_MEDIUM:
        points += ABUSE_MEDIUM_POINTS
        evidence.append(f"abuse confidence {abuse}")
    if malicious is not None and malicious >= MALICIOUS_HIGH:
        points += MALICIOUS_HIGH_POINTS
        evidence.append(_flagged(malicious))
    elif malicious:
        points += MALICIOUS_LOW_POINTS
        evidence.append(_flagged(malicious))
    if tor:
        points += TOR_POINTS
        evidence.append("Tor exit node")
    if not points:
        return 0, ""
    providers = ", ".join(sorted({_PROVIDER_NAMES.get(r.provider, r.provider) for r in results}))
    points = min(points, REPUTATION_CAP)
    return points, f"Reputation of {ip}: {'; '.join(evidence)} (from {providers})"


def success_after_failure(rule_ids: Iterable[str], events: Sequence[EventSummary]) -> bool:
    """Whether a sign-in succeeded after a failure from the same IP or for the same account."""
    if set(rule_ids) & SUCCESS_AFTER_FAILURE_RULES:
        return True
    # One pass for the earliest failure per IP and per account, then one per success: linear in
    # the number of events, which come from untrusted logs.
    first_by_ip: dict[str, datetime] = {}
    first_by_account: dict[str, datetime] = {}
    for failure in (e for e in events if e.action in SIGNIN_FAILURE_ACTIONS):
        for key, table in ((failure.source_ip, first_by_ip), (failure.account, first_by_account)):
            if key is not None and (key not in table or failure.timestamp < table[key]):
                table[key] = failure.timestamp
    for success in (e for e in events if e.action in SIGNIN_SUCCESS_ACTIONS):
        for key, table in ((success.source_ip, first_by_ip), (success.account, first_by_account)):
            if key is not None and key in table and table[key] < success.timestamp:
                return True
    return False


def _severity_for(total: int, floor: Severity) -> Severity:
    band = next((sev for limit, sev in SEVERITY_BANDS if total >= limit), Severity.LOW)
    return band if band.rank > floor.rank else floor


def score_incident(
    alerts: Sequence[Alert],
    events: Sequence[EventSummary],
    keys: Iterable[tuple[str, str]],
    enrichment: Mapping[str, Sequence[EnrichmentResult]],
    novelty: Sequence[Novelty],
) -> Score:
    """Score one incident. ``enrichment`` maps the incident's IP addresses to provider results."""
    components: list[tuple[str, int]] = []
    top = max(alerts, key=lambda a: a.severity.rank)
    components.append(
        (
            f"Most severe alert: {top.detector_id} ({top.severity.value})",
            SEVERITY_POINTS[top.severity],
        )
    )
    rule_ids = sorted({a.detector_id for a in alerts})
    if len(rule_ids) > 1:
        extra = len(rule_ids) - 1
        components.append(
            (
                f"{_plural(extra, 'more rule')} fired: "
                + ", ".join(r for r in rule_ids if r != top.detector_id),
                min(extra * EXTRA_RULE_POINTS, EXTRA_RULE_CAP),
            )
        )
    succeeded = success_after_failure(rule_ids, events)
    if succeeded:
        components.append(
            ("A sign-in succeeded after failed attempts", SUCCESS_AFTER_FAILURE_POINTS)
        )
    sensitive = sorted({e.action for e in events if e.action in SENSITIVE_ACTIONS})
    sensitive_rules = sorted(set(rule_ids) & SENSITIVE_RULES)
    if sensitive or sensitive_rules:
        what = ", ".join(sensitive) if sensitive else ", ".join(sensitive_rules)
        components.append((f"Sensitive account or admin change: {what}", SENSITIVE_ACTION_POINTS))
    best = max(
        (reputation(ip, results) for ip, results in sorted(enrichment.items())),
        key=lambda item: item[0],
        default=(0, ""),
    )
    if best[0]:
        components.append((best[1], best[0]))
    key_set = set(keys)
    ips = {v for f, v in key_set if f == "source.ip"}
    # One account can appear as an id, a name and an email hash; count the field with most values.
    accounts_count = max((sum(1 for f, _ in key_set if f == u) for u in USER_FIELDS), default=0)
    spread = max(len(ips) - 1, 0) + max(accounts_count - 1, 0)
    if spread:
        components.append(
            (
                f"Spread: {_plural(len(ips), 'source IP')}, {_plural(accounts_count, 'account')}",
                min(spread * SPREAD_POINTS, SPREAD_CAP),
            )
        )
    components.extend(_novelty_components(novelty))
    total = sum(points for _, points in components)
    if total > MAX_SCORE:
        components.append((f"Capped at {MAX_SCORE}", MAX_SCORE - total))
        total = MAX_SCORE
    return Score(
        components=tuple(ScoreComponent(reason=r, points=p) for r, p in components),
        total=total,
        severity=_severity_for(total, top.severity),
        success_after_failure=succeeded,
        reputation_points=best[0],
    )


def _novelty_components(novelty: Sequence[Novelty]) -> list[tuple[str, int]]:
    new_ip = next((n for n in novelty if n.ip_status is NoveltyStatus.NEW), None)
    new_client = next((n for n in novelty if n.client_status is NoveltyStatus.NEW), None)
    components: list[tuple[str, int]] = []
    if new_ip is not None:
        components.append(
            (
                f"Sign-in to {new_ip.account} from {new_ip.ip}, an IP not seen for this account "
                f"before ({_plural(new_ip.earlier_ips, 'earlier IP')})",
                NEW_IP_POINTS,
            )
        )
    if new_client is not None:
        components.append(
            (
                f"Sign-in to {new_client.account} with client {new_client.client}, not seen for "
                "this account before",
                NEW_CLIENT_POINTS,
            )
        )
    return components
