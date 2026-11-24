# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The attack scenarios. Each declares, before any evaluation is run, which rules should detect it.

Every scenario has a ``default`` variant and two held-out variants. ``heldout`` changes the
attacker's behaviour in ways a real attacker would (slower, spread over more addresses,
obfuscated, outside a time window) and exists to show where the rules stop working.
``heldout2`` was added after the evasion-resistant rules were fixed (ADR-0036) and is derived
from ``heldout`` by a fixed rule: rates halved, sources doubled, and a distributed attack's
sources spread over every documentation network (:meth:`AddressPool.take_spread`). The expected
rules are the same for every variant: a miss in a held-out variant is a real miss.

Where attackers come from (address model 2, fixed before any rule was scored on it):

* every default attack: one address, or two for credential stuffing, in one provider network
  (``203.0.113.0/24``, which holds no benign address);
* held-out SSH guessing (3 addresses) and password spraying (4 addresses): inside that one
  provider network, as a careful attacker renting a few servers from one host would be;
* held-out credential stuffing (30 addresses), described as spread out: spread over every
  network, like the whole of ``heldout2``;
* token reuse: one address (IPv6 in the held-out variants); account takeover, admin misuse, web
  scanning and injection: one address.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from prohori.simulate import formats
from prohori.simulate.addresses import HOSTILE, IPV6, AddressPool
from prohori.simulate.background import (
    BROWSERS,
    RequestIds,
    admin_background,
    app_background,
    population,
    ssh_background,
    user_fields,
    web_background,
)
from prohori.simulate.model import Attack, Recorder
from prohori.simulate.windows import COMMON_NAMES, STAFF, windows_background

Params = Mapping[str, float]
Generator = Callable[[Recorder, AddressPool, Params, str], None]

VARIANTS: Final = ("default", "heldout", "heldout2")


@dataclass(frozen=True)
class Scenario:
    """A named attack scenario and how to write it."""

    name: str
    description: str
    parser: str  # the Prohori parser that reads the output
    extension: str
    defaults: Mapping[str, Mapping[str, float]]  # variant -> parameter defaults
    starts: Mapping[str, str]  # variant -> ISO start time
    generate: Generator

    @property
    def filename(self) -> str:
        return f"{self.name}{self.extension}"


def _int(params: Params, name: str) -> int:
    return int(params[name])


def _sources(pool: AddressPool, network: str, count: int, variant: str) -> list[str]:
    """An attack's sources: from one range, or spread over every network in ``heldout2``."""
    return pool.take_spread(count) if variant == "heldout2" else pool.take_many(network, count)


# --------------------------------------------------------------------------- SSH


def ssh_bruteforce(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ssh_background(rec, pool, _int(p, "duration"), p["noise"])
    sources = _sources(pool, HOSTILE, _int(p, "sources"), variant)
    names: tuple[str, ...] = ("root", "admin", "ubuntu", "test", "oracle", "postgres")
    if variant != "default":
        names = ("root",)  # only a real account: no "Invalid user" lines
    attack = rec.attack(
        Attack(
            id="ssh-bruteforce-1",
            kind="ssh-bruteforce",
            description="Password guessing against SSH accounts",
            expected_rules=("PRH-AUTH-001", "PRH-SSH-001", "PRH-AUTH-005", "PRH-AUTH-006"),
            sources=tuple(sources),
            accounts=names,
        )
    )
    rng = rec.rng
    gap = 1 / (p["rate"] * len(sources))  # each source sends `rate` attempts per minute
    pid = 9000
    for n in range(_int(p, "attempts")):
        minute = p["attack_at"] + n * gap + rng.uniform(0, gap / 4)
        ip = sources[n % len(sources)]
        name = names[n % len(names)]
        pid += 1
        port = rng.randrange(30000, 60000)
        when = rec.at(minute)
        if name == "root":
            rec.add(
                when,
                formats.syslog(
                    when, "sshd", pid, f"Failed password for root from {ip} port {port} ssh2"
                ),
                attack,
            )
            if n % 6 == 5:
                rec.add(
                    when,
                    formats.syslog(
                        when,
                        "sshd",
                        pid,
                        f"error: maximum authentication attempts exceeded for root from {ip} "
                        f"port {port} ssh2 [preauth]",
                    ),
                    attack,
                )
                rec.add(
                    when,
                    formats.syslog(
                        when,
                        "sshd",
                        pid,
                        f"Disconnecting authenticating user root {ip} port {port}: "
                        "Too many authentication failures [preauth]",
                    ),
                    attack,
                )
        else:
            rec.add(
                when,
                formats.syslog(when, "sshd", pid, f"Invalid user {name} from {ip} port {port}"),
                attack,
            )
            rec.add(
                when,
                formats.syslog(
                    when,
                    "sshd",
                    pid,
                    "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                    f"ruser= rhost={ip}",
                ),
                attack,
            )
            rec.add(
                when,
                formats.syslog(
                    when,
                    "sshd",
                    pid,
                    f"Failed password for invalid user {name} from {ip} port {port} ssh2",
                ),
                attack,
            )
            rec.add(
                when,
                formats.syslog(
                    when,
                    "sshd",
                    pid,
                    f"Connection closed by invalid user {name} {ip} port {port} [preauth]",
                ),
                attack,
            )


# --------------------------------------------------------------------------- app events


def _app_setup(rec: Recorder, pool: AddressPool, p: Params) -> tuple[RequestIds, list[str]]:
    ids = RequestIds("req")
    people = population(rec, pool, _int(p, "users"))
    app_background(rec, people, ids, _int(p, "duration"), p["noise"])
    return ids, people.accounts


def password_spraying(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ids, accounts = _app_setup(rec, pool, p)
    sources = _sources(pool, HOSTILE, _int(p, "sources"), variant)
    targets = accounts[: _int(p, "attempts")] if _int(p, "attempts") <= len(accounts) else accounts
    attack = rec.attack(
        Attack(
            id="password-spraying-1",
            kind="password-spraying",
            description="One common password tried against many accounts",
            expected_rules=("PRH-AUTH-002", "PRH-AUTH-001", "PRH-AUTH-007"),
            sources=tuple(sources),
            accounts=tuple(targets),
        )
    )
    rng = rec.rng
    gap = 1 / (p["rate"] * len(sources))  # each source sends `rate` attempts per minute
    for n, account in enumerate(targets):
        when = rec.at(p["attack_at"] + n * gap + rng.uniform(0, gap / 4))
        rec.add(
            when,
            formats.app(
                when,
                "auth.signin.failure",
                "authentication",
                "failure",
                ip=sources[n % len(sources)],
                request_id=ids.next(),
                user_agent="python-requests/2.32.3",
                user=user_fields(account),
                reason="bad_password",
            ),
            attack,
        )


def credential_stuffing(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ids, accounts = _app_setup(rec, pool, p)
    count = _int(p, "sources")  # spread out except in the default variant
    sources = pool.take_many(HOSTILE, count) if variant == "default" else pool.take_spread(count)
    attack = rec.attack(
        Attack(
            id="credential-stuffing-1",
            kind="credential-stuffing",
            description="Leaked email and password pairs replayed; a few still work",
            expected_rules=(
                "PRH-AUTH-001",
                "PRH-AUTH-002",
                "PRH-AUTH-003",
                "PRH-AUTH-008",
                "PRH-AUTH-009",
            ),
            sources=tuple(sources),
        )
    )
    rng = rec.rng
    gap = 1 / (p["rate"] * len(sources))
    for n in range(_int(p, "attempts")):
        ip = sources[n % len(sources)]
        when = rec.at(p["attack_at"] + n * gap + rng.uniform(0, gap / 4))
        if rng.random() < 0.3:  # an email the shop does not know: no hash is logged
            rec.add(
                when,
                formats.app(
                    when,
                    "auth.signin.failure",
                    "authentication",
                    "failure",
                    ip=ip,
                    request_id=ids.next(),
                    user_agent="python-requests/2.32.3",
                    reason="unknown_user",
                ),
                attack,
            )
            continue
        account = f"u-{5000 + n}" if rng.random() < 0.5 else rng.choice(accounts)
        works = rng.random() < 0.06
        rec.add(
            when,
            formats.app(
                when,
                "auth.signin.success" if works else "auth.signin.failure",
                "authentication",
                "success" if works else "failure",
                ip=ip,
                request_id=ids.next(),
                user_agent="python-requests/2.32.3",
                user=user_fields(account),
                reason=None if works else "bad_password",
            ),
            attack,
        )


def token_reuse(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ids, accounts = _app_setup(rec, pool, p)
    victims = accounts[: _int(p, "attempts")]
    source = pool.take(HOSTILE if variant == "default" else IPV6)
    attack = rec.attack(
        Attack(
            id="token-reuse-1",
            kind="token-reuse",
            description="Stolen refresh tokens replayed after the victims already used them",
            expected_rules=("PRH-SESS-001",),
            sources=(source,),
            accounts=tuple(victims),
        )
    )
    for n, victim in enumerate(victims):
        when = rec.at(p["attack_at"] + n * 7.5 + rec.rng.uniform(0, 2))
        client = "web" if variant == "default" else "android/10203"
        rec.add(
            when,
            formats.app(
                when,
                "session.refresh.reuse_detected",
                "session",
                "failure",
                ip=source,
                request_id=ids.next(),
                client=client,
                user_agent="okhttp/4.12.0",
                route="/api/auth/refresh",
                user=user_fields(victim),
                severity="high",
            ),
            attack,
        )


def account_takeover(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ids, accounts = _app_setup(rec, pool, p)
    victim = accounts[-1]
    source = pool.take(HOSTILE)
    attack = rec.attack(
        Attack(
            id="account-takeover-1",
            kind="account-takeover",
            description="Password guessing on one account, sign-in, 2FA and payout changes",
            expected_rules=("PRH-AUTH-001", "PRH-AUTH-003", "PRH-ACCT-001", "PRH-AUTH-010"),
            sources=(source,),
            accounts=(victim,),
        )
    )
    rng = rec.rng
    user = user_fields(victim)
    gap = 1 / p["rate"]
    start = p["attack_at"]
    for n in range(_int(p, "attempts")):
        when = rec.at(start + n * gap + rng.uniform(0, gap / 4))
        rec.add(
            when,
            formats.app(
                when,
                "auth.signin.failure",
                "authentication",
                "failure",
                ip=source,
                request_id=ids.next(),
                user_agent="python-requests/2.32.3",
                user=user,
                reason="bad_password",
            ),
            attack,
        )
    signed_in = start + _int(p, "attempts") * gap + 0.5
    when = rec.at(signed_in)
    rec.add(
        when,
        formats.app(
            when,
            "auth.signin.success",
            "authentication",
            "success",
            ip=source,
            request_id=ids.next(),
            user_agent="python-requests/2.32.3",
            user=user,
        ),
        attack,
    )
    changes = (("account.2fa.disabled", 1.5), ("account.bkash.changed", 2.2))
    if variant != "default":  # waits longer than PRH-ACCT-001's 30 minutes before acting
        changes = (("account.bkash.changed", 35.0), ("account.password.changed", 41.0))
    for action, after in changes:
        when = rec.at(signed_in + after)
        rec.add(
            when,
            formats.app(
                when,
                action,
                "account",
                "success",
                ip=source,
                request_id=ids.next(),
                user_agent="python-requests/2.32.3",
                method="PATCH",
                route="/api/account",
                user=user,
                severity="high",
            ),
            attack,
        )


def admin_misuse(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    ids, _accounts = _app_setup(rec, pool, p)
    admins = {"u-0001": pool.household(), "u-0002": pool.household()}
    # Background starts at 00:00 Dhaka time (18:00 UTC); office hours are 10:00-18:00 local,
    # which only fall inside the background when it runs that long.
    admin_background(rec, ids, admins, day_start=600, day_end=1080)
    source = pool.take(HOSTILE)
    attack = rec.attack(
        Attack(
            id="admin-misuse-1",
            kind="admin-misuse",
            description="A hijacked admin session grants admin rights to the attacker's account",
            expected_rules=("PRH-ADMIN-001", "PRH-ADMIN-002"),
            sources=(source,),
            accounts=("u-0002", "u-6666"),
        )
    )
    start = p["attack_at"]
    steps = (
        ("auth.signin.success", "authentication", "/api/auth/signin", {"id": "u-0002"}),
        ("admin.role.granted", "admin", "/api/admin/roles", {"id": "u-0002"}),
        ("admin.payout.recorded", "admin", "/api/admin/payouts", {"id": "u-0002"}),
    )
    for n, (action, category, route, user) in enumerate(steps):
        when = rec.at(start + n * 4 + rec.rng.uniform(0, 1))
        rec.add(
            when,
            formats.app(
                when,
                action,
                category,
                "success",
                ip=source,
                request_id=ids.next(),
                route=route,
                user=user,
                severity="high",
            ),
            attack,
        )


# --------------------------------------------------------------------------- web


SCAN_PATHS = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/xmlrpc.php",
    "/server-status",
    "/backup.zip",
    "/config.json",
    "/admin/",
    "/login.php",
    "/test.php",
    "/old/",
    "/api/v1/",
    "/console",
    "/.aws/credentials",
    "/shell.php",
    "/info.php",
)


def web_scanning(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    web_background(rec, pool, _int(p, "duration"), p["noise"])
    source = pool.take(HOSTILE)
    agent = "Mozilla/5.0 zgrab/0.x" if variant == "default" else BROWSERS[0]
    attack = rec.attack(
        Attack(
            id="web-scanning-1",
            kind="web-scanning",
            description="An automated scan for admin tools, backups and leaked files",
            expected_rules=("PRH-WEB-001", "PRH-WEB-003", "PRH-WEB-004"),
            sources=(source,),
        )
    )
    rng = rec.rng
    gap = 1 / p["rate"]
    for n in range(_int(p, "attempts")):
        when = rec.at(p["attack_at"] + n * gap + rng.uniform(0, gap / 4))
        path = SCAN_PATHS[n % len(SCAN_PATHS)]
        if n >= len(SCAN_PATHS):
            stem = rng.choice(("admin", "backup", "old", "dev", "tmp"))
            path = f"/{stem}{n}{rng.choice(('.php', '/', '.bak', '.zip'))}"
        status = 200 if path == "/admin/" else 404
        rec.add(when, formats.access(when, source, "GET", path, status, 153, agent), attack)


INJECTIONS = (
    "/books?id=1%27%20OR%20%271%27%3D%271",
    "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
    "/books?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/search?q=%22%3E%3Csvg%20onload%3Dalert(1)%3E",
    "/books?id=1%3BSELECT%20SLEEP(5)",
)
OBFUSCATED = (
    "/books?id=1%27/**/oR/**/%271%27%3D%271",
    "/books?id=1%20UnIoN/**/SeLeCt%20username,password%20FROM%20users",
    "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "/download?file=....%2F%2F....%2F%2Fetc%2Fpasswd",
    "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/books?id=1%20AND%20(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)",
)


def injection(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    web_background(rec, pool, _int(p, "duration"), p["noise"])
    source = pool.take(HOSTILE)
    payloads = INJECTIONS if variant == "default" else OBFUSCATED
    attack = rec.attack(
        Attack(
            id="injection-1",
            kind="injection",
            description="SQL injection, cross-site scripting and path traversal probes",
            expected_rules=("PRH-WEB-002",),
            sources=(source,),
        )
    )
    rng = rec.rng
    gap = 1 / p["rate"]
    for n in range(_int(p, "attempts")):
        when = rec.at(p["attack_at"] + n * gap + rng.uniform(0, gap / 4))
        target = payloads[n % len(payloads)]
        status = rng.choice((400, 403, 500, 200))
        rec.add(when, formats.access(when, source, "GET", target, status, 420, BROWSERS[2]), attack)


# --------------------------------------------------------------------------- registry

# --------------------------------------------------------------------------- Windows


def windows_signin(rec: Recorder, pool: AddressPool, p: Params, variant: str) -> None:
    log = windows_background(rec, pool, _int(p, "duration"), p["noise"])
    sources = _sources(pool, HOSTILE, _int(p, "sources"), variant)
    # Common names first (a spray), then the built-in administrator over and over (guessing).
    names = (*COMMON_NAMES[:4], *STAFF[:4])
    attack = rec.attack(
        Attack(
            id="windows-signin-1",
            kind="windows-signin",
            description="Remote-desktop password spraying and guessing, a sign-in, then a new "
            "administrator account",
            expected_rules=("PRH-WIN-001", "PRH-WIN-002", "PRH-WIN-003", "PRH-WIN-004"),
            sources=tuple(sources),
            accounts=("administrator", "svc-update"),
        )
    )
    rng = rec.rng
    gap = 1 / (p["rate"] * len(sources))  # each source sends `rate` attempts per minute
    attempts = _int(p, "attempts")
    for n in range(attempts):
        minute = p["attack_at"] + n * gap + rng.uniform(0, gap / 4)
        name = names[n] if n < len(names) else "administrator"
        log.failure(
            rec.at(minute),
            name,
            sources[n % len(sources)],
            unknown=name in COMMON_NAMES and name != "administrator",
            logon_type=10,
            workstation="-",
            attack=attack,
        )
    # The guess that works comes from the source that sent the last failure.
    winner = sources[(attempts - 1) % len(sources)]
    signed_in = p["attack_at"] + attempts * gap + 0.4
    log.logon(rec.at(signed_in), "administrator", winner, logon_type=10, attack=attack)
    log.account_created(rec.at(signed_in + 2.5), "administrator", "svc-update", attack)
    log.added_to_administrators(rec.at(signed_in + 2.8), "administrator", "svc-update", attack)


_APP = {"duration": 180, "users": 40, "noise": 3}
_WEB = {"duration": 120, "noise": 6}

SCENARIOS: Final[dict[str, Scenario]] = {
    s.name: s
    for s in (
        Scenario(
            "ssh-bruteforce",
            "SSH password guessing against root and common user names",
            "auth_log",
            ".log",
            {
                "default": {
                    "duration": 180,
                    "noise": 1.5,
                    "attack_at": 60,
                    "rate": 20,
                    "attempts": 60,
                    "sources": 1,
                },
                "heldout": {
                    "duration": 240,
                    "noise": 1.5,
                    "attack_at": 30,
                    "rate": 1.5,
                    "attempts": 60,
                    "sources": 3,
                },
            },
            {"default": "2026-10-24T08:00:00Z", "heldout": "2026-10-24T08:00:00Z"},
            ssh_bruteforce,
        ),
        Scenario(
            "password-spraying",
            "One password tried against many app accounts",
            "app_json",
            ".jsonl",
            {
                "default": {**_APP, "attack_at": 60, "rate": 4, "attempts": 30, "sources": 1},
                "heldout": {**_APP, "attack_at": 40, "rate": 0.4, "attempts": 30, "sources": 4},
            },
            {"default": "2026-10-24T06:00:00Z", "heldout": "2026-10-24T06:00:00Z"},
            password_spraying,
        ),
        Scenario(
            "credential-stuffing",
            "Leaked credentials replayed against the sign-in API",
            "app_json",
            ".jsonl",
            {
                "default": {**_APP, "attack_at": 50, "rate": 15, "attempts": 120, "sources": 2},
                "heldout": {**_APP, "attack_at": 50, "rate": 0.5, "attempts": 120, "sources": 30},
            },
            {"default": "2026-10-24T06:00:00Z", "heldout": "2026-10-24T06:00:00Z"},
            credential_stuffing,
        ),
        Scenario(
            "token-reuse",
            "Stolen refresh tokens replayed",
            "app_json",
            ".jsonl",
            {
                "default": {**_APP, "attack_at": 70, "attempts": 3},
                "heldout": {**_APP, "attack_at": 70, "attempts": 3},
            },
            {"default": "2026-10-24T06:00:00Z", "heldout": "2026-10-24T06:00:00Z"},
            token_reuse,
        ),
        Scenario(
            "account-takeover",
            "Guessing one account's password, then disabling 2FA and changing the payout number",
            "app_json",
            ".jsonl",
            {
                "default": {**_APP, "attack_at": 90, "rate": 20, "attempts": 12},
                "heldout": {**_APP, "attack_at": 90, "rate": 1.6, "attempts": 9},
            },
            {"default": "2026-10-24T12:00:00Z", "heldout": "2026-10-24T12:00:00Z"},
            account_takeover,
        ),
        Scenario(
            "web-scanning",
            "Automated scanning for admin tools, backups and leaked files",
            "access_log",
            ".log",
            {
                "default": {**_WEB, "attack_at": 40, "rate": 60, "attempts": 150},
                "heldout": {**_WEB, "attack_at": 40, "rate": 8, "attempts": 150},
            },
            {"default": "2026-10-24T09:00:00Z", "heldout": "2026-10-24T09:00:00Z"},
            web_scanning,
        ),
        Scenario(
            "injection",
            "SQL injection, cross-site scripting and path traversal in query strings",
            "access_log",
            ".log",
            {
                "default": {**_WEB, "attack_at": 45, "rate": 6, "attempts": 18},
                "heldout": {**_WEB, "attack_at": 45, "rate": 6, "attempts": 18},
            },
            {"default": "2026-10-24T09:00:00Z", "heldout": "2026-10-24T09:00:00Z"},
            injection,
        ),
        Scenario(
            "admin-misuse",
            "A hijacked admin session at night grants admin rights to another account",
            "app_json",
            ".jsonl",
            {
                # Starts at 00:00 Asia/Dhaka. Default attack at 02:40 local; held-out at 21:30.
                "default": {**_APP, "duration": 1440, "noise": 0.5, "attack_at": 160},
                "heldout": {**_APP, "duration": 1440, "noise": 0.5, "attack_at": 1290},
            },
            {"default": "2026-10-23T18:00:00Z", "heldout": "2026-10-23T18:00:00Z"},
            admin_misuse,
        ),
        Scenario(
            "windows-signin",
            "Remote-desktop password spraying and guessing on a Windows server, a sign-in, then "
            "a new administrator account",
            "windows_security",
            ".jsonl",
            {
                "default": {
                    "duration": 240,
                    "noise": 3,
                    "attack_at": 60,
                    "rate": 20,
                    "attempts": 40,
                    "sources": 1,
                },
                "heldout": {
                    "duration": 240,
                    "noise": 3,
                    "attack_at": 60,
                    "rate": 1.5,
                    "attempts": 40,
                    "sources": 4,
                },
            },
            {"default": "2026-10-24T03:00:00Z", "heldout": "2026-10-24T03:00:00Z"},
            windows_signin,
        ),
    )
}
