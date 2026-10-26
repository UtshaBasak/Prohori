"""Benign background activity: the normal traffic every attack is hidden in.

Background includes the awkward cases rules must not alert on, or are known to: users who mistype
a password once, many customers behind one shared NAT address, a search-engine crawler that hits
a few dead links, owners changing their own settings, planned admin work, and the stray
internet probes every public SSH server sees.
"""

from dataclasses import dataclass, field

from prohori.simulate import formats
from prohori.simulate.addresses import CUSTOMERS, INTERNET, IPV6, AddressPool
from prohori.simulate.model import Recorder

BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Mobile Safari/537.36",
)
APP_CLIENTS = (("web", BROWSERS[0]), ("android/10203", "okhttp/4.12.0"), ("web", BROWSERS[2]))
CRAWLER = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
STAFF = ("alice", "bob", "carol", "deploy", "backup")
PAGES = ("/", "/books", "/books/new", "/cart", "/account", "/about", "/contact", "/search")
STATIC = ("/static/app.js", "/static/style.css", "/static/logo.svg", "/favicon.ico")


@dataclass
class Population:
    """Who uses the system: customer accounts, staff and their usual addresses and clients."""

    accounts: list[str]
    homes: dict[str, str]  # account -> usual IP
    clients: dict[str, tuple[str, str]]  # account -> (client, user agent)
    nat: str  # one shared address many customers use
    nat_accounts: list[str] = field(default_factory=list)


def population(rec: Recorder, pool: AddressPool, users: int) -> Population:
    rng = rec.rng
    accounts = [f"u-{1000 + n}" for n in range(users)]
    homes: dict[str, str] = {}
    for account in accounts:
        homes[account] = pool.take(IPV6) if rng.random() < 0.2 else pool.take(CUSTOMERS)
    clients = {account: rng.choice(APP_CLIENTS) for account in accounts}
    nat = pool.take(CUSTOMERS)
    nat_accounts = accounts[: max(3, users // 3)]
    return Population(accounts, homes, clients, nat, nat_accounts)


def user_fields(account: str) -> dict[str, str]:
    return {"id": account, "email_hash": formats.email_hash(account)}


class RequestIds:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.count = 0

    def next(self) -> str:
        self.count += 1
        return f"{self.prefix}-{self.count:06d}"


def app_background(
    rec: Recorder, people: Population, ids: RequestIds, duration: int, noise: float
) -> None:
    """Customers signing in, refreshing sessions and occasionally changing settings."""
    rng = rec.rng
    events = round(duration * noise)
    for _ in range(events):
        minute = rng.uniform(0, duration)
        account = rng.choice(people.accounts)
        ip = (
            people.nat
            if account in people.nat_accounts and rng.random() < 0.5
            else people.homes[account]
        )
        client, agent = people.clients[account]
        when = rec.at(minute)
        roll = rng.random()
        user = user_fields(account)
        if roll < 0.07:  # a mistyped password, then the right one
            rec.add(
                when,
                formats.app(
                    when,
                    "auth.signin.failure",
                    "authentication",
                    "failure",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    user=user,
                    reason="bad_password",
                ),
            )
            later = rec.at(minute + rng.uniform(0.1, 0.8))
            rec.add(
                later,
                formats.app(
                    later,
                    "auth.signin.success",
                    "authentication",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    user=user,
                ),
            )
        elif roll < 0.45:
            rec.add(
                when,
                formats.app(
                    when,
                    "auth.signin.success",
                    "authentication",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    user=user,
                ),
            )
        elif roll < 0.9:
            rec.add(
                when,
                formats.app(
                    when,
                    "session.refresh",
                    "session",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    route="/api/auth/refresh",
                    user=user,
                ),
            )
        elif roll < 0.95:
            rec.add(
                when,
                formats.app(
                    when,
                    "authz.denied",
                    "authorization",
                    "failure",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    method="GET",
                    route="/api/orders/:id",
                    user=user,
                    severity="medium",
                ),
            )
        elif roll < 0.98:
            rec.add(
                when,
                formats.app(
                    when,
                    "ratelimit.exceeded",
                    "abuse",
                    "failure",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    method="GET",
                    route="/api/books",
                ),
            )
        else:  # the owner changes a setting shortly after signing in
            rec.add(
                when,
                formats.app(
                    when,
                    "auth.signin.success",
                    "authentication",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    user=user,
                ),
            )
            later = rec.at(minute + rng.uniform(1, 10))
            action = rng.choice(("account.password.changed", "account.bkash.changed"))
            rec.add(
                later,
                formats.app(
                    later,
                    action,
                    "account",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    client=client,
                    user_agent=agent,
                    method="PATCH",
                    route="/api/account",
                    user=user,
                    severity="high",
                ),
            )


def admin_background(
    rec: Recorder, ids: RequestIds, admins: dict[str, str], day_start: float, day_end: float
) -> None:
    """Admins doing routine work during office hours, including one planned role grant."""
    rng = rec.rng
    for admin, ip in admins.items():
        signin = rng.uniform(day_start, day_start + 30)
        when = rec.at(signin)
        rec.add(
            when,
            formats.app(
                when,
                "auth.signin.success",
                "authentication",
                "success",
                ip=ip,
                request_id=ids.next(),
                user=user_fields(admin),
            ),
        )
        for _ in range(6):
            minute = rng.uniform(signin + 5, day_end)
            later = rec.at(minute)
            action = rng.choice(
                ("admin.user.deactivated", "admin.payout.recorded", "admin.message.sent")
            )
            rec.add(
                later,
                formats.app(
                    later,
                    action,
                    "admin",
                    "success",
                    ip=ip,
                    request_id=ids.next(),
                    route="/api/admin",
                    user=user_fields(admin),
                    severity="medium",
                ),
            )
    first = next(iter(admins))
    when = rec.at(rng.uniform(day_start + 60, day_end))
    rec.add(
        when,
        formats.app(
            when,
            "admin.role.granted",
            "admin",
            "success",
            ip=admins[first],
            request_id=ids.next(),
            route="/api/admin/roles",
            user=user_fields(first),
            severity="high",
        ),
    )


def ssh_background(rec: Recorder, pool: AddressPool, duration: int, noise: float) -> None:
    """Staff logging in with keys, a mistyped password now and then, cron, internet probes."""
    rng = rec.rng
    offices = {name: pool.take(CUSTOMERS) for name in STAFF}
    pid = 3000
    for _ in range(round(duration * noise)):
        pid += 1
        minute = rng.uniform(0, duration)
        name = rng.choice(STAFF)
        ip = offices[name]
        port = rng.randrange(40000, 65000)
        when = rec.at(minute)
        roll = rng.random()
        if roll < 0.55:
            rec.add(
                when,
                formats.syslog(
                    when,
                    "sshd",
                    pid,
                    f"Accepted publickey for {name} from {ip} port {port} ssh2: "
                    f"ED25519 SHA256:{name}examplekeyexamplekey",
                ),
            )
            rec.add(
                when,
                formats.syslog(
                    when,
                    "sshd",
                    pid,
                    f"pam_unix(sshd:session): session opened for user "
                    f"{name}(uid={1000 + STAFF.index(name)}) by (uid=0)",
                ),
            )
            end = rec.at(minute + rng.uniform(1, 30))
            rec.add(
                end,
                formats.syslog(end, "sshd", pid, f"Disconnected from user {name} {ip} port {port}"),
            )
            rec.add(
                end,
                formats.syslog(
                    end, "sshd", pid, f"pam_unix(sshd:session): session closed for user {name}"
                ),
            )
        elif roll < 0.65:  # one typo, then success
            rec.add(
                when,
                formats.syslog(
                    when, "sshd", pid, f"Failed password for {name} from {ip} port {port} ssh2"
                ),
            )
            later = rec.at(minute + rng.uniform(0.05, 0.3))
            rec.add(
                later,
                formats.syslog(
                    later, "sshd", pid, f"Accepted password for {name} from {ip} port {port} ssh2"
                ),
            )
        elif roll < 0.8:
            rec.add(
                when,
                formats.syslog(
                    when,
                    "CRON",
                    pid,
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                ),
            )
        else:  # a stray probe from somewhere on the internet
            probe = pool.take(INTERNET) if rng.random() < 0.9 else pool.take(IPV6)
            rec.add(
                when,
                formats.syslog(
                    when, "sshd", pid, f"Connection closed by {probe} port {port} [preauth]"
                ),
            )


def web_background(rec: Recorder, pool: AddressPool, duration: int, noise: float) -> None:
    """Customers browsing the shop and a crawler that finds a few dead links."""
    rng = rec.rng
    visitors = pool.take_many(CUSTOMERS, 40)
    crawler = pool.take(INTERNET)
    for _ in range(round(duration * noise)):
        minute = rng.uniform(0, duration)
        when = rec.at(minute)
        ip = rng.choice(visitors)
        agent = BROWSERS[visitors.index(ip) % len(BROWSERS)]
        page = rng.choice(PAGES)
        if page == "/books":
            page = f"/books/{rng.randrange(1, 500)}"
        rec.add(when, formats.access(when, ip, "GET", page, 200, rng.randrange(2000, 40000), agent))
        asset = rec.at(minute + 0.01)
        rec.add(
            asset,
            formats.access(
                asset,
                ip,
                "GET",
                rng.choice(STATIC),
                rng.choice((200, 200, 200, 304)),
                rng.randrange(200, 90000),
                agent,
                "https://shop.example/",
            ),
        )
        if rng.random() < 0.05:
            rec.add(asset, formats.access(asset, ip, "GET", "/favicon.ico", 404, 153, agent))
    for step in range(round(duration / 2)):  # the crawler: a page every two minutes
        when = rec.at(step * 2 + rng.uniform(0, 1))
        dead = rng.random() < 0.1
        path = f"/books/{rng.randrange(1, 900)}"
        rec.add(
            when,
            formats.access(
                when, crawler, "GET", path, 404 if dead else 200, rng.randrange(150, 30000), CRAWLER
            ),
        )
