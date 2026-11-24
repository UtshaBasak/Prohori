# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Simulated Windows Security events: an office's server and the people who sign in to it.

The background is what a file and remote-desktop server sees on a working day: staff opening
shares from their workstations (network logons, 4624 type 3, and logoffs, 4634), the backup
service signing in, an administrator using remote desktop (type 10, with 4672 special
privileges), a mistyped password now and then (about one per person every two hours) followed by
the right one, a phone with an old password that fails one to three times at every sync (about
every 15 minutes) and never succeeds, and the stray remote-desktop guesses any server reachable
from the internet gets.
"""

from datetime import datetime

from prohori.simulate import formats
from prohori.simulate.addresses import AddressPool
from prohori.simulate.model import Attack, Recorder

DOMAIN = "CORP"
SID_PREFIX = "S-1-5-21-1004336348-1177238915-682003330"
STAFF = ("amina", "rafiq", "nusrat", "tanvir", "farhana", "jamal")
ADMIN = "it-admin"
SERVICE = "svc-backup"
#: Names internet guessers try on any reachable server.
COMMON_NAMES = ("administrator", "admin", "user", "test", "guest", "scanner", "backup")


class WindowsLog:
    """Writes Winlogbeat records with increasing record ids."""

    def __init__(self, rec: Recorder) -> None:
        self.rec = rec
        self.record_id = 81_000

    def add(
        self, when: datetime, event_id: int, data: dict[str, str], attack: Attack | None = None
    ) -> None:
        self.record_id += 1
        self.rec.add(
            when, formats.winlogbeat(when, event_id, data, record_id=self.record_id), attack
        )

    def logon(
        self,
        when: datetime,
        user: str,
        ip: str,
        *,
        logon_type: int = 3,
        workstation: str = "-",
        attack: Attack | None = None,
    ) -> None:
        self.add(
            when,
            4624,
            {
                "SubjectUserSid": "S-1-5-18",
                "SubjectUserName": "SRV01$",
                "SubjectDomainName": DOMAIN,
                "TargetUserSid": sid(user),
                "TargetUserName": user,
                "TargetDomainName": DOMAIN,
                "TargetLogonId": f"0x{self.record_id:x}",
                "LogonType": str(logon_type),
                "LogonProcessName": "User32 " if logon_type == 10 else "NtLmSsp ",
                "AuthenticationPackageName": "Negotiate" if logon_type == 10 else "NTLM",
                "WorkstationName": workstation,
                "IpAddress": ip,
                "IpPort": str(self.rec.rng.randrange(49152, 65535)),
            },
            attack,
        )

    def failure(
        self,
        when: datetime,
        user: str,
        ip: str,
        *,
        unknown: bool = False,
        logon_type: int = 3,
        workstation: str = "-",
        attack: Attack | None = None,
    ) -> None:
        self.add(
            when,
            4625,
            {
                "SubjectUserSid": "S-1-0-0",
                "TargetUserSid": "S-1-0-0",
                "TargetUserName": user,
                "TargetDomainName": DOMAIN,
                "Status": "0xc000006d",
                "FailureReason": "%%2313",
                "SubStatus": "0xc0000064" if unknown else "0xc000006a",
                "LogonType": str(logon_type),
                "LogonProcessName": "NtLmSsp ",
                "AuthenticationPackageName": "NTLM",
                "WorkstationName": workstation,
                "IpAddress": ip,
                "IpPort": str(self.rec.rng.randrange(49152, 65535)),
            },
            attack,
        )

    def logoff(self, when: datetime, user: str, logon_type: int = 3) -> None:
        self.add(
            when,
            4634,
            {
                "TargetUserSid": sid(user),
                "TargetUserName": user,
                "TargetDomainName": DOMAIN,
                "TargetLogonId": f"0x{self.record_id:x}",
                "LogonType": str(logon_type),
            },
        )

    def special_privileges(self, when: datetime, user: str) -> None:
        self.add(
            when,
            4672,
            {
                "SubjectUserSid": sid(user),
                "SubjectUserName": user,
                "SubjectDomainName": DOMAIN,
                "SubjectLogonId": f"0x{self.record_id:x}",
                "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege",
            },
        )

    def account_created(self, when: datetime, actor: str, user: str, attack: Attack) -> None:
        self.add(
            when,
            4720,
            {
                "TargetUserName": user,
                "TargetDomainName": DOMAIN,
                "TargetSid": sid(user),
                "SubjectUserSid": sid(actor),
                "SubjectUserName": actor,
                "SubjectDomainName": DOMAIN,
                "SubjectLogonId": "0x9b3c10",
                "SamAccountName": user,
            },
            attack,
        )

    def added_to_administrators(
        self, when: datetime, actor: str, user: str, attack: Attack
    ) -> None:
        self.add(
            when,
            4732,
            {
                "MemberName": "-",
                "MemberSid": sid(user),
                "TargetUserName": "Administrators",
                "TargetDomainName": "Builtin",
                "TargetSid": "S-1-5-32-544",
                "SubjectUserSid": sid(actor),
                "SubjectUserName": actor,
                "SubjectDomainName": DOMAIN,
                "SubjectLogonId": "0x9b3c10",
                "PrivilegeList": "-",
            },
            attack,
        )


def sid(user: str) -> str:
    """A stable, made-up domain SID for an account name (500 for the built-in administrator)."""
    if user == "administrator":
        return f"{SID_PREFIX}-500"
    return f"{SID_PREFIX}-{1100 + sum(user.encode()) % 900}"


def windows_background(rec: Recorder, pool: AddressPool, duration: int, noise: float) -> WindowsLog:
    """A working day on the server; returns the log so the attack keeps numbering records."""
    log = WindowsLog(rec)
    rng = rec.rng
    desks = {name: (pool.household(), f"WS{n + 1:02d}") for n, name in enumerate(STAFF)}
    admin_ip, backup_ip, phone_ip = pool.household(), pool.household(), pool.household()
    phone = rng.choice(STAFF)  # a phone, on its own address, still using an old password
    for _ in range(round(duration * noise)):
        minute = rng.uniform(0, duration)
        when = rec.at(minute)
        roll = rng.random()
        if roll < 0.6:  # opening a share
            name = rng.choice(STAFF)
            ip, desk = desks[name]
            log.logon(when, name, ip, workstation=desk)
            log.logoff(rec.at(minute + rng.uniform(0.5, 20)), name)
        elif roll < 0.63:  # one typo, then the right password
            name = rng.choice(STAFF)
            ip, desk = desks[name]
            log.failure(when, name, ip, workstation=desk)
            log.logon(rec.at(minute + rng.uniform(0.05, 0.3)), name, ip, workstation=desk)
        elif roll < 0.83:  # the backup service
            log.logon(when, SERVICE, backup_ip, workstation="BACKUP01")
            log.logoff(rec.at(minute + rng.uniform(1, 5)), SERVICE)
        elif roll < 0.92:  # the administrator over remote desktop
            log.logon(when, ADMIN, admin_ip, logon_type=10, workstation="ADMIN-PC")
            log.special_privileges(when, ADMIN)
            log.logoff(rec.at(minute + rng.uniform(5, 40)), ADMIN, logon_type=10)
        else:  # a stray remote-desktop guess from the internet
            log.failure(
                when,
                rng.choice(COMMON_NAMES),
                pool.internet_host(),
                unknown=True,
                logon_type=10,
                workstation="-",
            )
    # The phone syncs about every 15 minutes and fails one to three times each time.
    minute = rng.uniform(0, 15)
    while minute < duration:
        for n in range(rng.randrange(1, 4)):
            log.failure(rec.at(minute + n * 0.2), phone, phone_ip, workstation="PHONE-1")
        minute += rng.uniform(13, 17)
    return log
