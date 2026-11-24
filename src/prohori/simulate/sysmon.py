# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Simulated Sysmon and Security events on an office workstation, and an intrusion on it.

Everything here is **defanged**: command lines name made-up files and run nothing; the encoded
PowerShell commands decode to ``Write-Output`` of a fixed text. The background is a working day
on a Windows 11 workstation: the user opens mail, documents and the browser, Word prints now and
then, Windows and Defender touch ``lsass.exe`` the way they always do, the browser resolves names
and connects out, the configuration-management agent runs an encoded PowerShell command every
two hours, and a software updater installs a service once. The last two are the known false
positives of PRH-PROC-001 and PRH-PROC-003, there on purpose.
"""

import base64
import hashlib
from datetime import datetime

from prohori.simulate import formats
from prohori.simulate.addresses import AddressPool
from prohori.simulate.model import Attack, Recorder

SYSMON = "Microsoft-Windows-Sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
COMPUTER = "WS01.corp.example"
USER = "CORP\\amina"
SYSTEM = "NT AUTHORITY\\SYSTEM"

WINDOWS = "C:\\Windows\\System32\\"
POWERSHELL = WINDOWS + "WindowsPowerShell\\v1.0\\powershell.exe"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
EXPLORER = "C:\\Windows\\explorer.exe"
CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25010.11-0\\MsMpEng.exe"
AGENT = "C:\\Program Files\\ConfigAgent\\agent.exe"
DOCUMENTS = "C:\\Users\\amina\\Documents\\"
SITES = ("www.example.com", "mail.example.net", "docs.example.org", "cdn.example.com")


def encoded(text: str) -> str:
    """``-EncodedCommand`` text: Base64 of UTF-16LE, as PowerShell expects."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


class SysmonLog:
    """Writes Winlogbeat records for Sysmon (and Security) with increasing record ids."""

    def __init__(self, rec: Recorder) -> None:
        self.rec = rec
        self.record_id = 52_000
        self.pid = 4000

    def add(
        self,
        when: datetime,
        event_id: int,
        data: dict[str, str],
        attack: Attack | None = None,
        *,
        security: bool = False,
    ) -> None:
        self.record_id += 1
        provider = formats.SECURITY_PROVIDER if security else SYSMON
        line = formats.winlogbeat(
            when,
            event_id,
            data,
            record_id=self.record_id,
            computer=COMPUTER,
            provider=provider,
            channel="Security" if security else CHANNEL,
        )
        self.rec.add(when, line, attack)

    def _guid(self) -> str:
        return f"{{94f748d5-{self.pid:04x}-6a1a-0000-0010{self.record_id:08x}}}"

    def process(
        self,
        when: datetime,
        image: str,
        command: str,
        parent: str,
        parent_command: str = "",
        *,
        user: str = USER,
        integrity: str = "Medium",
        attack: Attack | None = None,
    ) -> int:
        """Event 1; returns the new process id."""
        self.pid += self.rec.rng.randrange(4, 400)
        self.add(
            when,
            1,
            {
                "RuleName": "-",
                "UtcTime": f"{when:%Y-%m-%d %H:%M:%S}.{when.microsecond // 1000:03d}",
                "ProcessGuid": self._guid(),
                "ProcessId": str(self.pid),
                "Image": image,
                "CommandLine": command,
                "CurrentDirectory": "C:\\Users\\amina\\",
                "User": user,
                "IntegrityLevel": integrity,
                "Hashes": "SHA256=" + hashlib.sha256(image.encode()).hexdigest().upper(),
                "ParentProcessId": str(self.pid - 3),
                "ParentImage": parent,
                "ParentCommandLine": parent_command or parent,
            },
            attack,
        )
        return self.pid

    def network(
        self,
        when: datetime,
        image: str,
        ip: str,
        port: int,
        name: str,
        attack: Attack | None = None,
    ) -> None:
        self.add(
            when,
            3,
            {
                "RuleName": "-",
                "ProcessId": str(self.pid),
                "Image": image,
                "User": USER,
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": "192.0.2.41",
                "SourcePort": str(self.rec.rng.randrange(49152, 65535)),
                "DestinationIp": ip,
                "DestinationHostname": name,
                "DestinationPort": str(port),
            },
            attack,
        )

    def dns(self, when: datetime, image: str, name: str, attack: Attack | None = None) -> None:
        self.add(
            when,
            22,
            {
                "RuleName": "-",
                "ProcessId": str(self.pid),
                "QueryName": name,
                "QueryStatus": "0",
                "Image": image,
                "User": USER,
            },
            attack,
        )

    def file_created(
        self, when: datetime, image: str, path: str, attack: Attack | None = None
    ) -> None:
        self.add(
            when,
            11,
            {"RuleName": "-", "ProcessId": str(self.pid), "Image": image, "TargetFilename": path},
            attack,
        )

    def registry_set(
        self, when: datetime, image: str, path: str, details: str, attack: Attack | None = None
    ) -> None:
        self.add(
            when,
            13,
            {
                "RuleName": "-",
                "EventType": "SetValue",
                "ProcessId": str(self.pid),
                "Image": image,
                "TargetObject": path,
                "Details": details,
                "User": SYSTEM,
            },
            attack,
        )

    def lsass_access(
        self, when: datetime, image: str, access: str, attack: Attack | None = None
    ) -> None:
        self.add(
            when,
            10,
            {
                "RuleName": "-",
                "SourceProcessId": str(self.pid),
                "SourceImage": image,
                "TargetProcessId": "680",
                "TargetImage": WINDOWS + "lsass.exe",
                "GrantedAccess": access,
                "SourceUser": SYSTEM if image.startswith("C:\\Windows") else USER,
                "TargetUser": SYSTEM,
            },
            attack,
        )

    def signin(self, when: datetime, user: str, ip: str, attack: Attack | None = None) -> None:
        self.add(
            when,
            4624,
            {
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": ip,
                "WorkstationName": "WS01",
            },
            attack,
            security=True,
        )


def workstation_background(
    rec: Recorder, pool: AddressPool, duration: int, noise: float
) -> SysmonLog:
    """A working day on WS01; returns the log so the attack keeps numbering records."""
    log = SysmonLog(rec)
    rng = rec.rng
    servers = {name: pool.household() for name in SITES}
    for _ in range(round(duration * noise)):
        minute = rng.uniform(0, duration)
        when = rec.at(minute)
        roll = rng.random()
        if roll < 0.3:  # the browser: a lookup and a connection
            site = rng.choice(SITES)
            log.dns(when, CHROME, site)
            log.network(rec.at(minute + 0.01), CHROME, servers[site], 443, site)
        elif roll < 0.45:  # opening a document from mail or the file server
            app = rng.choice(("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"))
            log.process(
                when,
                OFFICE + app,
                f'"{OFFICE}{app}" /n "{DOCUMENTS}report-{rng.randrange(100)}.docx"',
                EXPLORER,
            )
            log.signin(rec.at(minute + 0.02), "amina", "192.0.2.41")
        elif roll < 0.5:  # Word prints
            log.process(
                when, WINDOWS + "splwow64.exe", "splwow64.exe 12288", OFFICE + "WINWORD.EXE"
            )
        elif roll < 0.7:  # Windows and Defender touch lsass, as they always do
            image = rng.choice((WINDOWS + "svchost.exe", WINDOWS + "wininit.exe", DEFENDER))
            log.lsass_access(when, image, rng.choice(("0x1000", "0x1410", "0x1010")))
        elif roll < 0.85:  # files saved by the user
            log.file_created(
                when,
                OFFICE + "WINWORD.EXE",
                f"C:\\Users\\amina\\Documents\\draft-{rng.randrange(900)}.docx",
            )
        else:  # Explorer starts the user's programs
            program = rng.choice((CHROME, OFFICE + "OUTLOOK.EXE", WINDOWS + "notepad.exe"))
            log.process(when, program, f'"{program}"', EXPLORER)
    # The configuration agent's inventory every two hours: an encoded PowerShell command (a known
    # false positive of PRH-PROC-001).
    minute = rng.uniform(0, 120)
    while minute < duration:
        log.process(
            rec.at(minute),
            POWERSHELL,
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
            f"{encoded('Write-Output inventory-check')}",
            AGENT,
            user=SYSTEM,
            integrity="System",
        )
        minute += 120
    # A software updater installs its service once (a known false positive of PRH-PROC-003).
    minute = rng.uniform(0, duration)
    log.process(
        rec.at(minute),
        WINDOWS + "msiexec.exe",
        "msiexec.exe /i C:\\ProgramData\\Viewer\\viewer-update.msi /qn",
        WINDOWS + "svchost.exe",
        user=SYSTEM,
        integrity="System",
    )
    log.registry_set(
        rec.at(minute + 0.2),
        WINDOWS + "services.exe",
        "HKLM\\System\\CurrentControlSet\\Services\\ViewerUpdate\\ImagePath",
        '"C:\\Program Files\\Viewer\\updater.exe" /service',
    )
    return log
