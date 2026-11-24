# New Windows service

**Rules:** PRH-PROC-003

## What it means

A Windows service was created: a service's `ImagePath` was written in the registry, or
`sc.exe create` was run. Services start with Windows and usually run as SYSTEM, so attackers
install one to keep a foothold. Installers and updates create services all the time, so the
program the service runs is what matters.

## Triage

1. Read the service's program: `registry.data` for the registry event, or `binPath=` in the
   `sc.exe` command line.
2. Is it a signed program in `C:\Program Files` or `C:\Windows`, installed by a known product?
   A program in a user folder, `C:\Users\Public`, a temporary folder or `C:\ProgramData`, or a
   command line that runs `cmd.exe` or PowerShell, is suspicious.
3. Which process created it (`process.name`) and was an installer running at the time?

## Recommended actions

- If the service is not from known software, stop and disable it, keep a copy of its program
  for analysis, and isolate the host.
- Look for the same service name or program on other hosts.
- Record known installers that create services as a suppression with an owner and an expiry date.

## False positives

- Software and driver installation and updates.

## ATT&CK

- T1543.003 Create or Modify System Process: Windows Service (Persistence, Privilege Escalation)
