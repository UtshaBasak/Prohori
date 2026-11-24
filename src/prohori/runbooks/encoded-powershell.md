# PowerShell with an encoded command

**Rules:** PRH-PROC-001

## What it means

PowerShell was started with `-EncodedCommand` (or an abbreviation such as `-enc` or `-e`) and a
Base64 script. Encoding keeps the script out of plain sight in the command line, which is why
malicious documents, droppers and attack tools use it. A few management tools do too.

## Triage

1. Decode the argument to read the script: it is Base64 of UTF-16LE text. Decode it on an
   analysis machine, and never run it.
2. Look at the parent process (`process.parent.name`, `process.parent.command_line`): Word or
   Excel, a browser, `wscript.exe` or `mshta.exe` point to an attack; a known management agent
   points to administration.
3. Check what the process did next on the same host: network connections, DNS queries, files
   written, services or Run keys created.

## Recommended actions

- If the script downloads or runs code, or the parent is an Office application or a browser,
  isolate the host and treat the user's account as compromised.
- Block the domains and addresses the script contacts.
- Record known management tools that use encoded commands as a suppression with an owner and an
  expiry date.

## False positives

- Management and deployment tools (configuration management agents, some installers).

## ATT&CK

- T1059.001 Command and Scripting Interpreter: PowerShell (Execution)
- T1027.010 Obfuscated Files or Information: Command Obfuscation (Stealth)
