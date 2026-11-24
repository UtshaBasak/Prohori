# Office application or browser started a shell

**Rules:** PRH-PROC-002

## What it means

Word, Excel, PowerPoint, Outlook, OneNote, Access or Publisher, or a web browser, started a
command shell, PowerShell or a script host (`wscript.exe`, `mshta.exe`, ...). A document with a
macro, a malicious attachment or an exploited browser does this to run the next stage of an
attack. These programs rarely need a shell for ordinary work.

## Triage

1. Which document or page was open? The parent's command line (`process.parent.command_line`)
   often names the file; check where it came from (an email attachment, a download).
2. Read the child's command line (`process.command_line`): encoded PowerShell, a download, or a
   script in a temporary folder is an attack.
3. Look for what followed on the host: network connections, new files, services or Run keys.

## Recommended actions

- Isolate the host if the command line runs or downloads code, and find the document: delete
  it from mailboxes and shares where others could open it too.
- Block macros in documents from the internet (Office's default since 2022; make sure a policy
  has not turned it off).
- Reset the user's password if the attack ran with their session.

## False positives

- Add-ins or macros that run scripts on purpose (rare; confirm with the document's owner).
- A user who chose to run a downloaded script from the browser.

## ATT&CK

- T1204.002 User Execution: Malicious File (Execution)
- T1059 Command and Scripting Interpreter (Execution)
- T1566.001 Phishing: Spearphishing Attachment (Initial Access)
