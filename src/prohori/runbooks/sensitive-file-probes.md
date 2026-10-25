# Probes for sensitive files and admin tools

**Rules:** PRH-WEB-004

## What it means

One source IP asked for several well-known sensitive paths such as `/.env`, `/.git/`,
`/wp-login.php` or `/phpmyadmin`. Automated scanners try these on every site. The probe itself is
routine; a successful response is a serious exposure.

## Triage

1. Check the response status of every probed path. A 200 for `/.env`, `/.git/` or a backup file
   means secrets or source code may have leaked.
2. Check whether the site really runs the probed software (WordPress, phpMyAdmin).
3. Look for other requests from the IP (PRH-WEB-001, PRH-WEB-002).

## Recommended actions

- If any probe succeeded: remove the file from the web root, rotate every secret it contained
  (database passwords, API keys), and review access logs for other downloads of it.
- Deny access to dot-files and backups in the web server configuration.
- Block the IP if probing continues.

## False positives

- The site's own security scanner.
- Sites that really run WordPress or phpMyAdmin, where admins visit these paths.

## ATT&CK

- T1595.003 Active Scanning: Wordlist Scanning (Reconnaissance)
