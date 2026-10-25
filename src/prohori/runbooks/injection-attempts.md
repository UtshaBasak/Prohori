# Injection attempts in request paths

**Rules:** PRH-WEB-002

## What it means

One source IP sent several requests whose path or query string contained SQL injection, path
traversal or cross-site scripting markers. Tools such as sqlmap send these in bulk. An attempt is
not a breach; the question is whether any request succeeded.

## Triage

1. List the matching requests and their response statuses and sizes. A 200 with an unusually large
   response, or a 500 error, deserves a closer look.
2. Check application and database logs at the same times for errors or unexpected queries.
3. Check the user agent: scanner tools often name themselves (see PRH-WEB-003).

## Recommended actions

- Block or rate-limit the IP while you investigate.
- Review the targeted endpoints for parameterised queries, path normalisation and output encoding.
- If a request may have succeeded, treat the affected data as exposed: check for data access and
  rotate credentials the endpoint could reach.
- Consider a web application firewall rule for the targeted endpoints.

## False positives

- Search queries or content that legitimately contain these words, such as a blog post about SQL.
- Security testing by the site's own team.

## ATT&CK

- T1190 Exploit Public-Facing Application (Initial Access)
