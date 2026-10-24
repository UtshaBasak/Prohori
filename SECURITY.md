# Security Policy

## Supported versions

Prohori is pre-release software. Security fixes are applied to the latest release only.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/UtshaBasak/Prohori/security/advisories/new).
Include the affected version, a description of the impact and a minimal reproduction using
synthetic data. You should receive an acknowledgement within 7 days.

## Scope

Prohori processes untrusted input (log files, rule files, datasets, third-party API responses).
In-scope issues include, for example:

- Code execution, path traversal or resource exhaustion triggered by crafted logs, rules or datasets.
- Injection into generated reports (HTML, Markdown, CSV).
- Leakage of API keys or other secrets into output, logs or caches.
- Prompt injection that makes the optional LLM analyst misreport an incident.

A full threat model will be published in `docs/THREAT_MODEL.md`.

## Intended use

Prohori is a defensive tool. It contains no exploit code and its simulator writes log files only.
