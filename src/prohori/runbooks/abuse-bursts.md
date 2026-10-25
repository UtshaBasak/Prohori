# Rate-limit bursts and bot-check failures

**Rules:** PRH-ABUSE-001

## What it means

One source IP kept hitting the rate limiter or failing the bot check (Turnstile). The protections
are working, but something automated is pushing hard: scraping, credential stuffing behind the bot
check, or an attempt to exhaust the service.

## Triage

1. Check which routes were rate-limited or protected: sign-in and password reset suggest account
   attacks, catalogue routes suggest scraping.
2. Check whether the same IP also appears in sign-in failures (PRH-AUTH-001, PRH-AUTH-002).
3. Look up the IP: hosting provider, proxy network, or a mobile carrier gateway shared by many
   users.
4. Check service health: response times and error rates during the burst.

## Recommended actions

- Block or challenge the IP at the reverse proxy or CDN if it is not a shared gateway.
- Tighten rate limits on the targeted routes if the burst got through before limiting started.
- If sign-in routes were targeted, review recent successful sign-ins from the IP.

## False positives

- A busy shared NAT or proxy, such as a mobile carrier gateway.
- A misbehaving client release retrying too fast.
- Monitoring or load tests run by the site's own team.

## ATT&CK

- T1499.002 Endpoint Denial of Service: Service Exhaustion Flood (Impact)
