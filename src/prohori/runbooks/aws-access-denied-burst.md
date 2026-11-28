# Many AWS calls denied for one identity

**Rules:** PRH-AWS-007

## What it means

One identity (user or role session, `user.id`) had many different API calls denied in a few
minutes. Someone with new credentials, often stolen access keys, is finding out what they may do:
listing users, roles, buckets, instances and secrets one service after another, by hand or with
an enumeration tool.

## Triage

1. Which identity (`user.id`), from where (`source.ip`) and with which program (`user_agent`:
   a CLI or SDK on an unfamiliar host is suspicious)?
2. Which calls were denied, and which were allowed? The allowed ones show what the caller learnt
   or did.
3. Is it a long-term key (`extra.access_key_type`)? When and by whom was it created?

## Recommended actions

- If the use is not explained: deactivate the access key or revoke the role's sessions, and find
  out where the credentials leaked (code repositories, CI logs, a laptop).
- Review the allowed calls and anything they changed.

## False positives

- A person exploring the console with a role that allows little (each page makes several calls).
- A new deployment tool run with too narrow a policy.

## ATT&CK

- T1580 Cloud Infrastructure Discovery (Discovery)
- T1087.004 Account Discovery: Cloud Account (Discovery)
