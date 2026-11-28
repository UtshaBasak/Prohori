# CloudTrail logging stopped

**Rules:** PRH-AWS-006

## What it means

Someone stopped a CloudTrail trail's logging or deleted a trail. Without it, what happens next
in the account is not recorded (Event history still keeps 90 days of management events). This
is a common step right before or after an attacker does something they want to hide. A denied
attempt is reported too.

## Triage

1. Who did it (`user.name`, `source.ip`, `user_agent`) and to which trail (`extra.trail`)?
2. Was it planned? Trail changes are rare.
3. What did the same identity do in the minutes before and after? Use CloudTrail Event history,
   which still records management events.

## Recommended actions

- Start logging again (`StartLogging`) or recreate the trail at once.
- If it was not planned, treat the caller's account as compromised.
- Protect trails: an organisation trail or a service control policy that denies
  `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`, and S3 Object Lock on the log bucket.

## False positives

- Planned removal of an old trail, or a test account being cleaned up.

## ATT&CK

- T1685 Disable or Modify Tools (Defense Impairment)
- T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log (Defense Impairment)
