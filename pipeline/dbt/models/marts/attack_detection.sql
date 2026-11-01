-- Per simulated attack: when it started, whether a true-positive alert was credited to it,
-- and how long that took (time to detect, in log time).
with attacks as (
    select
        l.scenario,
        l.attack_id,
        min(e.event_at) as started_at,
        max(e.event_at) as ended_at,
        count(*) as attack_events
    from {{ ref('stg_labels') }} as l
    inner join {{ ref('stg_events') }} as e on e.event_id = l.event_id
    where l.is_attack
    group by l.scenario, l.attack_id
),

detections as (
    select
        credited_attack as attack_id,
        min(last_seen) as first_detected_at,
        count(*) as alerts,
        count(distinct detector_id) as rules
    from {{ ref('int_alert_judgements') }}
    where is_true_positive and credited_attack is not null
    group by credited_attack
)

select
    a.scenario,
    a.attack_id,
    a.started_at,
    a.ended_at,
    a.attack_events,
    d.first_detected_at is not null as detected,
    d.first_detected_at,
    {{ seconds_between('a.started_at', 'd.first_detected_at') }} as time_to_detect_seconds,
    coalesce(d.alerts, 0) as alerts,
    coalesce(d.rules, 0) as rules
from attacks as a
left join detections as d on d.attack_id = a.attack_id
