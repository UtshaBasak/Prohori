-- How long each incident lasted, from its first to its last alert.
with rules as (
    select
        ia.incident_id,
        count(distinct a.detector_id) as rules
    from {{ ref('stg_incident_alerts') }} as ia
    inner join {{ ref('stg_alerts') }} as a on a.alert_id = ia.alert_id
    group by ia.incident_id
)

select
    i.incident_id,
    i.severity,
    i.confidence,
    i.score,
    i.first_seen,
    i.last_seen,
    i.duration_seconds,
    i.alert_count,
    coalesce(r.rules, 0) as rules,
    i.title
from {{ ref('stg_incidents') }} as i
left join rules as r on r.incident_id = i.incident_id
