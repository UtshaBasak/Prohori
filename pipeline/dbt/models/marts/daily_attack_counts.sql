-- Per UTC day: events, failures, alerts, incidents.
with events as (
    select
        event_date as day,
        count(*) as events,
        sum(case when outcome = 'failure' then 1 else 0 end) as failed_events,
        count(distinct source_ip) as source_ips
    from {{ ref('stg_events') }}
    group by event_date
),

alerts as (
    select
        alert_date as day,
        count(*) as alerts,
        sum(case when severity in ('high', 'critical') then 1 else 0 end) as high_alerts,
        count(distinct detector_id) as rules_fired
    from {{ ref('stg_alerts') }}
    group by alert_date
),

incidents as (
    select
        incident_date as day,
        count(*) as incidents,
        sum(case when severity in ('high', 'critical') then 1 else 0 end) as high_incidents
    from {{ ref('stg_incidents') }}
    group by incident_date
),

days as (
    select day from events
    union
    select day from alerts
    union
    select day from incidents
)

select
    d.day,
    coalesce(e.events, 0) as events,
    coalesce(e.failed_events, 0) as failed_events,
    coalesce(e.source_ips, 0) as source_ips,
    coalesce(a.alerts, 0) as alerts,
    coalesce(a.high_alerts, 0) as high_alerts,
    coalesce(a.rules_fired, 0) as rules_fired,
    coalesce(i.incidents, 0) as incidents,
    coalesce(i.high_incidents, 0) as high_incidents
from days as d
left join events as e on e.day = d.day
left join alerts as a on a.day = d.day
left join incidents as i on i.day = d.day
