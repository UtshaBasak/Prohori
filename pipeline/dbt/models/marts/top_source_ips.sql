-- Every source address with its activity, alerts and incidents, ranked by alerts.
with activity as (
    select
        source_ip,
        count(*) as events,
        sum(case when outcome = 'failure' then 1 else 0 end) as failed_events,
        count(distinct user_name) as accounts,
        min(event_at) as first_seen,
        max(event_at) as last_seen
    from {{ ref('stg_events') }}
    where source_ip is not null
    group by source_ip
),

alert_sources as (
    select distinct
        e.source_ip,
        ae.alert_id
    from {{ ref('stg_alert_events') }} as ae
    inner join {{ ref('stg_events') }} as e on e.event_id = ae.event_id
    where e.source_ip is not null
),

alerts as (
    select source_ip, count(*) as alerts
    from alert_sources
    group by source_ip
),

incidents as (
    select
        s.source_ip,
        count(distinct ia.incident_id) as incidents
    from alert_sources as s
    inner join {{ ref('stg_incident_alerts') }} as ia on ia.alert_id = s.alert_id
    group by s.source_ip
)

select
    row_number() over (
        order by coalesce(al.alerts, 0) desc, a.events desc, a.source_ip
    ) as rank,
    a.source_ip,
    a.events,
    a.failed_events,
    a.accounts,
    coalesce(al.alerts, 0) as alerts,
    coalesce(i.incidents, 0) as incidents,
    a.first_seen,
    a.last_seen
from activity as a
left join alerts as al on al.source_ip = a.source_ip
left join incidents as i on i.source_ip = a.source_ip
