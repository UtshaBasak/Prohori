-- event_count matches the event ids the alert lists.
select a.alert_id, a.event_count, count(ae.event_id) as listed
from {{ ref('stg_alerts') }} as a
left join {{ ref('stg_alert_events') }} as ae on ae.alert_id = a.alert_id
group by a.alert_id, a.event_count
having count(ae.event_id) <> a.event_count
