-- alert_count matches the alerts the incident holds, and every one of them was stored.
select i.incident_id, i.alert_count, count(a.alert_id) as stored
from {{ ref('stg_incidents') }} as i
left join {{ ref('stg_incident_alerts') }} as ia on ia.incident_id = i.incident_id
left join {{ ref('stg_alerts') }} as a on a.alert_id = ia.alert_id
group by i.incident_id, i.alert_count
having count(a.alert_id) <> i.alert_count
