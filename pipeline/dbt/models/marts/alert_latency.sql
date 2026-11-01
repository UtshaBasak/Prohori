-- Per alert, two latencies:
--   activity_seconds: from the first event the alert counts to the event that raised it, in log
--     time (how long the activity ran before the rule fired);
--   pipeline_seconds: from the moment its last event was stored to the moment the alert was
--     stored, in wall-clock time (how long the pipeline took). Batch-granular: 0 when both were
--     written in the same batch.
with stored as (
    select
        ae.alert_id,
        max(e.stored_at) as last_event_stored_at
    from {{ ref('stg_alert_events') }} as ae
    inner join {{ ref('stg_events') }} as e on e.event_id = ae.event_id
    group by ae.alert_id
)

select
    a.alert_id,
    a.detector_id,
    a.severity,
    a.first_seen,
    a.last_seen,
    {{ seconds_between('a.first_seen', 'a.last_seen') }} as activity_seconds,
    greatest({{ seconds_between('s.last_event_stored_at', 'a.stored_at') }}, 0)
        as pipeline_seconds
from {{ ref('stg_alerts') }} as a
left join stored as s on s.alert_id = a.alert_id
