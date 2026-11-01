-- Per rule: how long activity ran before it fired, and how long the pipeline took.
select
    detector_id,
    count(*) as alerts,
    percentile_cont(0.5) within group (order by activity_seconds) as median_activity_seconds,
    max(activity_seconds) as max_activity_seconds,
    percentile_cont(0.5) within group (order by pipeline_seconds) as median_pipeline_seconds,
    max(pipeline_seconds) as max_pipeline_seconds
from {{ ref('alert_latency') }}
group by detector_id
