-- Per rule: alerts, and how many were true positives against the simulator's labels.
-- precision is null for a rule none of whose alerts could be judged (real logs have no labels).
select
    detector_id,
    count(*) as alerts,
    sum(case when is_judged then 1 else 0 end) as judged_alerts,
    sum(case when is_true_positive then 1 else 0 end) as true_positives,
    sum(case when is_judged and not is_true_positive then 1 else 0 end) as false_positives,
    {{ ratio(
        'sum(case when is_true_positive then 1 else 0 end)',
        'sum(case when is_judged then 1 else 0 end)'
    ) }} as precision
from {{ ref('int_alert_judgements') }}
group by detector_id
