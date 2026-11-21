-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- Per rule: alerts, and how many were true positives against the simulator's labels.
-- precision is null for a rule none of whose alerts could be judged (real logs have no labels).
-- Suppressed alerts are left out (what an analyst sees); suppressed_alerts counts them.
with seen as (
    select
        *,
        case when is_suppressed then 0 else 1 end as shown
    from {{ ref('int_alert_judgements') }}
)

select
    detector_id,
    sum(shown) as alerts,
    sum(case when is_judged then shown else 0 end) as judged_alerts,
    sum(case when is_true_positive then shown else 0 end) as true_positives,
    sum(case when is_judged and not is_true_positive then shown else 0 end) as false_positives,
    {{ ratio(
        'sum(case when is_true_positive then shown else 0 end)',
        'sum(case when is_judged then shown else 0 end)'
    ) }} as precision,
    count(*) - sum(shown) as suppressed_alerts
from seen
group by detector_id
