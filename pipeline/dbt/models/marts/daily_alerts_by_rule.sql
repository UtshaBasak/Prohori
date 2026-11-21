-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- Per UTC day and rule: how many alerts it raised, and how many of them were suppressed.
select
    alert_date as day,
    detector_id,
    detector_kind,
    severity,
    sum(case when suppression_id is null then 1 else 0 end) as alerts,
    sum(case when suppression_id is null then 0 else 1 end) as suppressed_alerts
from {{ ref('stg_alerts') }}
group by alert_date, detector_id, detector_kind, severity
