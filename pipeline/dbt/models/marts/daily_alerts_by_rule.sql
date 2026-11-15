-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- Per UTC day and rule: how many alerts it raised.
select
    alert_date as day,
    detector_id,
    detector_kind,
    severity,
    count(*) as alerts
from {{ ref('stg_alerts') }}
group by alert_date, detector_id, detector_kind, severity
