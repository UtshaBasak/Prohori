-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
select
    id as alert_id,
    detector_id,
    detector_kind,
    severity,
    first_seen,
    last_seen,
    {{ utc_date('last_seen') }} as alert_date,
    title,
    event_count,
    -- The suppression entry that silenced the alert (null for an alert an analyst sees).
    {{ json_text('record', 'suppression', 'id') }} as suppression_id,
    stored_at
from {{ source('prohori', 'alerts') }}
