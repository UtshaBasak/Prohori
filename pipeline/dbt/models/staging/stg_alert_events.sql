-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- The events behind each alert (an alert lists at most 100 event ids).
select
    id as alert_id,
    {{ json_array_text('record', 'event_ids') }} as event_id
from {{ source('prohori', 'alerts') }}
