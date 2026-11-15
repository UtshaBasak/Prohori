-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- The alerts grouped into each incident.
select
    id as incident_id,
    {{ json_array_text('record', 'alerts', 'id') }} as alert_id
from {{ source('prohori', 'incidents') }}
