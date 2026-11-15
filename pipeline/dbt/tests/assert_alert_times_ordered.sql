-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- An alert ends no earlier than it starts.
select alert_id, first_seen, last_seen
from {{ ref('stg_alerts') }}
where last_seen < first_seen
