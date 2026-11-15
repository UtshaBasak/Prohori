-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
select
    id as dead_letter_id,
    stage,
    topic,
    key,
    reason,
    stored_at
from {{ source('prohori', 'dead_letters') }}
