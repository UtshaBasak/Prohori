-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
select
    id as event_id,
    source,
    line,
    scenario,
    attack_id,
    attack_id is not null as is_attack
from {{ source('prohori', 'labels') }}
