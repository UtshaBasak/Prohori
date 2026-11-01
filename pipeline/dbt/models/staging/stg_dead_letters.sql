select
    id as dead_letter_id,
    stage,
    topic,
    key,
    reason,
    stored_at
from {{ source('prohori', 'dead_letters') }}
