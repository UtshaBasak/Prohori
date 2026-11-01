{{ config(severity='warn') }}
-- Rejected messages are kept, not lost, but any at all deserve a look.
select dead_letter_id, stage, topic, reason
from {{ ref('stg_dead_letters') }}
