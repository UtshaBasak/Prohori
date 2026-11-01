-- The events behind each alert (an alert lists at most 100 event ids).
select
    id as alert_id,
    {{ json_array_text('record', 'event_ids') }} as event_id
from {{ source('prohori', 'alerts') }}
