-- The alerts grouped into each incident.
select
    id as incident_id,
    {{ json_array_text('record', 'alerts', 'id') }} as alert_id
from {{ source('prohori', 'incidents') }}
