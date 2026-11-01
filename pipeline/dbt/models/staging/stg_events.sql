select
    id as event_id,
    timestamp as event_at,
    {{ utc_date('timestamp') }} as event_date,
    log_source,
    action,
    category,
    outcome,
    source_ip,
    user_name,
    http_status,
    stored_at
from {{ source('prohori', 'events') }}
