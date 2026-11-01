select
    id as incident_id,
    severity,
    score,
    confidence,
    first_seen,
    last_seen,
    {{ utc_date('first_seen') }} as incident_date,
    {{ seconds_between('first_seen', 'last_seen') }} as duration_seconds,
    title,
    alert_count,
    stored_at
from {{ source('prohori', 'incidents') }}
