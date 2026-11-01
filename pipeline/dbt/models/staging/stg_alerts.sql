select
    id as alert_id,
    detector_id,
    detector_kind,
    severity,
    first_seen,
    last_seen,
    {{ utc_date('last_seen') }} as alert_date,
    title,
    event_count,
    stored_at
from {{ source('prohori', 'alerts') }}
