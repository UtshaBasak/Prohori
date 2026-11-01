-- An alert ends no earlier than it starts.
select alert_id, first_seen, last_seen
from {{ ref('stg_alerts') }}
where last_seen < first_seen
