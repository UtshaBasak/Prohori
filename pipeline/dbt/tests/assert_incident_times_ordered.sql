-- An incident ends no earlier than it starts.
select incident_id, first_seen, last_seen
from {{ ref('stg_incidents') }}
where last_seen < first_seen
