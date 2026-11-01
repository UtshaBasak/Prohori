-- Each alert judged against the simulator's labels, as the rule evaluation does
-- (docs/SIMULATOR.md): a true positive when at least half of its labelled events are attack
-- events, credited to the attack most of them belong to. Alerts without labelled events are
-- not judged.
with alert_labels as (
    select
        ae.alert_id,
        l.event_id as labelled_event,
        l.attack_id
    from {{ ref('stg_alert_events') }} as ae
    inner join {{ ref('stg_labels') }} as l on l.event_id = ae.event_id
),

counts as (
    select
        alert_id,
        count(*) as labelled_events,
        count(attack_id) as attack_events
    from alert_labels
    group by alert_id
),

attack_votes as (
    select
        alert_id,
        attack_id,
        row_number() over (
            partition by alert_id order by count(*) desc, attack_id
        ) as vote
    from alert_labels
    where attack_id is not null
    group by alert_id, attack_id
)

select
    a.alert_id,
    a.detector_id,
    a.last_seen,
    coalesce(c.labelled_events, 0) as labelled_events,
    coalesce(c.attack_events, 0) as attack_events,
    coalesce(c.labelled_events, 0) > 0 as is_judged,
    coalesce(c.labelled_events, 0) > 0 and c.attack_events * 2 >= c.labelled_events
        as is_true_positive,
    case when c.attack_events * 2 >= c.labelled_events then v.attack_id end as credited_attack
from {{ ref('stg_alerts') }} as a
left join counts as c on c.alert_id = a.alert_id
left join attack_votes as v on v.alert_id = a.alert_id and v.vote = 1
