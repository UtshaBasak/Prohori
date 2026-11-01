{#- No timestamp more than slack_days after now: a clock or parsing problem. -#}
{% test not_in_future(model, column_name, slack_days=1) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} > {{ dbt.dateadd('day', slack_days, dbt.current_timestamp()) }}
{% endtest %}
