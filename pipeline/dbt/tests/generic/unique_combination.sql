{#- Duplicate check over several columns: each combination appears once. -#}
{% test unique_combination(model, columns) %}
select {{ columns | join(', ') }}, count(*) as rows_with_it
from {{ model }}
group by {{ columns | join(', ') }}
having count(*) > 1
{% endtest %}
