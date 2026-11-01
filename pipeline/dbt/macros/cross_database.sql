{#- The few expressions that differ between DuckDB and PostgreSQL. -#}

{#- The UTC calendar date of a timestamp with time zone, whatever the session's time zone. -#}
{% macro utc_date(column) -%}
    cast(({{ column }} at time zone 'UTC') as date)
{%- endmacro %}

{#- One row per element of a JSON array of strings (key) or of a field of an array of objects. -#}
{% macro json_array_text(column, key, field=none) -%}
    {{ return(adapter.dispatch('json_array_text')(column, key, field)) }}
{%- endmacro %}

{% macro duckdb__json_array_text(column, key, field) -%}
    {%- if field is none -%}
        unnest(json_extract_string({{ column }}, '$.{{ key }}[*]'))
    {%- else -%}
        unnest(json_extract_string({{ column }}, '$.{{ key }}[*].{{ field }}'))
    {%- endif -%}
{%- endmacro %}

{% macro postgres__json_array_text(column, key, field) -%}
    {%- if field is none -%}
        jsonb_array_elements_text({{ column }} -> '{{ key }}')
    {%- else -%}
        jsonb_array_elements({{ column }} -> '{{ key }}') ->> '{{ field }}'
    {%- endif -%}
{%- endmacro %}

{#- Seconds between two timestamps, as a whole number. -#}
{% macro seconds_between(start, finish) -%}
    {{ dbt.datediff(start, finish, 'second') }}
{%- endmacro %}

{#- A ratio as a double, null when the denominator is 0. -#}
{% macro ratio(numerator, denominator) -%}
    case when {{ denominator }} > 0
        then cast({{ numerator }} as double precision) / {{ denominator }}
    end
{%- endmacro %}
