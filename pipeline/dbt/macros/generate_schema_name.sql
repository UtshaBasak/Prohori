{#- Use the configured schema name as it is (staging, intermediate, marts), not prefixed with the
    target schema, so the same names exist in DuckDB and PostgreSQL. -#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {%- if custom_schema_name is none -%}
        {{ target.schema }}
    {%- else -%}
        {{ custom_schema_name | trim }}
    {%- endif -%}
{%- endmacro %}
