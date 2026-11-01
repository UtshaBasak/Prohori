-- Prepares the database server for the stage containers, Grafana and Airflow. Run by the
-- warehouse-init service on every 'prohori pipeline up' as the prohori user; every statement is
-- idempotent.
--   psql --set=reader_password=... --set=airflow_password=... --file=warehouse-init.sql

-- The schemas the sink and the dbt marts write to (owned by prohori).
CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS marts;

-- Grafana reads with its own login, which can only SELECT from raw and marts.
SELECT 'CREATE ROLE grafana LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana') \gexec
ALTER ROLE grafana WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'reader_password';
GRANT CONNECT ON DATABASE prohori TO grafana;
GRANT USAGE ON SCHEMA raw, marts TO grafana;
GRANT SELECT ON ALL TABLES IN SCHEMA raw, marts TO grafana;
-- dbt replaces the mart tables on every build: grant on the tables prohori creates later too.
ALTER DEFAULT PRIVILEGES FOR ROLE prohori IN SCHEMA raw, marts GRANT SELECT ON TABLES TO grafana;

-- Airflow (the orchestration profile) keeps its own state in a separate database it owns.
SELECT 'CREATE ROLE airflow LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'airflow') \gexec
ALTER ROLE airflow WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'airflow_password';
SELECT 'CREATE DATABASE airflow OWNER airflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'airflow') \gexec
