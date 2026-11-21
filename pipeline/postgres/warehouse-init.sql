-- SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
-- Copyright (c) 2026 Utsha Basak
-- Prepares the database server for the stage containers, dbt, Grafana and Airflow. Run by the
-- warehouse-init service on every 'prohori pipeline up' as the superuser (prohori); every
-- statement is idempotent, so it also upgrades a database created by an earlier version.
--   psql --set=app_password=... --set=reader_password=... --set=airflow_password=...
--        --file=warehouse-init.sql

SET client_min_messages = warning;  -- no "already exists, skipping" notices on every start

-- The application role: the stages, dbt and Airflow's jobs connect as prohori_app, which owns
-- the warehouse schemas and nothing else. It cannot create roles or databases, bypass row
-- security, replicate, or run server programs (COPY ... TO PROGRAM needs superuser or
-- pg_execute_server_program, which it is never granted).
SELECT 'CREATE ROLE prohori_app LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'prohori_app') \gexec
ALTER ROLE prohori_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
GRANT CONNECT, TEMPORARY ON DATABASE prohori TO prohori_app;
-- CREATE on the database only lets it create schemas, which the sink and dbt ask for with
-- CREATE SCHEMA IF NOT EXISTS (PostgreSQL checks the privilege even when the schema exists).
GRANT CREATE ON DATABASE prohori TO prohori_app;

-- The schemas: raw (the sink), staging, intermediate and marts (dbt), analytics (dbt's default).
CREATE SCHEMA IF NOT EXISTS raw AUTHORIZATION prohori_app;
CREATE SCHEMA IF NOT EXISTS staging AUTHORIZATION prohori_app;
CREATE SCHEMA IF NOT EXISTS intermediate AUTHORIZATION prohori_app;
CREATE SCHEMA IF NOT EXISTS marts AUTHORIZATION prohori_app;
CREATE SCHEMA IF NOT EXISTS analytics AUTHORIZATION prohori_app;

-- A stack created before 1.1 kept everything as the superuser: hand the schemas, and every
-- table, view and sequence in them, to prohori_app (indexes follow their tables).
DO $migrate$
DECLARE
    item record;
BEGIN
    FOR item IN
        SELECT nspname FROM pg_namespace
        WHERE nspname IN ('raw', 'staging', 'intermediate', 'marts', 'analytics')
          AND pg_get_userbyid(nspowner) <> 'prohori_app'
    LOOP
        EXECUTE format('ALTER SCHEMA %I OWNER TO prohori_app', item.nspname);
    END LOOP;
    FOR item IN
        SELECT n.nspname, c.relname, c.relkind
        FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('raw', 'staging', 'intermediate', 'marts', 'analytics')
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
          AND pg_get_userbyid(c.relowner) <> 'prohori_app'
          -- a sequence owned by a column moves with its table
          AND NOT (c.relkind = 'S' AND EXISTS (
              SELECT FROM pg_depend AS d
              WHERE d.objid = c.oid AND d.classid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
          ))
    LOOP
        EXECUTE format(
            'ALTER %s %I.%I OWNER TO prohori_app',
            CASE item.relkind
                WHEN 'v' THEN 'VIEW'
                WHEN 'm' THEN 'MATERIALIZED VIEW'
                WHEN 'S' THEN 'SEQUENCE'
                ELSE 'TABLE'
            END,
            item.nspname,
            item.relname
        );
    END LOOP;
END
$migrate$;

-- Grafana reads with its own login, which can only SELECT from raw and marts.
SELECT 'CREATE ROLE grafana LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana') \gexec
ALTER ROLE grafana WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'reader_password';
-- Anyone who can open the dashboards can run a query through this role, so it is bounded: a
-- query stops after 15 seconds, at most five connections, and every transaction is read-only.
ALTER ROLE grafana CONNECTION LIMIT 5;
ALTER ROLE grafana SET statement_timeout = '15s';
ALTER ROLE grafana SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE prohori TO grafana;
GRANT USAGE ON SCHEMA raw, marts TO grafana;
GRANT SELECT ON ALL TABLES IN SCHEMA raw, marts TO grafana;
-- dbt replaces the mart tables on every build: grant on the tables created later too, by the
-- application role (and by the superuser, for a stack created before 1.1).
ALTER DEFAULT PRIVILEGES FOR ROLE prohori_app IN SCHEMA raw, marts GRANT SELECT ON TABLES TO grafana;
ALTER DEFAULT PRIVILEGES FOR ROLE prohori IN SCHEMA raw, marts GRANT SELECT ON TABLES TO grafana;

-- Airflow (the orchestration profile) keeps its own state in a separate database it owns.
SELECT 'CREATE ROLE airflow LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'airflow') \gexec
ALTER ROLE airflow WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'airflow_password';
SELECT 'CREATE DATABASE airflow OWNER airflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'airflow') \gexec
-- Only Airflow (and the superuser) may connect to it.
REVOKE CONNECT ON DATABASE airflow FROM PUBLIC;
