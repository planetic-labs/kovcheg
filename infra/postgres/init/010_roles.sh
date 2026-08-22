#!/bin/sh

set -eu

read_secret() {
  secret_value=$(tr -d '\r\n' <"$1")
  if [ -z "$secret_value" ]; then
    echo 'A PostgreSQL role secret is empty.' >&2
    exit 1
  fi
  printf '%s' "$secret_value"
}

migration_password=$(read_secret /run/secrets/postgres_migration_password)
runtime_password=$(read_secret /run/secrets/postgres_runtime_password)
audit_password=$(read_secret /run/secrets/postgres_audit_password)

psql --set=ON_ERROR_STOP=1 \
  --set=migration_password="$migration_password" \
  --set=runtime_password="$runtime_password" \
  --set=audit_password="$audit_password" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
SET password_encryption = 'scram-sha-256';

SELECT 'CREATE ROLE kovcheg_migration NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_migration')
\gexec
SELECT 'CREATE ROLE kovcheg_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_runtime')
\gexec
SELECT 'CREATE ROLE kovcheg_audit NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_audit')
\gexec

SELECT 'CREATE ROLE kovcheg_migrator LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_migrator')
\gexec
SELECT 'CREATE ROLE kovcheg_app LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_app')
\gexec
SELECT 'CREATE ROLE kovcheg_audit_writer LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kovcheg_audit_writer')
\gexec

SELECT format('ALTER ROLE kovcheg_migrator PASSWORD %L', :'migration_password')
\gexec
SELECT format('ALTER ROLE kovcheg_app PASSWORD %L', :'runtime_password')
\gexec
SELECT format('ALTER ROLE kovcheg_audit_writer PASSWORD %L', :'audit_password')
\gexec

GRANT kovcheg_migration TO kovcheg_migrator;
GRANT kovcheg_runtime TO kovcheg_app;
GRANT kovcheg_audit TO kovcheg_audit_writer;

REVOKE CONNECT ON DATABASE kovcheg FROM PUBLIC;
GRANT CONNECT ON DATABASE kovcheg TO kovcheg_migration, kovcheg_runtime, kovcheg_audit;
GRANT CREATE ON DATABASE kovcheg TO kovcheg_migration;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

unset migration_password runtime_password audit_password secret_value
