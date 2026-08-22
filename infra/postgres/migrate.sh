#!/bin/sh

set -eu

migration_root=${KOVCHEG_MIGRATION_ROOT:-/workspace/infra/postgres/migrations}
migration_target=${MIGRATION_TARGET:-latest}

if [ ! -d "$migration_root" ]; then
  echo 'Migration directory is unavailable.' >&2
  exit 1
fi
if [ ! -s "${PGPASSWORD_FILE:-}" ]; then
  echo 'PGPASSWORD_FILE must point to a non-empty migration secret.' >&2
  exit 1
fi

PGPASSWORD=$(tr -d '\r\n' <"$PGPASSWORD_FILE")
export PGPASSWORD

psql --no-psqlrc --set=ON_ERROR_STOP=1 <<'SQL'
BEGIN;
SET ROLE kovcheg_migration;
CREATE SCHEMA IF NOT EXISTS kovcheg_meta AUTHORIZATION kovcheg_migration;
CREATE TABLE IF NOT EXISTS kovcheg_meta.schema_migrations (
  version text PRIMARY KEY,
  checksum varchar(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  correlation_id varchar(128) NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  applied_by name NOT NULL DEFAULT session_user
);
REVOKE ALL ON SCHEMA kovcheg_meta FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA kovcheg_meta FROM PUBLIC;
COMMIT;
SQL

for migration_file in "$migration_root"/*.sql; do
  migration_name=$(basename "$migration_file" .sql)
  migration_version=${migration_name%%_*}

  case "$migration_name" in
    [0-9][0-9][0-9][0-9]_[a-z0-9_]*) ;;
    *)
      echo 'Migration filenames must use NNNN_lowercase_name.sql.' >&2
      exit 1
      ;;
  esac

  if [ "$migration_target" != 'latest' ] && [ "$migration_version" -gt "$migration_target" ]; then
    continue
  fi

  migration_checksum=$(sha256sum "$migration_file" | awk '{print $1}')
  applied_checksum=$(
    psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT checksum FROM kovcheg_meta.schema_migrations WHERE version = '$migration_version'"
  )

  if [ -n "$applied_checksum" ]; then
    if [ "$applied_checksum" != "$migration_checksum" ]; then
      echo "Migration $migration_version checksum does not match the applied migration." >&2
      exit 1
    fi
    continue
  fi

  migration_correlation_id="migration-${migration_version}-$$"
  psql --no-psqlrc --single-transaction --set=ON_ERROR_STOP=1 \
    --command="SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('kovcheg-schema-migration', 0)); SET ROLE kovcheg_migration" \
    --file="$migration_file" \
    --command="INSERT INTO kovcheg_meta.schema_migrations (version, checksum, correlation_id) VALUES ('$migration_version', '$migration_checksum', '$migration_correlation_id')"
done

unset PGPASSWORD

echo 'PostgreSQL migrations are current.'
