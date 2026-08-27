#!/bin/sh

set -eu

backup_directory=${KOVCHEG_BACKUP_DIRECTORY:-/backup}
restore_database=${KOVCHEG_RESTORE_DATABASE:-kovcheg_restore_smoke}

case "$restore_database" in
  kovcheg_restore_*) ;;
  *) echo 'Restore smoke database must use the disposable kovcheg_restore_ prefix.' >&2; exit 1 ;;
esac
if [ ! -s "${PGPASSWORD_FILE:-}" ]; then
  echo 'PostgreSQL password file is required for restore smoke.' >&2
  exit 1
fi

backup_name=${KOVCHEG_RESTORE_BACKUP_FILE:-}
if [ -z "$backup_name" ]; then
  backup_name=$(find "$backup_directory" -maxdepth 1 -type f -name 'kovcheg-*.dump' -print \
    | sort | tail -n 1 | sed 's#^.*/##')
fi
case "$backup_name" in
  kovcheg-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.dump) ;;
  *) echo 'A verified local backup filename is required.' >&2; exit 1 ;;
esac

backup_path="$backup_directory/$backup_name"
test -s "$backup_path"
test -s "$backup_path.sha256"
(
  cd "$backup_directory"
  sha256sum --check --status "$backup_name.sha256"
)
pg_restore --list "$backup_path" >/dev/null

PGPASSWORD=$(tr -d '\r\n' <"$PGPASSWORD_FILE")
export PGPASSWORD
cleanup() {
  dropdb --if-exists "$restore_database" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup
createdb "$restore_database"
pg_restore --exit-on-error --no-owner --no-privileges --dbname="$restore_database" "$backup_path"
recorded_version=$(psql --no-psqlrc --tuples-only --no-align --dbname="$restore_database" \
  --command='SELECT max(version) FROM kovcheg_meta.schema_migrations')
if [ -z "$recorded_version" ]; then
  echo 'Restored database does not contain migration provenance.' >&2
  exit 1
fi
cleanup
trap - EXIT INT TERM
unset PGPASSWORD recorded_version
printf 'Local restore smoke passed for %s.\n' "$backup_name"
