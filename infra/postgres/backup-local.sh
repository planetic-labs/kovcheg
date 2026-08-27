#!/bin/sh

set -eu

backup_directory=${KOVCHEG_BACKUP_DIRECTORY:-/backup}
retention_days=${KOVCHEG_BACKUP_RETENTION_DAYS:-7}

case "$retention_days" in
  '' | *[!0-9]*) echo 'Backup retention must be a positive number of days.' >&2; exit 1 ;;
esac
if [ "$retention_days" -lt 1 ] || [ ! -s "${PGPASSWORD_FILE:-}" ]; then
  echo 'Backup retention and PostgreSQL password file are required.' >&2
  exit 1
fi

umask 077
mkdir -p "$backup_directory"
temporary_backup=$(mktemp "$backup_directory/.pending.XXXXXX")
cleanup() {
  rm -f "$temporary_backup"
}
trap cleanup EXIT INT TERM

PGPASSWORD=$(tr -d '\r\n' <"$PGPASSWORD_FILE")
export PGPASSWORD
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
backup_name="kovcheg-$timestamp.dump"
backup_path="$backup_directory/$backup_name"

pg_dump --format=custom --file="$temporary_backup"
pg_restore --list "$temporary_backup" >/dev/null
mv "$temporary_backup" "$backup_path"
checksum=$(sha256sum "$backup_path" | awk '{print $1}')
printf '%s  %s\n' "$checksum" "$backup_name" >"$backup_path.sha256"

find "$backup_directory" -type f \
  \( -name 'kovcheg-*.dump' -o -name 'kovcheg-*.dump.sha256' \) \
  -mtime "+$retention_days" -delete

unset PGPASSWORD checksum
trap - EXIT INT TERM
printf 'Local backup created and verified: %s\n' "$backup_name"
