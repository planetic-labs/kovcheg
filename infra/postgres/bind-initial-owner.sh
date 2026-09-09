#!/bin/sh

# The input is private contact data, not shell arguments or SQL text.
set +x
set -eu

reject() {
  echo 'INITIAL_OWNER_BINDING_UNCONFIRMED' >&2
  exit 1
}

[ "$#" -eq 0 ] || reject
[ "${PGUSER:-}" = kovcheg_migrator ] || reject
# libpq may use an externally mounted PGPASSFILE. Do not copy its value into env.
[ "${PGPASSWORD+x}" != x ] || reject
[ -z "${PGOPTIONS:-}" ] || reject
[ -z "${PGSERVICE:-}" ] || reject

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
export PGAPPNAME=initial-owner-binding

# COPY data is sent separately from SQL. Base64 prevents input from introducing
# psql metacommands. No input, database error, or provider detail is echoed.
# A lost connection may occur after COMMIT: failure is deliberately UNCONFIRMED.
if result=$(
  {
    printf '%s\n' '\set ON_ERROR_STOP on' '\set VERBOSITY terse' \
      'BEGIN;' 'SET LOCAL ROLE kovcheg_migration;' \
      "SET LOCAL lock_timeout = '5s';" "SET LOCAL statement_timeout = '30s';" \
      'CREATE TEMP TABLE owner_binding_input (encoded text NOT NULL);' \
      'COPY owner_binding_input FROM STDIN;'
    head -c 16385 | base64 | tr -d '\r\n'
    printf '\n%s\n' '\.'
    cat "$script_directory/bind-initial-owner.sql"
  } | psql --no-psqlrc --no-password --quiet --tuples-only --no-align 2>/dev/null
); then
  case "$result" in
    BOUND | ALREADY_BOUND) printf '%s\n' "$result" ;;
    *) reject ;;
  esac
else
  reject
fi
unset result
