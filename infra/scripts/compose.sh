#!/bin/sh

set -eu

compose_project=${COMPOSE_PROJECT_NAME:-kovcheg-local}
secret_directory=${KOVCHEG_LOCAL_SECRET_DIR:-$PWD/.local/postgres-${compose_project}}

case "$compose_project" in
  *[!a-zA-Z0-9_-]* | '')
    echo 'COMPOSE_PROJECT_NAME must contain only letters, digits, underscores, and hyphens.' >&2
    exit 1
    ;;
esac

umask 077
mkdir -p "$secret_directory"
chmod 0700 "$secret_directory"

create_secret() {
  secret_path=$1
  if [ ! -s "$secret_path" ]; then
    chmod 0600 "$secret_path" 2>/dev/null || true
    node --input-type=module -e "import {randomBytes} from 'node:crypto'; process.stdout.write(randomBytes(32).toString('hex'))" >"$secret_path"
  fi
  # The owner-only parent protects the host path; read-only files let non-root container users read explicitly mounted secrets.
  chmod 0444 "$secret_path"
}

create_secret "$secret_directory/audit"
create_secret "$secret_directory/auth"
create_secret "$secret_directory/migration"
create_secret "$secret_directory/runtime"
create_secret "$secret_directory/superuser"

export KOVCHEG_POSTGRES_AUDIT_PASSWORD_FILE="$secret_directory/audit"
export KOVCHEG_POSTGRES_AUTH_PASSWORD_FILE="$secret_directory/auth"
export KOVCHEG_POSTGRES_MIGRATION_PASSWORD_FILE="$secret_directory/migration"
export KOVCHEG_POSTGRES_RUNTIME_PASSWORD_FILE="$secret_directory/runtime"
export KOVCHEG_POSTGRES_SUPERUSER_PASSWORD_FILE="$secret_directory/superuser"

if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@"
fi

exec docker-compose "$@"
