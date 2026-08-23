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

create_json_secret() {
  secret_path=$1
  node_expression=$2
  if [ ! -s "$secret_path" ]; then
    chmod 0600 "$secret_path" 2>/dev/null || true
    node --input-type=module -e "$node_expression" >"$secret_path"
  fi
  chmod 0444 "$secret_path"
}

create_secret "$secret_directory/audit"
create_secret "$secret_directory/auth"
create_secret "$secret_directory/migration"
create_secret "$secret_directory/runtime"
create_secret "$secret_directory/superuser"
create_secret "$secret_directory/realtime-relay"
create_secret "$secret_directory/auth-challenge-pepper"
create_secret "$secret_directory/auth-rate-limit-pepper"
create_secret "$secret_directory/auth-session-pepper"
create_secret "$secret_directory/resend-api-key"
create_json_secret "$secret_directory/auth-oidc-cookie-keys" \
  "import {randomBytes} from 'node:crypto'; process.stdout.write(JSON.stringify([randomBytes(32).toString('base64url'),randomBytes(32).toString('base64url')]))"
create_json_secret "$secret_directory/auth-oidc-jwks" \
  "import {generateKeyPairSync} from 'node:crypto'; const {privateKey}=generateKeyPairSync('ec',{namedCurve:'P-256'}); const key=privateKey.export({format:'jwk'}); process.stdout.write(JSON.stringify({keys:[{...key,alg:'ES256',kid:'local-signing-key',use:'sig'}]}))"

export KOVCHEG_POSTGRES_AUDIT_PASSWORD_FILE="$secret_directory/audit"
export KOVCHEG_POSTGRES_AUTH_PASSWORD_FILE="$secret_directory/auth"
export KOVCHEG_POSTGRES_MIGRATION_PASSWORD_FILE="$secret_directory/migration"
export KOVCHEG_POSTGRES_RUNTIME_PASSWORD_FILE="$secret_directory/runtime"
export KOVCHEG_POSTGRES_SUPERUSER_PASSWORD_FILE="$secret_directory/superuser"
export KOVCHEG_REALTIME_RELAY_TOKEN_FILE="$secret_directory/realtime-relay"
export KOVCHEG_AUTH_CHALLENGE_PEPPER_FILE="$secret_directory/auth-challenge-pepper"
export KOVCHEG_AUTH_RATE_LIMIT_PEPPER_FILE="$secret_directory/auth-rate-limit-pepper"
export KOVCHEG_AUTH_SESSION_PEPPER_FILE="$secret_directory/auth-session-pepper"
export KOVCHEG_AUTH_OIDC_COOKIE_KEYS_FILE="$secret_directory/auth-oidc-cookie-keys"
export KOVCHEG_AUTH_OIDC_JWKS_FILE="$secret_directory/auth-oidc-jwks"
export KOVCHEG_RESEND_API_KEY_FILE="$secret_directory/resend-api-key"

if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@"
fi

exec docker-compose "$@"
