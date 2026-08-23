#!/bin/sh

set -eu

if [ ! -s "${PGPASSWORD_FILE:-}" ]; then
  echo 'PGPASSWORD_FILE must point to a non-empty migration secret.' >&2
  exit 1
fi

PGPASSWORD=$(tr -d '\r\n' <"$PGPASSWORD_FILE")
export PGPASSWORD

psql --no-psqlrc --set=ON_ERROR_STOP=1 <<'SQL'
BEGIN;
SET ROLE kovcheg_migration;

INSERT INTO kovcheg.oidc_clients (
  client_id,
  allowed_scope,
  grant_type,
  pkce_required,
  token_endpoint_auth_method
) VALUES (
  'kovcheg-local',
  'openid',
  'authorization_code',
  true,
  'none'
)
ON CONFLICT (client_id) DO UPDATE SET
  allowed_scope = EXCLUDED.allowed_scope,
  grant_type = EXCLUDED.grant_type,
  pkce_required = EXCLUDED.pkce_required,
  token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method;

DELETE FROM kovcheg.oidc_client_redirect_uris
WHERE client_id = 'kovcheg-local';

INSERT INTO kovcheg.oidc_client_redirect_uris (client_id, redirect_uri)
VALUES ('kovcheg-local', 'https://client.invalid/auth/callback');

COMMIT;
SQL

unset PGPASSWORD

echo 'Synthetic local OIDC client configuration is current.'
