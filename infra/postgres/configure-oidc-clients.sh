#!/bin/sh

set -eu

if [ ! -s "${PGPASSWORD_FILE:-}" ]; then
  echo 'PGPASSWORD_FILE must point to a non-empty migration secret.' >&2
  exit 1
fi
if [ ! -s "${AUTH_OIDC_CLIENTS_JSON_FILE:-}" ]; then
  echo 'AUTH_OIDC_CLIENTS_JSON_FILE must point to a non-empty JSON configuration.' >&2
  exit 1
fi

configuration_size=$(wc -c <"$AUTH_OIDC_CLIENTS_JSON_FILE" | tr -d ' ')
case "$configuration_size" in
  '' | *[!0-9]*)
    echo 'OIDC client configuration size is unavailable.' >&2
    exit 1
    ;;
esac
if [ "$configuration_size" -gt 1048576 ]; then
  echo 'OIDC client configuration exceeds the 1 MiB limit.' >&2
  exit 1
fi

PGPASSWORD=$(tr -d '\r\n' <"$PGPASSWORD_FILE")
export PGPASSWORD

psql --no-psqlrc --set=ON_ERROR_STOP=1 <<'SQL'
\set clients_base64 `base64 -w 0 < "$AUTH_OIDC_CLIENTS_JSON_FILE"`
BEGIN;
SET ROLE kovcheg_migration;

CREATE TEMP TABLE desired_oidc_configuration (
  configuration jsonb NOT NULL
) ON COMMIT DROP;

INSERT INTO desired_oidc_configuration (configuration)
VALUES (
  pg_catalog.convert_from(
    pg_catalog.decode(:'clients_base64', 'base64'),
    'UTF8'
  )::jsonb
);

DO $$
DECLARE
  configured jsonb;
BEGIN
  SELECT configuration INTO STRICT configured FROM desired_oidc_configuration;
  IF pg_catalog.jsonb_typeof(configured) IS DISTINCT FROM 'array'
    OR pg_catalog.jsonb_array_length(configured) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'OIDC clients must be a non-empty JSON array with at most 64 entries';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements(configured) AS item(value)
    WHERE pg_catalog.jsonb_typeof(item.value) IS DISTINCT FROM 'object'
  ) THEN
    RAISE EXCEPTION 'Each OIDC client must be a JSON object';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements(configured) AS item(value)
    WHERE pg_catalog.jsonb_typeof(item.value -> 'clientId') IS DISTINCT FROM 'string'
      OR pg_catalog.jsonb_typeof(item.value -> 'redirectUris') IS DISTINCT FROM 'array'
      OR pg_catalog.jsonb_typeof(item.value -> 'scopes') IS DISTINCT FROM 'array'
      OR pg_catalog.jsonb_typeof(item.value -> 'tokenEndpointAuthMethod') IS DISTINCT FROM 'string'
  ) THEN
    RAISE EXCEPTION 'OIDC client public metadata is incomplete';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements(configured) AS item(value)
    WHERE item.value -> 'scopes' <> '["openid"]'::jsonb
      OR item.value ->> 'tokenEndpointAuthMethod' NOT IN ('none', 'client_secret_basic')
      OR pg_catalog.jsonb_array_length(item.value -> 'redirectUris') < 1
      OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(item.value -> 'redirectUris') AS redirect(value)
        WHERE pg_catalog.jsonb_typeof(redirect.value) IS DISTINCT FROM 'string'
      )
  ) THEN
    RAISE EXCEPTION 'OIDC client protocol metadata is invalid';
  END IF;
END;
$$;

CREATE TEMP TABLE desired_oidc_clients (
  client_id varchar(128) PRIMARY KEY,
  token_endpoint_auth_method kovcheg.oidc_token_endpoint_auth_method NOT NULL
) ON COMMIT DROP;

INSERT INTO desired_oidc_clients (client_id, token_endpoint_auth_method)
SELECT
  item.value ->> 'clientId',
  (item.value ->> 'tokenEndpointAuthMethod')::kovcheg.oidc_token_endpoint_auth_method
FROM desired_oidc_configuration AS source
CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(source.configuration) AS item(value);

CREATE TEMP TABLE desired_oidc_redirect_uris (
  client_id varchar(128) NOT NULL REFERENCES desired_oidc_clients (client_id) ON DELETE CASCADE,
  redirect_uri varchar(2048) NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
) ON COMMIT DROP;

INSERT INTO desired_oidc_redirect_uris (client_id, redirect_uri)
SELECT item.value ->> 'clientId', redirect.value
FROM desired_oidc_configuration AS source
CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(source.configuration) AS item(value)
CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(item.value -> 'redirectUris') AS redirect(value);

INSERT INTO kovcheg.oidc_clients (
  client_id,
  allowed_scope,
  grant_type,
  pkce_required,
  token_endpoint_auth_method
)
SELECT client_id, 'openid', 'authorization_code', true, token_endpoint_auth_method
FROM desired_oidc_clients
ON CONFLICT (client_id) DO NOTHING;

INSERT INTO kovcheg.oidc_client_redirect_uris (client_id, redirect_uri)
SELECT client_id, redirect_uri FROM desired_oidc_redirect_uris
ON CONFLICT (client_id, redirect_uri) DO NOTHING;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM desired_oidc_clients AS desired
    LEFT JOIN kovcheg.oidc_clients AS existing USING (client_id)
    WHERE existing.client_id IS NULL
      OR existing.allowed_scope <> 'openid'
      OR existing.grant_type <> 'authorization_code'
      OR existing.pkce_required IS DISTINCT FROM true
      OR existing.token_endpoint_auth_method <> desired.token_endpoint_auth_method
  ) OR EXISTS (
    SELECT client_id, redirect_uri FROM desired_oidc_redirect_uris
    EXCEPT
    SELECT existing.client_id, existing.redirect_uri
    FROM kovcheg.oidc_client_redirect_uris AS existing
    JOIN desired_oidc_clients AS desired USING (client_id)
  ) OR EXISTS (
    SELECT existing.client_id, existing.redirect_uri
    FROM kovcheg.oidc_client_redirect_uris AS existing
    JOIN desired_oidc_clients AS desired USING (client_id)
    EXCEPT
    SELECT client_id, redirect_uri FROM desired_oidc_redirect_uris
  ) THEN
    RAISE EXCEPTION 'Existing OIDC client metadata conflicts with the requested configuration';
  END IF;
END;
$$;

COMMIT;
SQL

unset PGPASSWORD

echo 'OIDC client public metadata is registered and consistent.'
