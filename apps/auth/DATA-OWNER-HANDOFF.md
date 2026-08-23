# A2 administrative data-owner follow-up

Status: required before the A2 administrative HTTP API can be completed.

Public contract: `A2-AUTH-DECISIONS-0277`.

Migration `0005_auth_persistence.sql` remains unchanged. It provides administrator bootstrap,
account creation, account activation/deactivation, one-session revocation, logout revocation, and
deactivation-time revocation of all sessions. It does not provide protected operations for editing
an auth profile or explicitly revoking all sessions for one account. Its current administrator
mutations also do not atomically verify the acting administrator session and append a protected
audit event.

## Required protected functions

Add one forward-only A3 migration with narrow `SECURITY DEFINER` functions for:

1. creating an account;
2. updating its normalized email and display name;
3. activating or deactivating it, with deactivation invalidating pending challenges and revoking
   every active session;
4. revoking one session only when it belongs to the stated target account;
5. revoking every active session for the stated target account.

Each function must accept the acting application-session verifier, operation time, and correlation
ID. In the same transaction it must verify that the acting session is current, belongs to an active
administrator, perform the mutation, and append a sanitized protected audit event. Audit details
must contain no email address, display name, session verifier, challenge code, secret, or other
contact data.

Suggested signatures are:

```sql
kovcheg.admin_create_auth_account(
  text, uuid, text, text, timestamptz, varchar
)
kovcheg.admin_update_auth_account(
  text, uuid, text, text, timestamptz, varchar
)
kovcheg.admin_set_auth_account_status(
  text, uuid, kovcheg.account_status, timestamptz, varchar
)
kovcheg.admin_revoke_auth_session(
  text, uuid, uuid, timestamptz, varchar
)
kovcheg.admin_revoke_all_auth_sessions(
  text, uuid, timestamptz, varchar
)
```

The first three functions should return the public auth-account record. One-session revocation
should return whether the stated session changed state. All-session revocation should return the
number of sessions changed. Missing targets and authorization failures must be distinguishable to
the runtime without revealing contact data.

## Rights

- Grant the auth runtime role only `EXECUTE` on the new functions and the existing read,
  challenge, session-authentication, logout, bootstrap, and OIDC functions it still needs.
- After A2 switches to the administrative wrappers, remove auth-runtime `EXECUTE` on direct
  create, status, and session-by-ID mutation functions that bypass actor verification and audit.
- Do not grant direct table DML, migration-owner, database-owner, general runtime, or audit-writer
  credentials to the auth service.

## Required database tests

- active administrator succeeds; student, expired, revoked, missing, and deactivated acting
  sessions fail closed with no mutation;
- create and edit normalize values, preserve uniqueness, and roll back atomically on conflict;
- activation does not create a session; deactivation revokes every session and pending challenge;
- one-session revocation cannot affect a session of another account;
- revoke-all affects only the target account and is safe under concurrent retries;
- every successful mutation appends exactly one sanitized protected audit event in the same
  transaction, while a rolled-back mutation appends none;
- the auth login has only the intended function privileges and no direct DML;
- clean installation and every compatible upgrade boundary pass.

## Minimal public file allowlist for the A3 follow-up

- `infra/postgres/migrations/0006_auth_administration.sql`
- `infra/postgres/tests/verify-auth-runtime.sql`
- `infra/postgres/tests/verify-security.sql`
- `infra/postgres/tests/verify.sh`
- `infra/scripts/database-test.sh`
- `README.md`

Until this data-owner follow-up is merged and consumed, A2 must not expose a partial
administrative HTTP API or use direct DML as a workaround.
