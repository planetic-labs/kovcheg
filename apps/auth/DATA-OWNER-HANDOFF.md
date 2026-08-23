# A2 administrative data-owner contract

Status: fulfilled and consumed by A2.

Public contract: `A2-AUTH-DECISIONS-0277`.

The required data-owner follow-up is implemented by
`infra/postgres/migrations/0006_auth_administration.sql` in public
`main@82ca736e7cc0eede2b904b0c246669326dd84c53`. A2 consumes the protected
administrative functions without changing PostgreSQL schema, migrations, or roles.

## Consumed protected functions

- `kovcheg.admin_create_auth_account`
- `kovcheg.admin_update_auth_account`
- `kovcheg.admin_set_auth_account_status`
- `kovcheg.admin_revoke_auth_session`
- `kovcheg.admin_revoke_all_auth_sessions`

Each function accepts the acting application-session verifier, operation time, and correlation ID.
It verifies a current active-administrator session, performs the mutation, and appends one sanitized
protected audit event in the same PostgreSQL transaction. Missing targets and administrative
authorization failures remain machine-readable without exposing contact or session data.

The auth runtime has `EXECUTE` only on the narrow protected functions it needs. It has no direct
auth-table or audit-table DML and cannot call the older direct account creation, status mutation, or
session-by-ID revocation functions. Deactivation revokes all current sessions and pending
challenges, while ordinary logout continues to revoke only the current session by verifier.

Clean and upgrade database checks cover actor authorization, normalized-email conflicts,
cross-account session isolation, concurrent revoke-all retries, exact sanitized audit cardinality,
rollback behavior, and least-privilege rights. No A3 data blocker remains for the A2 administrative
HTTP API.
