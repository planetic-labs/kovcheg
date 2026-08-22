# A2 durable auth data-owner handoff

Status: blocked on an A3-owned PostgreSQL migration and database grants. A2 must not implement these objects.

The existing `kovcheg.accounts` row is the canonical account identifier and activation state. It deliberately has no contact identity, display name, auth role, challenge, session, or OIDC protocol storage. A durable implementation of the A2 `AuthRepository` therefore needs the data owner to provide the following persistence contract.

## Required records

- Account auth profile keyed by `accounts.id`, with normalized email under a case-insensitive unique constraint, display name, and an A2 administrator/student role. Email values are runtime data and must never appear in migrations, fixtures, logs, or audit payloads.
- Idempotent administrator bootstrap record keyed by the opaque bootstrap ID, bound permanently to one account. Concurrent retries with the same binding return the original account; a different binding conflicts.
- Email challenge record containing only an account reference, HMAC verifier, issue/expiry/use/invalidation timestamps, attempt count, and maximum attempts. The plaintext code is never persisted.
- Server session record containing an account reference, unique HMAC token verifier, session ID, issue/last-seen/idle/absolute-expiry timestamps, and revocation timestamp. The plaintext session token is never persisted.
- Durable `oidc-provider` adapter records for authorization codes, grants, interactions, sessions, access tokens, replay/consume state, and expiry. Provider signing keys, cookie keys, client secrets, and auth peppers remain secret-store inputs rather than migration content.
- Registered OIDC clients with immutable client ID, exact redirect URI set, allowed `openid` scope, Authorization Code grant, mandatory PKCE policy, and either public or confidential token-endpoint authentication metadata. Redirect URIs must be compared exactly; wildcards are forbidden.

## Required atomic behavior

- `issueChallengeForActiveAccount` performs account lookup, active-state check, resend cooldown, invalidation of prior live challenges, and insertion as one transaction. Unknown and deactivated accounts produce the same neutral result without a challenge row.
- `consumeChallengeAndCreateSession` locks/consumes one challenge, increments failed attempts, rechecks account activation, marks a successful challenge used, and inserts one session atomically. Concurrent verification permits at most one successful session.
- `authenticateSession` rechecks account activation and both expiry bounds, then advances idle expiry without exceeding absolute expiry. Invalid/deactivated/expired sessions are rejected and may be revoked in the same transaction.
- `setAccountStatusAndRevoke` changes activation state and revokes all live challenges and sessions atomically.
- Bootstrap, account creation, session revocation, and challenge invalidation must retain the conflict/not-found/idempotency semantics declared by `AuthRepository`.

## Ownership and grants

- A3 owns table/type/index/function creation, migrations, rollback strategy, and DB-role grants.
- The auth runtime role needs only the narrow operations required by the repository contract; it must not receive migration-owner, database-owner, or audit-writer credentials.
- Redis remains ephemeral and is used only for rate limiting. It is not a source of truth for accounts, challenges, sessions, OIDC grants, or revocation.
- After the migration lands, A2 can add the PostgreSQL `AuthRepository` and durable OIDC adapter without changing repository semantics.

## Separate shared dependency boundary

The A2 runtime accepts a `RedisScriptClientFactory`, passes it the validated Redis URL, and runs the rate-limit decision as one atomic Lua operation. Selecting and adding a concrete Node Redis client would also modify the shared workspace lockfile, so it is intentionally deferred until that shared-file ownership is approved.
