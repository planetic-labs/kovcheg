# Initial owner contact binding

This is an explicitly authorized maintenance operation, not an authentication
endpoint or an admission mechanism. It updates an unused, already established
singleton owner. It does not create an account, role, grant, session, code, or key.
Ordinary bootstrap remains immutable. There is no migration or persistent function.

## Input and authority

Run `sh infra/postgres/bind-initial-owner.sh` with a bounded private JSON input on
stdin. Never supply contact data as arguments, environment values, SQL literals,
logs, or evidence. Supply the exact verified script and adjacent SQL file as
read-only maintenance artifacts; they are not added to the runtime image by this
change. Publication and installation require separate authorization.

Use the existing `kovcheg_migrator` connection and its `kovcheg_migration` role.
An externally provisioned libpq `PGPASSFILE` may provide authentication; this
script neither reads passwords into shell variables nor creates credentials.
`PGPASSWORD`, `PGOPTIONS`, `PGSERVICE`, extra arguments, and another `PGUSER` are
rejected. The executor must independently establish the connection's exact target,
installed source/schema, logging safety, and operator authority. Test fixtures
are isolated PostgreSQL instances with no network and no real credentials.

The input has exactly these keys:

- `expectedBootstrap`: the current trusted bootstrap input, with exactly
  `bootstrapId`, `userId`, `email`, and `displayName` strings.
- `replacementBootstrap`: the same IDs and only the approved replacement email
  and display name, using the same four-field schema.
- `expectedDomainStatus`: the existing domain status, not a new assignment.
- `expectedFunctionalGrants`: the complete existing, sorted functional-grant list.
- `operationId`: a random, non-identifying UUID v4 retained for this operation.

Emails must already be lowercase/trimmed and display names trimmed. The previous
email must be in a reserved test/example domain **and** match the exact trusted
baseline; reserved-domain membership alone is never sufficient. Input is limited
to 16 KiB. No real contact examples belong in this document.

## Transaction and repeat semantics

The command requires schema version `0017`, one profile/bootstrap/owner, an active
person with administrator access, exact IDs and baseline contacts, and unchanged
domain/grants. It excludes writes with bounded locks and refuses any retained
session, challenge, gate, passkey, read-state, or authentication audit evidence.
Any OIDC provider artifact, including an unattributable artifact, blocks this
initial-only operation. Missing/unknown tables or states fail closed.

Only profile `email`, `display_name`, and `updated_at` may change. Existing account,
bootstrap, owner, domain, grant, and membership rows are compared before/after.
One `auth.account.updated` / `auth_account` audit event has a NULL system actor,
empty details, and the neutral operation correlation. No session actor is invented.
Errors roll back the DB transaction and never return raw database details.

`BOUND` is emitted only after COMMIT is acknowledged. `ALREADY_BOUND` requires
the same operation audit, matching desired contacts, identity/authorization checks,
and unused-account checks; it changes nothing. A different operation or changed
result fails closed. After actual use this initial-only command is unavailable.
The one ordinary bootstrap `account.provisioned` event is required, not erased:
its actor/target, correlation, version, outcome, creation-time ordering and exact
starter-count details must match the existing initialization contract. Unknown
or additional owner audit remains a blocker.
`INITIAL_OWNER_BINDING_UNCONFIRMED` is not proof of rollback: a connection can fail
after commit. Never automatically retry or revert an unconfirmed operation.

## Infrastructure-owned file/lifecycle handoff

1. Independently verify exact source/artifacts, authority, baseline, backup
   readiness, unused-account evidence, and the existing bootstrap file. Prepare
   the approved replacement privately; IDs and all other inputs stay unchanged.
2. Stop only auth and exclude competing maintenance. Do not restart it during the
   DB/file transition. This script does not control services or host files.
3. Invoke the command once. On an unconfirmed result, keep auth stopped and perform
   independent value-free DB/file readback; no blind retry or whole-install rollback.
4. After confirmed DB success, infrastructure atomically replaces only the bootstrap
   file while preserving its ownership, mode and read-only delivery. A replacement
   failure leaves auth stopped. Finish the same approved replacement only after
   establishing exact state and authority; do not compensate the DB automatically.
5. Confirm that the effective container-mounted file matches the approved desired
   input. A replaced host inode may require an explicitly authorized container
   recreation; do not assume a restart refreshes a bind mount.
6. Start only auth after agreement is proven. The unchanged bootstrap accepts the
   same IDs/new email idempotently; old or inconsistent email must fail. Independently
   confirm contacts by booleans, unchanged identity/rights, exactly one audit, and
   no session/challenge issuance. Actual user login is a separate outcome.

DB commit and host-file replacement are not one ACID operation. No host-file or
real-service behavior is claimed by the local DB tests. The targeted test command
is `node --test verification/initial-owner-binding.test.mjs`, with
`OWNER_BINDING_TEST_DOCKER_CONTEXT` explicitly selecting a disposable local context.
It uses the pinned upstream PG17 image, existing migrations once, synthetic fixtures,
and only its own temporary container; no product-wide upgrade suite is required.
