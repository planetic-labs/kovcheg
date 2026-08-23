# A2 durable auth data-owner handoff

Status: fulfilled by `0005_auth_persistence.sql` on the current public main.

A2 uses only the protected functions granted to `kovcheg_auth_runtime` through the dedicated `kovcheg_auth_app` login. The runtime does not receive direct table DML, migration-owner, database-owner, audit-writer, or general application credentials.

The delivered contract covers durable auth profiles, idempotent administrator bootstrap, email challenges, server-side sessions, account deactivation and revocation, registered OIDC clients, exact redirect URIs, and durable OIDC provider artifacts. PostgreSQL remains the source of truth; Redis is used only for ephemeral rate limiting.

No further A3 schema, migration, or DB-role handoff is required for A2. A real email delivery provider remains deliberately unselected and is an operational integration input, not a data-owner change. Until a provider-neutral production adapter is supplied, enabling the production auth runtime fails closed.
