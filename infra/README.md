# Infrastructure

The Alpha-0 topology is local-only and contains no deployment route, ingress, tunnel, or external preview.

`compose.yaml` starts eight isolated default containers:

- local Traefik `edge` plus `web`, `api-1`, `api-2`, `auth`, and `worker`;
- PostgreSQL with SCRAM authentication and explicit least-privilege role bootstrap;
- Redis for separate ephemeral application and Socket.IO streams.

Only the edge publishes `127.0.0.1:3000`. It routes `/` to web, public `/api/` paths across two API instances, `/socket.io` to the same sticky API pool, and `/auth/` to the technical auth surface. The worker relay uses a separate unexposed edge entrypoint; `/api/internal` is rejected on the published entrypoint. Every upstream port, PostgreSQL, Redis, and the worker health endpoint remain inside an `internal: true` Docker service network. Edge alone also joins a dedicated host-loopback bridge so Docker can expose the loopback entry. This is a local same-origin seam, not an ingress or deployment route.

The Compose wrapper generates random PostgreSQL passwords, auth peppers and signing material, a synthetic Resend credential, and a separate relay token in the ignored local `.local/` directory. It mounts them as files and never writes values to Compose configuration or Git. PostgreSQL initializes host and local authentication with `scram-sha-256`; the database port remains unexposed.

Two opt-in containers use the `data` profile:

- `migrate` connects only through the migration login and applies checksummed custom SQL migrations;
- `database-test` is an isolated verification harness for catalog, permissions, constraints, partitions, concurrency and query plans.

Apply migrations to the local volume with:

```sh
sh infra/scripts/compose.sh up --detach --wait postgres
sh infra/scripts/compose.sh --profile data run --rm migrate
```

Run both a latest-from-zero scenario and the compatible migration boundaries `0001 → 0002 → 0003 → 0004 → 0005 → 0006 → 0007` with:

```sh
pnpm database:test
```

Run the verified local lifecycle with:

```sh
pnpm docker:up
pnpm docker:smoke
```

The lifecycle applies migrations and registers only the synthetic `.invalid` local OIDC client before starting production-shaped Auth. The smoke script uses its own uniquely named Compose project. It builds the four application images, waits for all eight default containers, verifies the exact service, network, and loopback-port sets, checks that the service network is internal, proves internal routes are unreachable from the published entrypoint, validates dependency-aware API and Auth readiness, exercises one real synthetic A2 session through REST, Socket.IO and logout, tests correlation IDs, and inspects production runtime contents and build provenance. Its cleanup cannot address a developer project's volume.

`pnpm realtime:smoke` runs a separate test-only Compose override. The guarded identity stub remains available only with `NODE_ENV=test`; production-shaped API images stay fail-closed. The check proves both polling and WebSocket cross-instance delivery, reconnect history, Redis failure/recovery through the PostgreSQL outbox, and one-API failover. Application and Socket.IO streams use distinct names and responsibilities; Redis never becomes the only copy of messages, rights, or history.

The data core keeps authorization facts in PostgreSQL: platform-role assignments, chat audience and posting policies, chat administrators, role-based posting allowlists, service labels, and immutable membership periods. Runtime reads these facts through least-privilege tables and SECURITY DEFINER predicates; it does not infer rights from chat names or application memory.

Auth persistence uses a separate `kovcheg_auth_app` login inheriting only `kovcheg_auth_runtime`. It has no direct table DML and calls protected functions for account bootstrap/creation, challenge issue/consume/invalidation, session authentication/revocation, activation changes, exact OIDC client lookups, and durable OIDC adapter operations. The migration contains no contact fixtures, client registrations, plaintext codes or tokens, client secrets, signing keys, cookie keys, or auth peppers.

Message retries are serialized by their `(chat_id, sender_account_id, client_idempotency_key)` before the row-counter changes. A matching fingerprint skips insertion without consuming a sequence, while a mismatched fingerprint raises a uniqueness error. Event `payload`, audit `details`, and operation `metadata` accept only sanitized technical identifiers, codes, and counters. They must never contain message text, identity/contact data, authentication material, credentials, or secrets; recursive key-shape constraints provide a database guardrail in addition to this contract.
