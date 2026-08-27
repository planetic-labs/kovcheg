# Infrastructure

The Alpha-0 runtime topology is local-only and contains no deployment route, ingress, tunnel, or external preview. [`deployment/`](deployment/README.md) contains only the application-owned, image-only candidate contract for a later infrastructure handoff; it does not deploy or publish anything.

`compose.yaml` starts eight isolated default containers:

- local Traefik `edge` plus `web`, `api-1`, `api-2`, `auth`, and `worker`;
- PostgreSQL with SCRAM authentication and explicit least-privilege role bootstrap;
- Redis for separate ephemeral application and Socket.IO streams.

Only the edge publishes `127.0.0.1:3000`. It routes `/` to web, public `/api/` paths across two API instances, `/socket.io` to the same sticky API pool, and `/auth/` to the technical auth surface. The worker relay uses a separate unexposed edge entrypoint; `/api/internal` is rejected on the published entrypoint. Every upstream port, PostgreSQL, Redis, and the worker health endpoint remain inside an `internal: true` Docker service network. Edge alone also joins a dedicated host-loopback bridge so Docker can expose the loopback entry. This is a local same-origin seam, not an ingress or deployment route.

The Compose wrapper generates random PostgreSQL passwords, auth peppers and signing material, synthetic bootstrap and OIDC client files, a synthetic Resend credential, and a separate relay token in the ignored local `.local/` directory. It mounts them as files and never writes values to Compose configuration or Git. PostgreSQL initializes host and local authentication with `scram-sha-256`; the database port remains unexposed.

Two opt-in containers use the `data` profile:

- `migrate` connects only through the migration login and applies checksummed custom SQL migrations;
- `database-test` is an isolated verification harness for catalog, permissions, constraints, partitions, concurrency and query plans.

Apply migrations to the local volume with:

```sh
sh infra/scripts/compose.sh up --detach --wait postgres
sh infra/scripts/compose.sh --profile data run --rm migrate
```

Run both a latest-from-zero scenario and every compatible boundary through the current `0001 → … → 0015` chain with:

```sh
pnpm database:test
```

Run the verified local lifecycle with:

```sh
pnpm docker:up
pnpm docker:smoke
```

The lifecycle applies migrations and registers only the synthetic `.invalid` local OIDC client before starting production-shaped Auth. The smoke script uses its own uniquely named Compose project. It builds the four application images, waits for all eight default containers, verifies the exact service, network, and loopback-port sets, checks that the service network is internal, proves internal routes are unreachable from the published entrypoint, validates dependency-aware API and Auth readiness, exercises one real synthetic A2 session through REST, Socket.IO and logout, tests correlation IDs, and inspects production runtime contents and build provenance. Its cleanup cannot address a developer project's volume.

The deployment candidate embeds edge configuration and the migration/backup/restore tools in pinned images so a future server runtime never mounts an unpublished workspace. `pnpm deployment:verify` checks the contract without starting containers. `pnpm deployment:smoke` is an explicit local-only check of six `linux/amd64` images and removes only its own containers, networks, volumes, and generated synthetic secrets.

All disposable Docker verification entrypoints share an ownership lifecycle. Each run uses unique temporary image references and labels containing the neutral project name, purpose, run ID, and full source SHA. A preflight measures free Docker-daemon storage before a heavy build and requires 20 GiB unless `KOVCHEG_DOCKER_MIN_FREE_GIB` supplies another positive integer. Cleanup is exact-current-run only, runs after success, failure, or an ordinary signal, and never performs broad pruning. Set `KOVCHEG_KEEP_TEST_IMAGES=1` only for local diagnostics. `pnpm docker:resources` reports labelled stale resources and legacy-name matches with undetermined ownership without deleting them.

`pnpm realtime:smoke` runs a separate test-only Compose override. The guarded identity stub remains available only with `NODE_ENV=test`; production-shaped API images stay fail-closed. The check proves both polling and WebSocket cross-instance delivery, reconnect history, Redis failure/recovery through the PostgreSQL outbox, and one-API failover. Application and Socket.IO streams use distinct names and responsibilities; Redis never becomes the only copy of messages, rights, or history.

The data core keeps authorization facts in PostgreSQL: platform-role assignments, chat audience and posting policies, chat administrators, role-based posting allowlists, service labels, and immutable membership periods. Runtime reads these facts through least-privilege tables and SECURITY DEFINER predicates; it does not infer rights from chat names or application memory.

Auth persistence uses a separate `kovcheg_auth_app` login inheriting only `kovcheg_auth_runtime`. It has no direct table DML and calls protected functions for account bootstrap/creation, challenge issue/consume/invalidation, session authentication/revocation, activation changes, exact OIDC client lookups, and durable OIDC adapter operations. The migration contains no contact fixtures, client registrations, plaintext codes or tokens, client secrets, signing keys, cookie keys, or auth peppers.

Persona authorization remains internal to the API runtime. It rechecks the exact personal session, operator, active system persona, and active individual grant inside the same migration-owned entrypoint that writes an act-as message. The API runtime receives `EXECUTE` only and no direct DML on grant or auth-state tables. The message row and outbox retain the public sender account, while the append-only protected audit retains the distinct personal operator.

Message retries are serialized by their `(chat_id, sender_account_id, client_idempotency_key)` before the row-counter changes. A matching fingerprint skips insertion without consuming a sequence, while a mismatched fingerprint raises a uniqueness error. Event `payload`, audit `details`, and operation `metadata` accept only sanitized technical identifiers, public sender account identifiers, codes, and counters. They must never contain message text, personal operator identity, contact data, authentication material, credentials, or secrets; recursive key-shape constraints provide a database guardrail in addition to this contract.
