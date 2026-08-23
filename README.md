# Kovcheg

Kovcheg is a greenfield web/PWA messenger platform. This repository contains only public application code and the technical files required to build and verify it.

The Alpha-0 foundation contains the monorepo, local-only container topology, versioned technical contracts, guarded synthetic identity fixtures, typed non-secret configuration, health/readiness endpoints, and an OpenAPI surface. The A3 data layer adds reproducible PostgreSQL migrations, partitioned message storage, database roles, transactional outbox, append-only audit primitives, and durable auth persistence. A2 provides email-code/OIDC application sessions and protected administration. A4 provides the message API, and A5 adds PostgreSQL-outbox publication, separate application and Socket.IO Redis Streams, realtime relay, and two API instances behind local Traefik. Production-shaped REST and Socket.IO resolve their principal only through the A2 application session; synthetic identity remains test-only. The repository adds no functional PWA interface, Web Push, internet deployment, AI integration, or private product material.

## Toolchain

- Node.js `24.19.0` LTS is pinned as the production-oriented runtime line.
- pnpm `11.22.0` is pinned for deterministic workspace installs.
- TypeScript is strict across every workspace.

Use Corepack to activate the repository package manager, then install and verify the workspace:

```sh
corepack enable
corepack prepare pnpm@11.22.0 --activate
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm database:test
pnpm realtime:smoke
pnpm docker:smoke
```

## Repository structure

```text
apps/
  web/       Next.js web application entry point
  api/       NestJS browser-facing API entry point
  auth/      NestJS authentication service entry point
  worker/    NestJS background worker entry point
packages/
  contracts/ Shared public TypeScript contracts
  config/    Shared non-secret configuration primitives
infra/
  postgres/  Custom SQL migrations, role bootstrap, and database tests
  scripts/   Local lifecycle and verification scripts
```

The A1 contracts define technical seams only: machine-readable errors and operational events, correlation IDs, nullable build provenance, health states, identity/session interfaces, and fail-closed authorization. The synthetic identity stub uses fixed non-personal UUIDs for tests, is blocked in production, and does not authenticate users. A5 uses Redis only for ephemeral application-event delivery and cross-instance Socket.IO fanout; PostgreSQL remains the durable message, authorization, history, and outbox source.

## PostgreSQL data core

The forward-only custom SQL migration chain starts at `0001_data_core.sql`. It creates UUID accounts, memberships, chats, messages, message versions and read cursors; hash-partitions messages and versions by `chat_id`; allocates chat-local sequences from a transactional row-counter; and enforces idempotency with database constraints. The additive chain also defines PostgreSQL authorization facts for platform roles, chat administration, audience and posting policies, service labels, and preserved membership periods. A transactional outbox and protected append-only audit and operation events retain correlation and migration metadata.

Message insertion serializes each idempotency key before allocating its chat sequence. A same-fingerprint retry is skipped before the counter changes, including an `ON CONFLICT DO NOTHING` retry; reuse with a different fingerprint is rejected. Runtime posting is also checked against active membership and the chat's PostgreSQL posting policy before sequence allocation.

Provisioning is one database transaction. An account is active only after it receives the required non-empty starter chat set. Seeded fixtures use fixed synthetic UUIDs and neutral technical slugs; they contain no contact fields or real identities.

Migration `0005_auth_persistence.sql` is additive and keeps the existing account UUID and activation state canonical. It stores normalized unique contact identity, HMAC verifiers rather than plaintext codes or session tokens, one-time challenge state, bounded sessions, and generic durable `oidc-provider` adapter records. Administrator bootstrap, account creation, challenge issue/consume, session authentication/revocation, and account deactivation are protected transactions. A separate auth database login has no direct table DML and may call only the narrow functions required by that contract. OIDC client secrets, signing keys, cookie keys, auth peppers, and real client registrations remain outside migrations.

Migration `0006_auth_administration.sql` adds actor-verified administrative entrypoints for creating and editing auth accounts, activation or deactivation, and revoking one or all sessions belonging to a stated account. Every entrypoint requires a current active-administrator application session and atomically appends one sanitized protected audit event with the supplied correlation ID. The auth login can execute these wrappers but cannot call the older direct create, status, or session-by-ID mutation functions, write auth or audit tables directly, or inherit migration, database-owner, general runtime, or audit credentials.

Migration `0007_session_validation.sql` adds a narrow auth-runtime operation that validates an active application session without updating its last-seen time or idle expiry. User-initiated authentication continues to use the existing sliding-session operation; background service checks use the non-touch operation so they cannot turn server activity into user activity.

PostgreSQL bootstrap creates separate `migration`, general `runtime`, `auth runtime`, and `audit` group roles plus one local login for each. Host and local authentication use SCRAM. The Compose wrapper generates random passwords as ignored local files and never writes credentials to the repository. Apply migrations explicitly with:

```sh
sh infra/scripts/compose.sh up --detach --wait postgres
sh infra/scripts/compose.sh --profile data run --rm migrate
```

Migration `0004_message_flow.sql` adds one narrow `SECURITY DEFINER` entrypoint for text creation. It atomically writes the message, initial version, sanitized outbox event, and protected audit event. The runtime role can execute this entrypoint but cannot bypass it with direct message or outbox inserts.

`pnpm database:test` verifies the latest schema from a clean volume and each compatible boundary in `0001 → 0002 → 0003 → 0004 → 0005 → 0006 → 0007` on another clean volume, then reapplies the completed migration chain. It checks catalog shape, positive and negative role privileges, SCRAM rules, authorization functions, membership-period boundaries, partition pruning, planner-selected message/outbox indexes after representative loading and `ANALYZE`, real outbox claim/delivery operations, owner-level append-only triggers, partial-failure rollback, sanitized event metadata, message and auth idempotency, concurrent message retries, gap-free row-counter allocation, actor-verified auth administration, non-touch service validation, exact audit cardinality and sanitization, cross-account session isolation, concurrent revoke-all retries, auth revocation, and concurrent one-time challenge consumption. Test-only API and Auth containers also verify the actual HTTP-to-PostgreSQL paths without publishing a port.

## A4 message flow

The browser-facing API exposes:

- `POST /chats/{chatId}/messages` with `{ "clientMessageId": "...", "text": "..." }`;
- `GET /chats/{chatId}/messages?afterSequence=0&limit=50`.

Chat sequences are decimal strings in JSON so the full PostgreSQL `bigint` range remains lossless. History is read from a repeatable snapshot, ordered by `chat_sequence`, bounded to 100 items, and filtered through active account, current membership, and membership-period checks.

The create endpoint computes a SHA-256 content fingerprint. Repeating the same `(chat, sender, clientMessageId)` and content returns the original message with `200` and `outcome: "replayed"`; reusing the key with different content returns `409 message-flow.idempotency-key-reused`. New messages return `201` and `outcome: "created"`. Every error is machine-readable and carries the request correlation ID.

A4 accepts the `x-kovcheg-identity-stub-user-id` header only when a caller explicitly injects the guarded synthetic identity provider. The production-shaped application does not inject or package that test identity seam. It forwards only the expected host-only application-session cookie to A2 and uses the returned server principal for chat listing, message creation, and history authorization.

## A5 realtime

The worker claims one pending `message.created` outbox row with `FOR UPDATE SKIP LOCKED`, publishes its immutable event ID to `kovcheg:application-events:v1`, and marks the row delivered only after Redis accepts it. A separate `realtime-relay` consumer group acknowledges an application-stream entry only after a bearer-protected API endpoint on the edge's unexposed internal entrypoint accepts it; the public `/api/internal` path is rejected. The API emits a sanitized event containing only technical IDs and the chat sequence; message bodies remain in PostgreSQL and reconnect catch-up reads authorized history by `afterSequence`.

Socket.IO uses its own `kovcheg:socket.io:v1` Redis Stream, distinct from the application stream and consumer group. Delivery is at least once. The shared client contract provides bounded deduplication by `eventId` plus `messageId`; room subscription rechecks active identity and PostgreSQL membership. Redis loss disconnects realtime transports, while REST persistence remains available. After Redis returns, the worker resumes pending outbox publication and clients recover any gap from PostgreSQL history.

`pnpm realtime:smoke` uses the existing guarded test identity seam and an isolated Compose project. It proves polling and WebSocket clients on different API instances, cross-instance fanout, reconnect catch-up, a message stored while Redis is down, outbox recovery after Redis returns, and continued delivery after one API stops. It publishes only the same loopback edge as the ordinary Docker smoke and removes its own volume and generated local secrets.

## Local container topology

`compose.yaml` starts local Traefik `edge`, `web`, two stateless API instances, `auth`, `worker`, PostgreSQL, and Redis on an isolated Docker service network. The edge also joins a dedicated host-loopback bridge and provides one same-origin entry at `127.0.0.1:3000`; every application and data-service port remains internal. Traefik uses an HTTP-only local affinity cookie for Socket.IO polling and removes an unhealthy API from rotation. Nothing creates external DNS, ingress, a tunnel, a preview, TLS, or deployment configuration.

- Web health: `http://127.0.0.1:3000/health/ready`
- API health: `http://127.0.0.1:3000/api/health/ready`
- API OpenAPI JSON: `http://127.0.0.1:3000/api/openapi.json`
- Auth liveness: `http://127.0.0.1:3000/auth/health/live`; readiness returns success only when the production auth runtime and its PostgreSQL/Redis dependencies are enabled and available.
- Auth OpenAPI JSON: `http://127.0.0.1:3000/auth/openapi.json`

Swagger UI is available only in a non-production application process; production images retain OpenAPI JSON but do not publish the interactive UI.

`pnpm docker:up` applies migrations, registers the synthetic local OIDC client through the migration login, and starts the eight-container local contour. `pnpm docker:smoke` performs the same setup in a dedicated Compose project, builds the four application images, verifies all eight default containers and host-side same-origin endpoints, checks the exact port and network sets, validates health responses against OpenAPI, and proves a real synthetic A2 session across REST, Socket.IO, and logout. The migration and database-test containers are opt-in tools under the `data` profile and never publish a port. Runtime images contain production dependencies and the files required by their application, not the monorepo build workspace.

Official base-image tags are pinned to verified multi-architecture digests. The smoke build records the tested Git commit in image labels and health metadata. The database records checksummed migration versions itself. Application health keeps migration version `null` until a later stage connects runtime services to PostgreSQL; it does not invent a value before that integration exists.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Never commit secrets, personal data, private requirements, internal links, or local filesystem paths.

## License

Kovcheg is available under the [MIT License](LICENSE).
