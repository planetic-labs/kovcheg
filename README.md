# Kovcheg

Kovcheg is a greenfield web/PWA messenger platform. This repository contains only public application code and the technical files required to build and verify it.

The Alpha-0 foundation contains the monorepo, local-only container topology, versioned technical contracts, guarded synthetic identity fixtures, typed non-secret configuration, health/readiness endpoints, and a minimal OpenAPI surface. The A3 data core adds reproducible PostgreSQL migrations, partitioned message storage, database roles, transactional outbox and append-only audit primitives. It deliberately contains no product authentication, message API, realtime integration, email delivery, functional PWA interface, internet deployment, AI integration, or private product material.

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

The A1 contracts define technical seams only: machine-readable errors and operational events, correlation IDs, nullable build provenance, health states, identity/session interfaces, and fail-closed authorization. The synthetic identity stub uses fixed non-personal UUIDs for future tests, is blocked in production, and does not authenticate users. Redis still has no application behavior.

## PostgreSQL data core

The forward-only custom SQL migration chain starts at `0001_data_core.sql`. It creates UUID accounts, memberships, chats, messages, message versions and read cursors; hash-partitions messages and versions by `chat_id`; allocates chat-local sequences from a transactional row-counter; and enforces idempotency with database constraints. The additive chain also defines PostgreSQL authorization facts for platform roles, chat administration, audience and posting policies, service labels, and preserved membership periods. A transactional outbox and protected append-only audit and operation events retain correlation and migration metadata.

Message insertion serializes each idempotency key before allocating its chat sequence. A same-fingerprint retry is skipped before the counter changes, including an `ON CONFLICT DO NOTHING` retry; reuse with a different fingerprint is rejected. Runtime posting is also checked against active membership and the chat's PostgreSQL posting policy before sequence allocation.

Provisioning is one database transaction. An account is active only after it receives the required non-empty starter chat set. Seeded fixtures use fixed synthetic UUIDs and neutral technical slugs; they contain no contact fields or real identities.

PostgreSQL bootstrap creates separate `migration`, `runtime`, and `audit` group roles plus one local login for each. Host and local authentication use SCRAM. The Compose wrapper generates random passwords as ignored local files and never writes credentials to the repository. Apply migrations explicitly with:

```sh
sh infra/scripts/compose.sh up --detach --wait postgres
sh infra/scripts/compose.sh --profile data run --rm migrate
```

`pnpm database:test` verifies the latest schema from a clean volume and the compatible boundaries `0001 → 0002 → 0003` on another clean volume. It checks catalog shape, positive and negative role privileges, SCRAM rules, authorization functions, membership-period boundaries, partition pruning, planner-selected message/outbox indexes after representative loading and `ANALYZE`, real outbox claim/delivery operations, owner-level append-only triggers, partial-failure provisioning rollback, sanitized event metadata, idempotency, and concurrent gap-free row-counter allocation.

## Local container topology

`compose.yaml` starts a neutral `edge`, `web`, `api`, `auth`, `worker`, PostgreSQL, and Redis on an isolated Docker service network. The edge also joins a dedicated host-loopback bridge and provides one same-origin entry at `127.0.0.1:3000`; every application and data-service port remains internal. Nothing creates external DNS, ingress, a tunnel, a preview, TLS, or deployment configuration.

- Web health: `http://127.0.0.1:3000/health/ready`
- API health: `http://127.0.0.1:3000/api/health/ready`
- API OpenAPI JSON: `http://127.0.0.1:3000/api/openapi.json`
- Auth health: `http://127.0.0.1:3000/auth/health/ready`
- Auth OpenAPI JSON: `http://127.0.0.1:3000/auth/openapi.json`

Swagger UI is available only in a non-production application process; production images retain OpenAPI JSON but do not publish the interactive UI.

`pnpm docker:smoke` uses a dedicated Compose project, builds the four application images, verifies all seven default containers and host-side same-origin endpoints, checks the exact port and network sets, validates health responses against OpenAPI, and removes only its own temporary volume. The migration and database-test containers are opt-in tools under the `data` profile and never publish a port. Runtime images contain production dependencies and the files required by their application, not the monorepo build workspace.

Official base-image tags are pinned to verified multi-architecture digests. The smoke build records the tested Git commit in image labels and health metadata. The database records checksummed migration versions itself. Application health keeps migration version `null` until a later stage connects runtime services to PostgreSQL; it does not invent a value before that integration exists.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Never commit secrets, personal data, private requirements, internal links, or local filesystem paths.

## License

Kovcheg is available under the [MIT License](LICENSE).
