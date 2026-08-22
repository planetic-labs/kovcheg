# Kovcheg

Kovcheg is a greenfield web/PWA messenger platform. This repository contains only public application code and the technical files required to build and verify it.

The Alpha-0 foundation contains the monorepo, local-only container topology, versioned technical contracts, guarded synthetic identity fixtures, typed non-secret configuration, health/readiness endpoints, and a minimal OpenAPI surface. It deliberately contains no product authentication, database schema, messaging behavior, realtime integration, email delivery, functional PWA interface, internet deployment, or private product material.

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
infra/       Infrastructure placeholders and public operational notes
```

The A1 contracts define technical seams only: machine-readable errors and operational events, correlation IDs, nullable build provenance, health states, identity/session interfaces, and fail-closed authorization. The synthetic identity stub uses fixed non-personal UUIDs for future tests, is blocked in production, and does not authenticate users. PostgreSQL has no application schema or migrations, and Redis has no application behavior.

## Local container topology

`compose.yaml` starts a neutral `edge`, `web`, `api`, `auth`, `worker`, PostgreSQL, and Redis on an isolated Docker service network. The edge also joins a dedicated host-loopback bridge and provides one same-origin entry at `127.0.0.1:3000`; every application and data-service port remains internal. Nothing creates external DNS, ingress, a tunnel, a preview, TLS, or deployment configuration.

- Web health: `http://127.0.0.1:3000/health/ready`
- API health: `http://127.0.0.1:3000/api/health/ready`
- API OpenAPI JSON: `http://127.0.0.1:3000/api/openapi.json`
- Auth health: `http://127.0.0.1:3000/auth/health/ready`
- Auth OpenAPI JSON: `http://127.0.0.1:3000/auth/openapi.json`

Swagger UI is available only in a non-production application process; production images retain OpenAPI JSON but do not publish the interactive UI.

`pnpm docker:smoke` uses a dedicated Compose project, builds the four application images, verifies all seven containers and host-side same-origin endpoints, checks the exact port and network sets, validates health responses against OpenAPI, and removes only its own temporary volume. Runtime images contain production dependencies and the files required by their application, not the monorepo build workspace.

Official base-image tags are pinned to verified multi-architecture digests. The smoke build records the tested Git commit in image labels and health metadata. Image digest and migration version remain `null` until a real immutable image or schema version exists; the foundation does not invent provenance values.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Never commit secrets, personal data, private requirements, internal links, or local filesystem paths.

## License

Kovcheg is available under the [MIT License](LICENSE).
