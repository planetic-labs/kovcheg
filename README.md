# Kovcheg

Kovcheg is a greenfield web/PWA messenger platform. This repository contains only public application code and the technical files required to build and verify it.

The Alpha-0 foundation contains the monorepo, local-only container topology, technical contracts, synthetic identity fixtures, typed non-secret configuration, health/readiness endpoints, and a minimal OpenAPI surface. It deliberately contains no product authentication, database schema, messaging behavior, realtime integration, email delivery, functional PWA interface, internet deployment, or private product material.

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

The A1 contracts define technical seams only. The synthetic identity stub uses fixed non-personal UUIDs for future integration tests and does not authenticate users. PostgreSQL has no application schema or migrations, and Redis has no application behavior.

## Local container topology

`compose.yaml` starts `web`, `api`, `auth`, `worker`, PostgreSQL, and Redis on an isolated Docker network. Only the web and local HTTP service ports bind to `127.0.0.1`; nothing creates DNS, ingress, a tunnel, an external preview, or deployment configuration.

- Web health: `http://127.0.0.1:3000/health/ready`
- API health: `http://127.0.0.1:3001/health/ready`
- API OpenAPI JSON: `http://127.0.0.1:3001/openapi.json`
- API documentation: `http://127.0.0.1:3001/docs`
- Auth health: `http://127.0.0.1:3002/health/ready`
- Auth OpenAPI JSON: `http://127.0.0.1:3002/openapi.json`

`pnpm docker:smoke` builds the images, verifies all six containers and endpoints, then stops the topology and removes the temporary test volume.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Never commit secrets, personal data, private requirements, internal links, or local filesystem paths.

## License

Kovcheg is available under the [MIT License](LICENSE).
