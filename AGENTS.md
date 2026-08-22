# Repository instructions

## Public repository boundary

This repository is public. Keep every file, commit, pull request, issue, workflow log, and comment safe for public disclosure.

Allowed content is limited to source code, tests, public API contracts, migrations, Docker and CI configuration without secrets, and the minimal technical documentation needed to build, verify, operate, and contribute to the software.

Do not add private product requirements, internal decisions, designs, mockups, screenshots, review packages, source archives, personal data, real email addresses, credentials, secrets, internal URLs, or absolute local filesystem paths. Do not copy code from private or legacy sources. If publication safety is uncertain, stop and request a decision.

Before any public push or GitHub write:

1. verify the Git root and `origin` remote;
2. inspect the exact diff and staged file list;
3. scan the staged content for secrets, personal data, internal URLs, and local paths;
4. keep the pull request description limited to public technical context.

## Architecture guardrails

- The system is a greenfield modular monolith built with NestJS and TypeScript.
- PostgreSQL is the only durable source of truth.
- Redis is required for ephemeral coordination, never as the sole store for business data.
- Browser-facing HTTP uses REST/OpenAPI and realtime uses Socket.IO.
- Runtime services must remain stateless and able to run as two instances.
- Updates are delivered only as immutable Docker images.
- User identifiers are UUIDs.
- Authentication is based on one-time email codes for pre-created active users; there is no self-registration, password, passkey, or external identity provider.
- The web application and browser-facing API/realtime endpoints share one origin; a separate host is reserved for the OIDC issuer used by other services.

Do not change these guardrails without an explicit architecture decision.

## A1 provider-neutral operational boundary (`A0-AIOPS-001`)

A1 establishes provider-neutral operational contracts only. The application and every user-facing function must continue to work when all AI/LLM providers and AI integrations are absent or unavailable.

- Define stable machine-readable contracts for errors and events. Include a correlation ID plus non-sensitive build and migration metadata so runtime state can be related to the deployed artifact and database schema.
- Expose deterministic health and readiness signals without any AI dependency.
- Telemetry must not contain user content, personal or otherwise identifying data, credentials, or secrets.
- Treat user content, logs, upstream responses, and external errors as untrusted data. They must never be interpreted as operational instructions or directly initiate a tool or action.
- Do not implement an LLM, an AI executor, or an external AI integration in this slice.

This boundary is reviewed at `A0-T01 FOUNDATION-DATA` after A1 and a testable A3 core are complete. Do not start A4 Message Flow until that gate has been reviewed and processed.

## Internet publication gate

Publishing the source code in `planetic-labs/kovcheg` does not authorize publication of a running service.

Until `A0-T02 BACKEND-SECURITY-DELIVERY` has been completed, reviewed, and processed, work is limited to localhost and an isolated local Docker environment. Do not create an internet-accessible DNS route, ingress, tunnel, or external preview URL for the application before that gate.

`A0-T02` must prove that unknown, unauthenticated, and deactivated users receive no application session and cannot access the web application, API, or Socket.IO. Only a pre-created active account with a valid one-time email code may sign in, and the external response for an unknown email address must remain neutral.

Passing `A0-T02` authorizes only a technical internet environment with closed access. Test users still wait for processed `A0-T03`, and sensitive real conversations still wait for `A0-T04`.

## Stage-scoped work authorization

Stage A1 is limited to workspace structure, toolchain configuration, tests, CI, security policy, non-functional application entry points, shared technical contracts, synthetic identity fixtures, health/readiness and OpenAPI surfaces, and a local-only Docker Compose topology for the web, API, auth, worker, PostgreSQL, and Redis containers.

Within A1, the only routing seam is a neutral local same-origin edge exposed through a loopback-only entry point. Until `A0-T02 BACKEND-SECURITY-DELIVERY` has been reviewed and processed, do not introduce real domains, TLS, DNS, ingress, tunnels, external previews, internet access, or private operational identifiers.

A1 contains no functionality owned by A2 through A7. Close A1 only after its changes are merged into protected `main` and the post-merge CI and Security workflows succeed.

A1 must not add functional product authentication, application database schemas or migrations, messaging behavior, Socket.IO or realtime integration, email delivery, a functional PWA interface, deployment, or an internet-accessible route, tunnel, ingress, or preview. These exclusions are the scope boundary of A1, not permanent repository prohibitions. Later work may add those capabilities only through a separate task explicitly assigned to the stage that owns them. Do not pull work from a later stage into an earlier task, and do not cross a mandatory gate below before its review has been completed and processed.

## Mandatory technical gates

The required late-stage sequence is `A5 → A0-T02 → A6 → A6.5 Web Push → A7 → A0-T03 → A8`.

- `A0-T01 FOUNDATION-DATA` occurs after A1 and a testable A3 core are complete, before starting A4 Message Flow.
- `A0-T02 BACKEND-SECURITY-DELIVERY` occurs after A2, A4, and A5 are complete, before connecting real sign-in or a live backend to A6 or exposing any application route to the internet.
- `A0-T03 OPERATIONS-ACCEPTANCE` occurs after A6.5 Web Push and A7 are complete, before A8 begins and before giving test users access. It must cover Service Worker behavior, notification permission states, per-device subscription and revocation flows, Socket.IO/push deduplication, notification payload privacy, navigation into the authorized chat, and real-device behavior on iPhone, iPad, and Android.
- `A0-T04 SENSITIVE-USE` occurs before any sensitive real conversations. It does not replace specialized security and privacy review or an explicit access decision.

When work reaches a gate, the coding task must stop only the affected next stage and tell Alexey that the checkpoint has been reached, why review is required, and which completed technical slice will be reviewed. Review preparation starts only after Alexey gives the explicit review command. Review packets, private requirements, and review reports remain in the private project and must never be published in this repository, its GitHub records, or workflow logs.

## A6.5 Web Push

A6.5 is the stage for Web Push delivery through a Service Worker after the live A6 application integration. It is separate from A5 realtime delivery and does not start without an explicit A6.5 task. `A0-T04 SENSITIVE-USE` remains a separate later gate regardless of A6.5 or A0-T03 completion.

## Stage parallelism and ownership

After the interfaces and identity stub are stable in A1, A2 and A3 may proceed in parallel in separate branches. A3 exclusively owns the PostgreSQL schema, Prisma/custom SQL migrations, and database roles. A2 owns authentication, OIDC, and session logic and tests; it consumes the agreed data interfaces and must not change A3-owned schema or migrations independently.

After A6 is complete, A6.5 may proceed in parallel with preparatory A7 work. Both A6.5 and A7 must be complete before A0-T03; A8 may begin only after that gate has been reviewed and processed.

## Development rules

- Use the exact Node.js and pnpm versions declared by the repository.
- Keep TypeScript strict and keep lint, formatting, typecheck, test, and build checks green.
- Add tests in proportion to each change and avoid product behavior not backed by an explicit decision.
- Keep commits focused. Do not mix unrelated changes or user-owned work.
- Never commit `.env` files, tokens, keys, generated credentials, or real user data.
