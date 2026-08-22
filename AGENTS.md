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

## Stage-scoped work authorization

The current foundation pull request is limited to workspace structure, toolchain configuration, tests, CI, security policy, and non-functional application entry points. This pull request must not add functional product code, database schemas or migrations, Docker topology, deployment, chats, messages, Redis, Socket.IO, email delivery, or a functional PWA interface.

These exclusions are the scope boundary of the current pull request, not permanent repository prohibitions. Later work may add those capabilities only through a separate task explicitly assigned to the stage that owns them. Do not pull work from a later stage into an earlier task, and do not cross a mandatory gate below before its review has been completed and processed.

## Mandatory technical gates

The required late-stage sequence is `A5 → A0-T02 → A6 → A6.5 Web Push → A7 → A0-T03 → A8`.

- `A0-T01 FOUNDATION-DATA` occurs after A1 and a testable A3 core are complete, before starting A4 Message Flow.
- `A0-T02 BACKEND-SECURITY-DELIVERY` occurs after A2, A4, and A5 are complete, before connecting real sign-in or a live backend to A6.
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
