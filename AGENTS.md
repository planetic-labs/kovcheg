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

## Current foundation scope

The foundation may contain workspace structure, toolchain configuration, tests, CI, security policy, and non-functional application entry points. It must not yet implement authentication, database schemas or migrations, chats, messages, Redis, Socket.IO, email delivery, a functional PWA interface, or deployment.

## Development rules

- Use the exact Node.js and pnpm versions declared by the repository.
- Keep TypeScript strict and keep lint, formatting, typecheck, test, and build checks green.
- Add tests in proportion to each change and avoid product behavior not backed by an explicit decision.
- Keep commits focused. Do not mix unrelated changes or user-owned work.
- Never commit `.env` files, tokens, keys, generated credentials, or real user data.
