# Infrastructure

The Alpha-0 A1 topology is local-only and contains no deployment route, ingress, tunnel, or external preview.

`compose.yaml` starts seven isolated default containers:

- a neutral local `edge` plus `web`, `api`, `auth`, and `worker`;
- PostgreSQL with SCRAM authentication and explicit least-privilege role bootstrap;
- Redis without application queues, caching, or realtime behavior.

Only the edge publishes `127.0.0.1:3000`. It routes `/` to web, `/api/` to the technical API surface, and `/auth/` to the technical auth surface. Every upstream port, PostgreSQL, Redis, and the worker health endpoint remain inside an `internal: true` Docker service network. Edge alone also joins a dedicated host-loopback bridge so Docker can expose the loopback entry. This is a local same-origin seam, not an ingress or deployment route.

The Compose wrapper generates random PostgreSQL passwords in the ignored local `.local/` directory. It mounts them as files and never writes values to Compose configuration or Git. PostgreSQL initializes host and local authentication with `scram-sha-256`; the database port remains unexposed.

Two opt-in containers use the `data` profile:

- `migrate` connects only through the migration login and applies checksummed custom SQL migrations;
- `database-test` is an isolated verification harness for catalog, permissions, constraints, partitions, concurrency and query plans.

Apply migrations to the local volume with:

```sh
sh infra/scripts/compose.sh up --detach --wait postgres
sh infra/scripts/compose.sh --profile data run --rm migrate
```

Run both a latest-from-zero scenario and the compatible migration boundaries `0001 → 0002 → 0003` with:

```sh
pnpm database:test
```

Run the verified local lifecycle with:

```sh
pnpm docker:smoke
```

The smoke script uses its own uniquely named Compose project. It builds the four application images, waits for all seven default containers, verifies the exact service, network, and loopback-port sets, checks that the service network is internal, calls the documented routes from the host, validates API/Auth readiness responses against their published OpenAPI schemas, tests correlation IDs, and inspects production runtime contents and build provenance. Its cleanup cannot address a developer project's volume.

The data core keeps authorization facts in PostgreSQL: platform-role assignments, chat audience and posting policies, chat administrators, role-based posting allowlists, service labels, and immutable membership periods. Runtime reads these facts through least-privilege tables and SECURITY DEFINER predicates; it does not infer rights from chat names or application memory.

Message retries are serialized by their `(chat_id, sender_account_id, client_idempotency_key)` before the row-counter changes. A matching fingerprint skips insertion without consuming a sequence, while a mismatched fingerprint raises a uniqueness error. Event `payload`, audit `details`, and operation `metadata` accept only sanitized technical identifiers, codes, and counters. They must never contain message text, identity/contact data, authentication material, credentials, or secrets; recursive key-shape constraints provide a database guardrail in addition to this contract.
