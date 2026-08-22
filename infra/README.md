# Infrastructure

The Alpha-0 A1 topology is local-only and contains no deployment route, ingress, tunnel, or external preview.

`compose.yaml` starts seven isolated containers:

- a neutral local `edge` plus `web`, `api`, `auth`, and `worker`;
- PostgreSQL without application schema or migrations;
- Redis without application queues, caching, or realtime behavior.

Only the edge publishes `127.0.0.1:3000`. It routes `/` to web, `/api/` to the technical API surface, and `/auth/` to the technical auth surface. Every upstream port, PostgreSQL, Redis, and the worker health endpoint remain inside an `internal: true` Docker service network. Edge alone also joins a dedicated host-loopback bridge so Docker can expose the loopback entry. This is a local same-origin seam, not an ingress or deployment route.

The temporary PostgreSQL trust mode remains limited to the internal, non-published network and is not deployment configuration. A later data-stage task owns credentials and database authentication.

Run the verified local lifecycle with:

```sh
pnpm docker:smoke
```

The smoke script uses its own uniquely named Compose project. It builds the four application images, waits for all seven containers, verifies the exact service, network, and loopback-port sets, checks that the service network is internal, calls the documented routes from the host, validates API/Auth readiness responses against their published OpenAPI schemas, tests correlation IDs, and inspects production runtime contents and build provenance. Its cleanup cannot address a developer project's volume.
