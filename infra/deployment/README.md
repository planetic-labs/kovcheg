# Application deployment candidate

This directory defines the application-owned side of a Docker-only deployment candidate. It does
not publish images, select a registry, configure an internet route, provide secret values, authorize
a migration or deploy, or claim that an external runtime has been verified.

## Deploy unit

The indivisible Alpha-0 application unit contains eight long-running containers:

- `edge`, `web`, `api-1`, `api-2`, `auth`, and `worker`;
- one service-scoped PostgreSQL container and one ephemeral-only Redis container.

The forward-only `migrate` job must complete successfully before the application containers start.
After applying checksummed migrations, the same one-shot job registers only missing public OIDC
client metadata from the file-backed runtime configuration. Existing exact metadata is accepted;
any conflict fails closed and requires a separate controlled configuration change. Client secrets
are never persisted by this job.
The `backup` and `restore-smoke` jobs are explicit operations and are not long-running services. The
`verification` profile has its own PostgreSQL container, network, and disposable volume; it must
never point at the working database.

The application, edge, and PostgreSQL images are built from this repository. Redis remains the
pinned upstream image declared in Compose. All candidate images target only `linux/amd64`:

```sh
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f apps/api/Dockerfile -t <api-image-placeholder> .
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f apps/auth/Dockerfile -t <auth-image-placeholder> .
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f apps/web/Dockerfile -t <web-image-placeholder> .
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f apps/worker/Dockerfile -t <worker-image-placeholder> .
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f infra/edge/Dockerfile -t <edge-image-placeholder> infra/edge
docker buildx build --platform linux/amd64 --target runtime --build-arg BUILD_COMMIT_SHA=<full-sha> -f infra/postgres/Dockerfile -t <postgres-image-placeholder> infra/postgres
```

Mutable tags and a local build are verification inputs only. A future handoff requires a registry
reference by immutable digest for every repository-built image and direct provenance from every
digest to the same published source commit.

## Manual GHCR publication

The `Publish immutable GHCR images` workflow is a manual-only publication candidate for `api`,
`auth`, `web`, `worker`, `edge`, and `postgres`. It accepts one full source SHA and fails unless that
SHA is the current public `main` head immediately before publication. Each `linux/amd64` image uses
the single navigation tag `sha-<full-source-sha>`, carries OCI source and revision labels, receives a
registry provenance attestation, and produces a machine-readable service-to-package-to-digest
mapping. Deployment references use only `ghcr.io/planetic-labs/kovcheg-<service>@sha256:<digest>`.

Before any push, one inventory gate checks all six exact-source tags. An absent tag may be published
once; an existing tag is adopted without overwrite only after its digest, `linux/amd64` platform,
OCI source, and exact revision have been verified. Any conflict or ambiguous registry response stops
all publish jobs. Independent publish jobs do not cancel one another, so a retry can finish a
partially completed same-source set while preserving every verified immutable tag.

Each successful publish or adoption path creates provenance evidence and one mapping artifact. A
final aggregate gate accepts exactly one mapping for each of the six services, rejects missing or
duplicate services and mismatched source, platform, digest, reference, navigation tag, or attestation
evidence, and uploads one six-image mapping. The workflow uses the repository `GITHUB_TOKEN`,
creates no mutable `latest` tag, and does not change package visibility. New packages therefore
retain the registry default visibility. Merging the workflow does not run it: publication, package
existence, digest readback, anonymous pull, visibility changes, server handoff, and deployment all
remain separate operations and evidence gates.

The local deployment smoke uses unique temporary tags and exact ownership labels for its six
images. It first requires 20 GiB of measured free Docker-daemon storage by default, then records
image IDs, architecture, and source provenance before removing its own images and Compose resources.
`KOVCHEG_DOCKER_MIN_FREE_GIB` may set another positive-integer threshold, and
`KOVCHEG_KEEP_TEST_IMAGES=1` deliberately retains only the current run's images for diagnostics.
Neither option performs automatic storage cleanup. Use `pnpm docker:resources` for a read-only stale
resource report; resources without the complete ownership label set remain undetermined.

## Configuration and isolation

[`environment.schema.json`](environment.schema.json) is the application env contract. It contains
names and constraints only. Secret material is always supplied through owner-readable files and
mounted as Compose secrets. Bootstrap and OIDC client JSON are also file-backed because they may
contain contact or credential material. No secret or data is copied into an image layer.

Only `edge` publishes a port, and it binds to host loopback. Internal ports are:

| Service       | Port | Purpose                                          |
| ------------- | ---: | ------------------------------------------------ |
| edge          | 8080 | same-origin Web, REST, Auth, and Socket.IO entry |
| edge          | 8081 | worker-only realtime relay entry                 |
| web           | 3000 | Next.js runtime                                  |
| api-1 / api-2 | 3001 | REST and Socket.IO runtime                       |
| auth          | 3002 | authentication runtime                           |
| worker        | 3003 | worker health endpoint                           |
| postgres      | 5432 | durable primary database                         |
| redis         | 6379 | ephemeral streams and rate-limit/cache state     |

An external reverse proxy, TLS, trusted forwarding sources, host route, DNS name, and access policy
belong to a later infrastructure action. They are deliberately absent here. Any later proxy must
preserve one same-origin boundary and pass the original HTTPS scheme only from a trusted network.
The loopback port is not an internet publication.

## Health, readiness, and startup

Application liveness is `/health/live`; readiness is `/health/ready`. API and Auth readiness is
dependency-aware. PostgreSQL uses `pg_isready`, Redis uses `PING`, and edge uses Traefik ping. Compose
waits for PostgreSQL and Redis health and for the one-shot migration and OIDC-registration job before starting API, Auth,
and Worker; Web and edge then wait for their upstream application services.

The migration image embeds the checksummed `0001 -> 0016` chain. Migrations are forward-only and run
through the migration role. The migration action remains a separate infrastructure permission even
though its ordering is machine-readable here.

## Resource ceiling

Every service and operation has CPU, memory, and PID constraints. The staging/test-only CPU profile
for the neutral shared test-host role is:

| Long-running service | Hard CPU ceiling |
| -------------------- | ---------------: |
| `postgres`           |             0.40 |
| `redis`              |             0.15 |
| `api-1`              |             0.20 |
| `api-2`              |             0.20 |
| `auth`               |             0.25 |
| `worker`             |             0.15 |
| `web`                |             0.20 |
| `edge`               |             0.15 |

The eight long-running ceilings total **1.70 CPU**. The application handoff must also declare
`minimum_free_cpu=0.25`, so the normal-state envelope is `1.70 + 0.25 = 1.95 CPU`, within the
application capacity budget of **2.15 CPU**. The one-shot `migrate` job has a **0.15 CPU** ceiling;
the conservative transition envelope is `1.70 + 0.15 + 0.25 = 2.10 CPU`, leaving **0.05 CPU** of the
same budget unallocated even if migration and every long-running ceiling are counted together.

These CPU values apply only to the staging/test unit under idle and synthetic verification traffic.
They preserve the existing CPU reservations and a positive burst margin for every default service,
but they are not measured throughput, load, production capacity, or an SLA. Infrastructure must stop
before starting or transitioning the unit if the verified application budget is below 2.15 CPU, if
its required free reserve is above 0.25 CPU, or if service throttling prevents startup, readiness, or
functional verification; Docker overcommit is not an accepted fallback.

The existing memory and PID ceilings remain **3840 MiB and 1024 PIDs** for the eight long-running
services and **4096 MiB** for the conservative migration transition. Backup, restore, and disposable
verification jobs run only by explicit profile and must be capacity-checked before execution; they
are not scheduled concurrently by this file.

## Data, backup, and restore

Volume classes are:

- `postgres-data`: `durable-primary`;
- `postgres-backup`: `backup-staging` on the same server;
- `postgres-test-data`: `ephemeral` and disposable.

The declared data mode is `SINGLE_SERVER_LOCAL_ONLY`. `backup-local.sh` creates a PostgreSQL custom
dump in the local backup volume, verifies that its catalog can be read, writes a SHA-256 sidecar, and
prunes matching files after a default seven-day retention. `restore-smoke.sh` verifies the checksum
and restores only into a disposable database whose name begins with `kovcheg_restore_`; it never
overwrites the working database.

If infrastructure schedules one successful local backup per day, the conservative operational
proposal is a maximum backup age of 24 hours and a two-hour restore-drill objective. Those values are
not an accepted RPO, RTO, availability target, or SLA. Loss of the physical server can lose both the
primary database and all local copies. Off-server recoverability is **not available** and must not be
reported as `PASS`.

## Rollback and readback

The rollback target must be a previously approved set of immutable image digests with one exact
source commit. Image rollback is allowed only while every applied migration is backward-compatible
with that target. There are no down migrations. If compatibility is not proven, preserve current
data and stop; restore, data loss, or reconciliation needs a separate decision and permission.

A later independent readback must record, without secret or user data:

- the published full source SHA and each running immutable image digest plus provenance;
- `linux/amd64` architecture, container user, health, readiness, restart count, logs, CPU/memory/PID
  limits, exact networks, and the single loopback binding;
- the recorded migration version and volume classes;
- unknown, missing-session, deactivated, no-challenge verification, and retired-gate-endpoint negative
  checks for Web BFF, REST, and Socket.IO;
- neutral valid-email code-state behavior, case-insensitive active-account matching to OTP, registered
  discoverable passkey, REST, Socket.IO, logout, Redis recovery, and outbox/catch-up positive checks
  using only synthetic data;
- backup checksum verification and an isolated restore smoke when separately authorized.

## Current gate status

The local source candidate can prove the application-side fail-closed and container contracts. It
does **not** by itself complete the external security/delivery gate: published immutable digests,
commit-to-image provenance, infrastructure isolation, trusted ingress, secret provisioning,
authorized migration, runtime readback, and an exact-candidate security review remain `UNVERIFIED`
until their separate stages are performed.
