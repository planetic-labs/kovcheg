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

The migration image embeds the checksummed `0001 -> 0015` chain. Migrations are forward-only and run
through the migration role. The migration action remains a separate infrastructure permission even
though its ordering is machine-readable here.

## Resource ceiling

Every service and operation has CPU, memory, and PID constraints. The eight long-running services
have a total hard ceiling of **3.05 CPU, 3840 MiB, and 1024 PIDs**. Including the transient migration
job gives **3.30 CPU and 4096 MiB**. These are conservative candidate limits, not measured production
capacity or an SLA. Backup, restore, and disposable verification jobs run only by explicit profile
and must be capacity-checked before execution; they are not scheduled concurrently by this file.

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
- unknown, missing-gate, missing-session, and deactivated negative checks for Web BFF, REST, and
  Socket.IO;
- active gate to case-insensitive matching email to OTP, registered passkey, REST, Socket.IO,
  logout, Redis recovery, and outbox/catch-up positive checks using only synthetic data;
- backup checksum verification and an isolated restore smoke when separately authorized.

## Current gate status

The local source candidate can prove the application-side fail-closed and container contracts. It
does **not** by itself complete the external security/delivery gate: published immutable digests,
commit-to-image provenance, infrastructure isolation, trusted ingress, secret provisioning,
authorized migration, runtime readback, and an exact-candidate security review remain `UNVERIFIED`
until their separate stages are performed.
