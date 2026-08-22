# Infrastructure

The Alpha-0 A1 topology is local-only and contains no deployment route, ingress, tunnel, or external preview.

`compose.yaml` starts six isolated containers:

- `web`, `api`, `auth`, and `worker` from their own Dockerfiles;
- PostgreSQL without application schema or migrations;
- Redis without application queues, caching, or realtime behavior.

Only `127.0.0.1` ports `3000`, `3001`, and `3002` are published. PostgreSQL, Redis, and the worker health port remain inside the local Docker network. The temporary PostgreSQL trust mode is limited to that internal, non-published network and is not deployment configuration.

Run the verified local lifecycle with:

```sh
pnpm docker:smoke
```

The smoke script builds the four application images, waits for all six containers, verifies health/readiness and the API/Auth OpenAPI documents, and always stops the topology and removes its test volume.
