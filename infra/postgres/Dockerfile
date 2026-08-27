FROM postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

ENV KOVCHEG_MIGRATION_ROOT=/opt/kovcheg/migrations

COPY --chown=999:999 init/010_roles.sh /docker-entrypoint-initdb.d/010_roles.sh
COPY --chown=999:999 migrations/ /opt/kovcheg/migrations/
COPY --chown=999:999 tests/ /opt/kovcheg/tests/
COPY --chown=999:999 migrate.sh deploy-migrate.sh configure-oidc-clients.sh backup-local.sh restore-smoke.sh /opt/kovcheg/

RUN chmod 0555 /opt/kovcheg/migrate.sh /opt/kovcheg/deploy-migrate.sh \
    /opt/kovcheg/configure-oidc-clients.sh /opt/kovcheg/backup-local.sh \
    /opt/kovcheg/restore-smoke.sh /opt/kovcheg/tests/verify.sh \
  && find /opt/kovcheg/migrations /opt/kovcheg/tests -type f -exec chmod 0444 {} + \
  && mkdir -p /workspace/infra/postgres \
  && ln -s /opt/kovcheg/tests /workspace/infra/postgres/tests
