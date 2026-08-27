FROM postgres:17.11-bookworm@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

ENV KOVCHEG_MIGRATION_ROOT=/opt/kovcheg/migrations \
    KOVCHEG_TEST_ROOT=/opt/kovcheg/tests

COPY --chown=999:999 init/010_roles.sh /docker-entrypoint-initdb.d/010_roles.sh
COPY --chown=999:999 migrations/ /opt/kovcheg/migrations/
COPY --chown=999:999 tests/ /opt/kovcheg/tests/
COPY --chown=999:999 migrate.sh deploy-migrate.sh configure-oidc-clients.sh backup-local.sh restore-smoke.sh /opt/kovcheg/

RUN rm -f /usr/local/bin/gosu

USER 999:999
