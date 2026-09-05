FROM traefik:v3.7.13@sha256:f86a2cab1b5c649070c49f883c743dd32d8485a56e3368c5f93b9e91f1e91259 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

USER root

RUN apk upgrade --no-cache

COPY --chown=65532:65532 traefik.deployment.yaml /etc/traefik/traefik.yaml
COPY --chown=65532:65532 routes.deployment.yaml /etc/traefik/routes.yaml

USER 65532:65532

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--configFile=/etc/traefik/traefik.yaml"]
