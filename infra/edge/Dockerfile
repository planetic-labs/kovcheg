FROM traefik:v3.7.12@sha256:ef751c695afd26e2be41009047f651153dc1e61ace03e6d13f299d8c4be842b8 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

USER root

RUN apk upgrade --no-cache

COPY --chown=65532:65532 traefik.deployment.yaml /etc/traefik/traefik.yaml
COPY --chown=65532:65532 routes.deployment.yaml /etc/traefik/routes.yaml

USER 65532:65532

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--configFile=/etc/traefik/traefik.yaml"]
