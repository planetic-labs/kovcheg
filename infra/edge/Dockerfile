FROM traefik:v3.7.7@sha256:1cb3845d7a05e1473c9086351426597e911db49db382b6e4769f9b0744962ac8 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

COPY --chown=65532:65532 traefik.deployment.yaml /etc/traefik/traefik.yaml
COPY --chown=65532:65532 routes.deployment.yaml /etc/traefik/routes.yaml

USER 65532:65532

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--configFile=/etc/traefik/traefik.yaml"]
