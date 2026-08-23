FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build

ENV NEXT_TELEMETRY_DISABLED=1
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

WORKDIR /workspace

RUN corepack enable && corepack prepare pnpm@11.22.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/auth/package.json apps/auth/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/worker/package.json apps/worker/package.json
COPY packages/config/package.json packages/config/package.json
COPY packages/contracts/package.json packages/contracts/package.json
RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm --filter @kovcheg/api... build
RUN pnpm --filter @kovcheg/api deploy --prod --legacy /runtime
RUN find /runtime -type f \( -name '*.map' -o -name '*.ts' -o -name '*.md' -o -name '*.spec.js' -o -name '*.test.js' \) -delete

FROM build AS message-flow-test-build

RUN contract_dist="$(find /runtime/node_modules/.pnpm -path '*/node_modules/@kovcheg/contracts/dist' -type d -print -quit)" \
  && test -n "$contract_dist" \
  && mkdir -p "$contract_dist/testing" \
  && cp /workspace/packages/contracts/dist/testing/*.js "$contract_dist/testing/"

FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS message-flow-test

ENV HOST=127.0.0.1
ENV LOG_LEVEL=error
ENV NODE_ENV=test
ENV PORT=3001

WORKDIR /app

COPY --from=message-flow-test-build --chown=node:node /runtime/ ./

USER node

CMD ["node", "dist/message-flow/message-flow.integration-check.js"]

FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS realtime-test-runtime

ENV HOST=0.0.0.0
ENV LOG_LEVEL=error
ENV NODE_ENV=test
ENV PORT=3001

WORKDIR /app

COPY --from=message-flow-test-build --chown=node:node /runtime/ ./

USER node

EXPOSE 3001

CMD ["node", "dist/main.js"]

FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS runtime

ARG BUILD_COMMIT_SHA=""

LABEL org.opencontainers.image.revision=$BUILD_COMMIT_SHA

ENV BUILD_COMMIT_SHA=$BUILD_COMMIT_SHA
ENV HOST=0.0.0.0
ENV LOG_LEVEL=info
ENV NODE_ENV=production
ENV PORT=3001

WORKDIR /app

COPY --from=build --chown=node:node /runtime/ ./

RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
  && rm -f /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx \
    /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg

USER node

EXPOSE 3001

CMD ["node", "dist/main.js"]
