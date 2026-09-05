/* global console, process, URL */

import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';

import { parse } from 'yaml';

import { collectExecutionMetadata, writeJson } from '../../verification/lib.mjs';

const composeText = await readFile(new URL('./compose.yaml', import.meta.url), 'utf8');
const compose = parse(composeText, { merge: true });
const edgeStatic = parse(
  await readFile(new URL('../edge/traefik.deployment.yaml', import.meta.url), 'utf8'),
);
const edgeRoutes = parse(
  await readFile(new URL('../edge/routes.deployment.yaml', import.meta.url), 'utf8'),
);
const environmentSchema = JSON.parse(
  await readFile(new URL('./environment.schema.json', import.meta.url), 'utf8'),
);
const findings = [];
const testHostApplicationCpuBudget = 2.15;
const minimumFreeCpu = 0.25;
const expectedLongRunningCpuLimits = {
  postgres: '0.40',
  redis: '0.15',
  'api-1': '0.20',
  'api-2': '0.20',
  auth: '0.25',
  worker: '0.15',
  web: '0.20',
  edge: '0.15',
};
const expectedMigrationCpuLimit = '0.15';
const applicationEnvironmentSelector =
  '${KOVCHEG_APP_ENV:?logical application environment is required}';

function finding(code, evidence) {
  findings.push({ code, evidence });
}

function runHostCommand(command, args, environment) {
  return spawnSync(command, args, { encoding: 'utf8', env: environment });
}

function memoryMiB(value) {
  const match = /^(\d+)([KMG])$/u.exec(String(value));
  if (match === null) return Number.NaN;
  const amount = Number(match[1]);
  return match[2] === 'G' ? amount * 1024 : match[2] === 'K' ? amount / 1024 : amount;
}

function cpuTotal(...values) {
  return Number(values.reduce((total, value) => total + Number(value), 0).toFixed(2));
}

const services = compose.services ?? {};
const expectedServices = [
  'api-1',
  'api-2',
  'auth',
  'backup',
  'database-test',
  'edge',
  'migrate',
  'migrate-test',
  'postgres',
  'postgres-test',
  'redis',
  'restore-smoke',
  'web',
  'worker',
];
if (JSON.stringify(Object.keys(services).sort()) !== JSON.stringify(expectedServices)) {
  finding('service-inventory', Object.keys(services).sort());
}

for (const [name, service] of Object.entries(services)) {
  if (service.build !== undefined) finding('runtime-build-forbidden', name);
  if (service.platform !== 'linux/amd64') finding('platform-not-pinned', name);
  const limits = service.deploy?.resources?.limits;
  const reservations = service.deploy?.resources?.reservations;
  if (
    !Number.isFinite(Number(limits?.cpus)) ||
    !Number.isFinite(memoryMiB(limits?.memory)) ||
    !Number.isFinite(Number(reservations?.cpus)) ||
    !Number.isFinite(memoryMiB(reservations?.memory)) ||
    !Number.isSafeInteger(service.pids_limit)
  ) {
    finding('resource-boundary-missing', name);
  }
  if (service.network_mode !== undefined || service.privileged === true) {
    finding('network-or-privilege-bypass', name);
  }
}

const defaultServices = Object.entries(services).filter(
  ([, service]) => service.profiles === undefined,
);
const longRunning = defaultServices.filter(([name]) => name !== 'migrate');
function resourceTotal(entries) {
  const total = entries.reduce(
    (total, [, service]) => ({
      cpus: total.cpus + Number(service.deploy.resources.limits.cpus),
      memoryMiB: total.memoryMiB + memoryMiB(service.deploy.resources.limits.memory),
      pids: total.pids + service.pids_limit,
    }),
    { cpus: 0, memoryMiB: 0, pids: 0 },
  );
  return { ...total, cpus: Number(total.cpus.toFixed(2)) };
}
const longRunningCeiling = resourceTotal(longRunning);
const transitionCeiling = resourceTotal(defaultServices);
const longRunningCpuLimits = Object.fromEntries(
  longRunning.map(([name, service]) => [name, String(service.deploy.resources.limits.cpus)]),
);
if (
  JSON.stringify(Object.entries(longRunningCpuLimits).sort()) !==
  JSON.stringify(Object.entries(expectedLongRunningCpuLimits).sort())
) {
  finding('test-host-service-cpu-ceiling', {
    actual: longRunningCpuLimits,
    expected: expectedLongRunningCpuLimits,
  });
}
if (String(services.migrate?.deploy?.resources?.limits?.cpus) !== expectedMigrationCpuLimit) {
  finding('test-host-migration-cpu-ceiling', {
    actual: services.migrate?.deploy?.resources?.limits?.cpus,
    expected: expectedMigrationCpuLimit,
  });
}
for (const [name, service] of defaultServices) {
  const limit = Number(service.deploy.resources.limits.cpus);
  const reservation = Number(service.deploy.resources.reservations.cpus);
  if (!(limit > reservation)) {
    finding('test-host-cpu-burst-margin-missing', { limit, name, reservation });
  }
}
const longRunningWithReserveCpu = cpuTotal(longRunningCeiling.cpus, minimumFreeCpu);
const transitionWithReserveCpu = cpuTotal(transitionCeiling.cpus, minimumFreeCpu);
const unallocatedTransitionCpu = cpuTotal(testHostApplicationCpuBudget, -transitionWithReserveCpu);
if (
  longRunningCeiling.cpus !== 1.7 ||
  minimumFreeCpu <= 0 ||
  longRunningWithReserveCpu > testHostApplicationCpuBudget ||
  longRunningCeiling.memoryMiB > 3840
) {
  finding('long-running-capacity-ceiling', longRunningCeiling);
}
if (
  transitionCeiling.cpus !== 1.85 ||
  transitionWithReserveCpu >= testHostApplicationCpuBudget ||
  unallocatedTransitionCpu <= 0 ||
  transitionCeiling.memoryMiB > 4096
) {
  finding('transition-capacity-ceiling', transitionCeiling);
}

const portOwners = Object.entries(services).filter(([, service]) => service.ports !== undefined);
if (
  portOwners.length !== 1 ||
  portOwners[0]?.[0] !== 'edge' ||
  portOwners[0]?.[1].ports?.length !== 2 ||
  portOwners[0][1].ports.some((port) => !String(port).startsWith('127.0.0.1:'))
) {
  finding(
    'published-port-boundary',
    portOwners.map(([name, service]) => [name, service.ports]),
  );
}
if (compose.networks?.['service-internal']?.internal !== true) {
  finding('service-network-not-internal', compose.networks?.['service-internal']);
}
if (compose.networks?.['verification-internal']?.internal !== true) {
  finding('verification-network-not-internal', compose.networks?.['verification-internal']);
}
if (compose.networks?.['host-loopback']?.internal === true) {
  finding('loopback-network-unusable', compose.networks?.['host-loopback']);
}

for (const [name, secret] of Object.entries(compose.secrets ?? {})) {
  if (!String(secret.file ?? '').startsWith('${KOVCHEG_')) {
    finding('secret-file-not-externalized', name);
  }
}
const authEnvironment = services.auth?.environment ?? {};
const webEnvironment = services.web?.environment ?? {};
for (const serviceName of ['api-1', 'api-2', 'auth', 'web', 'worker']) {
  const environment = services[serviceName]?.environment ?? {};
  if (
    environment.KOVCHEG_APP_ENV !== applicationEnvironmentSelector ||
    environment.NODE_ENV !== 'production'
  ) {
    finding('application-environment-not-bound', {
      logicalEnvironment: environment.KOVCHEG_APP_ENV,
      nodeEnvironment: environment.NODE_ENV,
      service: serviceName,
    });
  }
}
for (const serviceName of ['migrate', 'migrate-test']) {
  if (services[serviceName]?.environment?.KOVCHEG_APP_ENV !== applicationEnvironmentSelector) {
    finding('migration-environment-not-bound', {
      logicalEnvironment: services[serviceName]?.environment?.KOVCHEG_APP_ENV,
      service: serviceName,
    });
  }
}
for (const key of Object.keys(authEnvironment)) {
  if (/SECRET|PASSWORD|TOKEN|PEPPER|KEY|JWKS|BOOTSTRAP|CLIENTS/u.test(key)) {
    const value = String(authEnvironment[key]);
    if (!value.startsWith('/run/secrets/') && key !== 'REALTIME_RELAY_TOKEN_FILE') {
      finding('sensitive-auth-value-not-file-backed', key);
    }
  }
}
for (const key of Object.keys(webEnvironment)) {
  if (/SECRET|PASSWORD|TOKEN|PEPPER|KEY|JWKS|BOOTSTRAP|CLIENTS/u.test(key)) {
    const value = String(webEnvironment[key]);
    if (
      !value.startsWith('/run/secrets/') &&
      key !== 'KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD'
    ) {
      finding('sensitive-web-value-not-file-backed', key);
    }
  }
}
if (
  authEnvironment.AUTH_OIDC_APPLICATION_CLIENT_ID !==
    '${KOVCHEG_WEB_OIDC_CLIENT_ID:?web OIDC client ID is required}' ||
  authEnvironment.AUTH_OIDC_APPLICATION_REDIRECT_URI !==
    '${KOVCHEG_WEB_OIDC_REDIRECT_URI:?web OIDC redirect URI is required}' ||
  authEnvironment.AUTH_OIDC_ISSUER !== '${KOVCHEG_AUTH_OIDC_ISSUER:?OIDC issuer is required}' ||
  webEnvironment.KOVCHEG_AUTH_INTERNAL_URL !== 'http://auth:3002' ||
  webEnvironment.KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT !==
    '${KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT:?web OIDC authorization endpoint is required}' ||
  webEnvironment.KOVCHEG_WEB_OIDC_CLIENT_ID !==
    '${KOVCHEG_WEB_OIDC_CLIENT_ID:?web OIDC client ID is required}' ||
  webEnvironment.KOVCHEG_WEB_OIDC_ISSUER !==
    '${KOVCHEG_WEB_OIDC_ISSUER:?web OIDC issuer is required}' ||
  webEnvironment.KOVCHEG_WEB_OIDC_REDIRECT_URI !==
    '${KOVCHEG_WEB_OIDC_REDIRECT_URI:?web OIDC redirect URI is required}' ||
  webEnvironment.KOVCHEG_WEB_OIDC_STATE_KEY_FILE !== '/run/secrets/web_oidc_state_key' ||
  webEnvironment.KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD !==
    '${KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD:?web OIDC token endpoint auth method is required}' ||
  !services.web?.secrets?.includes('web_oidc_state_key') ||
  compose.secrets?.web_oidc_state_key?.file !==
    '${KOVCHEG_WEB_OIDC_STATE_KEY_FILE:?web OIDC state key file is required}' ||
  /CLIENT_SECRET/u.test(composeText)
) {
  finding('oidc-bff-compose-contract', {
    authApplicationClientId: authEnvironment.AUTH_OIDC_APPLICATION_CLIENT_ID,
    authApplicationRedirectUri: authEnvironment.AUTH_OIDC_APPLICATION_REDIRECT_URI,
    secretMount: services.web?.secrets,
    stateKeyFile: webEnvironment.KOVCHEG_WEB_OIDC_STATE_KEY_FILE,
    tokenEndpointAuthMethod: webEnvironment.KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD,
  });
}
const issuerRouter = edgeRoutes.http?.routers?.['oidc-issuer'];
if (
  edgeStatic.entryPoints?.issuer?.address !== ':8082' ||
  JSON.stringify(issuerRouter?.entryPoints) !== JSON.stringify(['issuer']) ||
  issuerRouter?.service !== 'auth' ||
  !issuerRouter?.middlewares?.includes('forwarded-https') ||
  !String(issuerRouter?.rule).includes('Path(`/.well-known/openid-configuration`)') ||
  !String(issuerRouter?.rule).includes('Path(`/token`)') ||
  String(issuerRouter?.rule).includes('/internal') ||
  edgeRoutes.http?.middlewares?.['forwarded-https']?.headers?.customRequestHeaders?.[
    'X-Forwarded-Proto'
  ] !== 'https' ||
  !edgeRoutes.http?.routers?.web?.middlewares?.includes('forwarded-https')
) {
  finding('oidc-dual-host-edge-contract', {
    issuerEntryPoint: edgeStatic.entryPoints?.issuer,
    issuerRouter,
    webMiddlewares: edgeRoutes.http?.routers?.web?.middlewares,
  });
}

for (const serviceName of ['api-1', 'api-2', 'auth', 'web', 'worker']) {
  if (services[serviceName]?.depends_on?.migrate?.condition !== 'service_completed_successfully') {
    finding('migration-order-not-enforced', serviceName);
  }
}
if (
  services.migrate?.entrypoint?.[0] !== '/opt/kovcheg/deploy-migrate.sh' ||
  services.migrate?.environment?.AUTH_OIDC_CLIENTS_JSON_FILE !== '/run/secrets/auth_oidc_clients' ||
  !services.migrate?.secrets?.includes('auth_oidc_clients')
) {
  finding('oidc-client-configuration-order-not-enforced', {
    entrypoint: services.migrate?.entrypoint,
    environment: services.migrate?.environment?.AUTH_OIDC_CLIENTS_JSON_FILE,
    secrets: services.migrate?.secrets,
  });
}
if (
  services['postgres-test']?.volumes?.[0] !== 'postgres-test-data:/var/lib/postgresql/data' ||
  services.postgres?.volumes?.[0] !== 'postgres-data:/var/lib/postgresql/data'
) {
  finding('test-database-not-isolated', {
    primary: services.postgres?.volumes,
    test: services['postgres-test']?.volumes,
  });
}
if (
  services.backup?.volumes?.[0] !== 'postgres-backup:/backup' ||
  services['restore-smoke']?.volumes?.[0] !== 'postgres-backup:/backup:ro'
) {
  finding('backup-volume-contract', {
    backup: services.backup?.volumes,
    restore: services['restore-smoke']?.volumes,
  });
}

const schemaNames = new Set();
for (const variable of environmentSchema.variables ?? []) {
  if (schemaNames.has(variable.name)) finding('duplicate-env-schema-key', variable.name);
  schemaNames.add(variable.name);
  if (
    typeof variable.required !== 'boolean' ||
    typeof variable.secret !== 'boolean' ||
    !variable.constraint ||
    !variable.restart ||
    !variable.rotation
  ) {
    finding('incomplete-env-schema-entry', variable.name);
  }
}
for (const requiredName of [
  'KOVCHEG_APP_ENV',
  'KOVCHEG_API_IMAGE',
  'KOVCHEG_AUTH_IMAGE',
  'KOVCHEG_EDGE_IMAGE',
  'KOVCHEG_POSTGRES_IMAGE',
  'KOVCHEG_WEB_IMAGE',
  'KOVCHEG_WORKER_IMAGE',
  'KOVCHEG_AUTH_SESSION_PEPPER_FILE',
  'KOVCHEG_AUTH_ISSUER_LOOPBACK_PORT',
  'KOVCHEG_POSTGRES_RUNTIME_PASSWORD_FILE',
  'KOVCHEG_REALTIME_RELAY_TOKEN_FILE',
  'KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT',
  'KOVCHEG_WEB_OIDC_CLIENT_ID',
  'KOVCHEG_WEB_OIDC_ISSUER',
  'KOVCHEG_WEB_OIDC_REDIRECT_URI',
  'KOVCHEG_WEB_OIDC_STATE_KEY_FILE',
  'KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD',
]) {
  if (!schemaNames.has(requiredName)) finding('env-schema-key-missing', requiredName);
}

if (
  Object.hasOwn(authEnvironment, 'AUTH_PERSONAL_GATE_PEPPER_FILE') ||
  services.auth?.secrets?.includes('auth_personal_gate_pepper') ||
  compose.secrets?.auth_personal_gate_pepper !== undefined ||
  schemaNames.has('KOVCHEG_AUTH_PERSONAL_GATE_PEPPER_FILE')
) {
  finding('retired-personal-gate-secret-present', {
    authEnvironment: Object.hasOwn(authEnvironment, 'AUTH_PERSONAL_GATE_PEPPER_FILE'),
    authSecretMount: services.auth?.secrets?.includes('auth_personal_gate_pepper') ?? false,
    composeSecret: compose.secrets?.auth_personal_gate_pepper !== undefined,
    environmentSchema: schemaNames.has('KOVCHEG_AUTH_PERSONAL_GATE_PEPPER_FILE'),
  });
}

const forbiddenPatterns = [
  { label: 'absolute-workstation-path', pattern: /\/(?:Users|home)\//u },
  {
    label: 'non-loopback-ipv4',
    pattern: /\b(?!(?:127\.0\.0\.1|0\.0\.0\.0)\b)(?:\d{1,3}\.){3}\d{1,3}\b/u,
  },
  { label: 'resolved-public-domain', pattern: /\bm6z\.ru\b/iu },
];
for (const { label, pattern } of forbiddenPatterns) {
  if (pattern.test(composeText)) finding(label, 'infra/deployment/compose.yaml');
}

const composeEnvironment = {
  ...process.env,
  KOVCHEG_APP_ENV: 'staging',
  KOVCHEG_API_IMAGE: `registry.invalid/kovcheg-api@sha256:${'a'.repeat(64)}`,
  KOVCHEG_API_IMAGE_DIGEST: `sha256:${'a'.repeat(64)}`,
  KOVCHEG_AUTH_ADMIN_BOOTSTRAP_FILE: '/dev/null',
  KOVCHEG_AUTH_CHALLENGE_PEPPER_FILE: '/dev/null',
  KOVCHEG_AUTH_EMAIL_FROM_ADDRESS: 'sender@deployment.invalid',
  KOVCHEG_AUTH_EMAIL_FROM_NAME: 'Synthetic Sender',
  KOVCHEG_AUTH_IMAGE: `registry.invalid/kovcheg-auth@sha256:${'b'.repeat(64)}`,
  KOVCHEG_AUTH_IMAGE_DIGEST: `sha256:${'b'.repeat(64)}`,
  KOVCHEG_AUTH_ISSUER_LOOPBACK_PORT: '3302',
  KOVCHEG_AUTH_OIDC_CLIENTS_FILE: '/dev/null',
  KOVCHEG_AUTH_OIDC_COOKIE_KEYS_FILE: '/dev/null',
  KOVCHEG_AUTH_OIDC_ISSUER: 'https://auth-deployment.invalid',
  KOVCHEG_AUTH_OIDC_JWKS_FILE: '/dev/null',
  KOVCHEG_AUTH_RATE_LIMIT_PEPPER_FILE: '/dev/null',
  KOVCHEG_AUTH_SESSION_PEPPER_FILE: '/dev/null',
  KOVCHEG_AUTH_WEBAUTHN_ORIGINS_JSON: '["https://auth-deployment.invalid"]',
  KOVCHEG_AUTH_WEBAUTHN_RP_ID: 'auth-deployment.invalid',
  KOVCHEG_AUTH_WEBAUTHN_RP_NAME: 'Synthetic Deployment',
  KOVCHEG_EDGE_IMAGE: `registry.invalid/kovcheg-edge@sha256:${'c'.repeat(64)}`,
  KOVCHEG_POSTGRES_AUDIT_PASSWORD_FILE: '/dev/null',
  KOVCHEG_POSTGRES_AUTH_PASSWORD_FILE: '/dev/null',
  KOVCHEG_POSTGRES_IMAGE: `registry.invalid/kovcheg-postgres@sha256:${'d'.repeat(64)}`,
  KOVCHEG_POSTGRES_MIGRATION_PASSWORD_FILE: '/dev/null',
  KOVCHEG_POSTGRES_RUNTIME_PASSWORD_FILE: '/dev/null',
  KOVCHEG_POSTGRES_SUPERUSER_PASSWORD_FILE: '/dev/null',
  KOVCHEG_REALTIME_RELAY_TOKEN_FILE: '/dev/null',
  KOVCHEG_RESEND_API_KEY_FILE: '/dev/null',
  KOVCHEG_WEB_IMAGE: `registry.invalid/kovcheg-web@sha256:${'e'.repeat(64)}`,
  KOVCHEG_WEB_IMAGE_DIGEST: `sha256:${'e'.repeat(64)}`,
  KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT: 'https://auth-deployment.invalid/auth',
  KOVCHEG_WEB_OIDC_CLIENT_ID: 'synthetic-deployment-web',
  KOVCHEG_WEB_OIDC_ISSUER: 'https://auth-deployment.invalid',
  KOVCHEG_WEB_OIDC_REDIRECT_URI: 'https://app-deployment.invalid/bff/auth/oidc/callback',
  KOVCHEG_WEB_OIDC_STATE_KEY_FILE: '/dev/null',
  KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD: 'none',
  KOVCHEG_WORKER_IMAGE: `registry.invalid/kovcheg-worker@sha256:${'f'.repeat(64)}`,
  KOVCHEG_WORKER_IMAGE_DIGEST: `sha256:${'f'.repeat(64)}`,
};
const composeV2 = runHostCommand('docker', ['compose', 'version'], composeEnvironment);
const composeV1 =
  composeV2.status === 0 ? null : runHostCommand('docker-compose', ['version'], composeEnvironment);
const composeInvocation =
  composeV2.status === 0
    ? {
        args: ['compose', '--file', 'infra/deployment/compose.yaml', 'config', '--quiet'],
        command: 'docker',
      }
    : composeV1?.status === 0
      ? {
          args: ['--file', 'infra/deployment/compose.yaml', 'config', '--quiet'],
          command: 'docker-compose',
        }
      : null;
const composeCommand =
  composeInvocation === null
    ? null
    : runHostCommand(composeInvocation.command, composeInvocation.args, composeEnvironment);
const composeConfig =
  composeInvocation === null ? 'TOOL_UNAVAILABLE' : composeCommand?.status === 0 ? 'PASS' : 'FAIL';
if (composeConfig === 'TOOL_UNAVAILABLE') {
  finding(
    'compose-cli-unavailable',
    'Docker Compose v2 plugin and legacy docker-compose are unavailable.',
  );
}
if (composeConfig === 'FAIL') finding('compose-config', composeCommand?.stderr.trim());

const report = {
  ...(await collectExecutionMetadata()),
  applicationEnvironment: {
    allowed: ['development', 'staging', 'production'],
    selector: 'KOVCHEG_APP_ENV',
    stagingAndProductionNodeEnvironment: 'production',
  },
  composeConfig,
  cpuProfile: {
    applicationCapacityCpu: testHostApplicationCpuBudget,
    longRunningCeilingCpu: longRunningCeiling.cpus,
    longRunningServiceLimits: longRunningCpuLimits,
    longRunningWithReserveCpu,
    migrationCeilingCpu: Number(services.migrate.deploy.resources.limits.cpus),
    minimumFreeCpu,
    scope: 'staging-test-only',
    transitionCeilingCpu: transitionCeiling.cpus,
    transitionWithReserveCpu,
    unallocatedTransitionCpu,
  },
  findings,
  longRunningCeiling,
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  transitionCeiling,
  volumeClasses: {
    'postgres-backup': 'backup-staging',
    'postgres-data': 'durable-primary',
    'postgres-test-data': 'ephemeral',
  },
};
await writeJson('.artifacts/deployment/summary.json', report);
console.log(
  `Deployment contract: ${report.status}; ${findings.length} finding(s); Compose ${composeConfig}.`,
);
if (findings.length > 0) process.exit(1);
