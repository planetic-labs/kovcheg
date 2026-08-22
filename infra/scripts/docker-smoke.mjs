/* global fetch, process, setTimeout */

import assert from 'node:assert/strict';

const baseUrl = process.argv[2];
assert.ok(baseUrl, 'A loopback base URL is required');

const expectedCommitSha = process.env.BUILD_COMMIT_SHA || null;
if (expectedCommitSha !== null) {
  assert.match(expectedCommitSha, /^[0-9a-f]{40}$/);
}

async function fetchWithRetry(url, init) {
  let lastError;

  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      return await fetch(url, init);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  throw lastError;
}

function assertAgainstSchema(value, schema, path = '$') {
  if (value === null && schema.nullable === true) {
    return;
  }

  if (Array.isArray(schema.enum)) {
    assert.ok(schema.enum.includes(value), `${path} is outside the published enum`);
  }

  switch (schema.type) {
    case 'array':
      assert.ok(Array.isArray(value), `${path} must be an array`);
      for (const [index, item] of value.entries()) {
        assertAgainstSchema(item, schema.items, `${path}[${index}]`);
      }
      return;
    case 'integer':
      assert.ok(Number.isInteger(value), `${path} must be an integer`);
      return;
    case 'object': {
      assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value));
      const properties = schema.properties ?? {};
      for (const required of schema.required ?? []) {
        assert.ok(Object.hasOwn(value, required), `${path}.${required} is required`);
      }
      if (schema.additionalProperties === false) {
        for (const key of Object.keys(value)) {
          assert.ok(Object.hasOwn(properties, key), `${path}.${key} is not published`);
        }
      }
      for (const [key, propertySchema] of Object.entries(properties)) {
        if (Object.hasOwn(value, key)) {
          assertAgainstSchema(value[key], propertySchema, `${path}.${key}`);
        }
      }
      return;
    }
    case 'string':
      assert.equal(typeof value, 'string', `${path} must be a string`);
      if (schema.minLength !== undefined) {
        assert.ok(value.length >= schema.minLength, `${path} is too short`);
      }
      if (schema.pattern !== undefined) {
        assert.match(value, new RegExp(schema.pattern), `${path} does not match its pattern`);
      }
      return;
    default:
      throw new Error(`${path} uses an unsupported schema type`);
  }
}

function readinessSchema(document) {
  const schema =
    document.paths?.['/health/ready']?.get?.responses?.['200']?.content?.['application/json']
      ?.schema;
  assert.ok(schema, 'OpenAPI is missing the readiness response schema');
  return schema;
}

async function readHealth(path, service, correlationId) {
  const response = await fetchWithRetry(
    `${baseUrl}${path}`,
    correlationId === null ? undefined : { headers: { 'x-correlation-id': correlationId } },
  );
  assert.equal(response.status, 200, `${service} readiness must be available`);
  if (correlationId !== null) {
    assert.equal(response.headers.get('x-correlation-id'), correlationId);
  }
  const health = await response.json();
  assert.equal(health.service, service);
  assert.equal(health.state, 'ready');
  assert.equal(health.status, 'ok');
  assert.equal(health.build.commitSha, expectedCommitSha);
  assert.equal(health.build.imageDigest, null);
  assert.equal(health.build.migrationVersion, null);
  return health;
}

const webHealth = await readHealth('/health/ready', 'web', null);
const apiHealth = await readHealth('/api/health/ready', 'api', 'api-smoke-001');
const authHealth = await readHealth('/auth/health/ready', 'auth', 'auth-smoke-001');

const [rootResponse, apiOpenApiResponse, authOpenApiResponse, apiDocs, authDocs] =
  await Promise.all([
    fetchWithRetry(`${baseUrl}/`),
    fetchWithRetry(`${baseUrl}/api/openapi.json`),
    fetchWithRetry(`${baseUrl}/auth/openapi.json`),
    fetchWithRetry(`${baseUrl}/api/docs`),
    fetchWithRetry(`${baseUrl}/auth/docs`),
  ]);

assert.equal(rootResponse.status, 200);
assert.equal(apiOpenApiResponse.status, 200);
assert.equal(authOpenApiResponse.status, 200);
assert.equal(apiDocs.status, 404, 'API Swagger UI must be disabled in production');
assert.equal(authDocs.status, 404, 'Auth Swagger UI must be disabled in production');

const apiDocument = await apiOpenApiResponse.json();
const authDocument = await authOpenApiResponse.json();
assertAgainstSchema(apiHealth, readinessSchema(apiDocument));
assertAgainstSchema(authHealth, readinessSchema(authDocument));
assert.equal(webHealth.contractVersion, 1);

const invalidCorrelationResponse = await fetchWithRetry(`${baseUrl}/api/health/live`, {
  headers: { 'x-correlation-id': 'unsafe value' },
});
const generatedCorrelationId = invalidCorrelationResponse.headers.get('x-correlation-id');
assert.match(generatedCorrelationId ?? '', /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
assert.notEqual(generatedCorrelationId, 'unsafe value');
