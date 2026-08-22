import { afterEach, describe, expect, it } from 'vitest';

import { loadServiceConfig } from '@kovcheg/config';
import { correlationIdHeaderName, parseCorrelationId } from '@kovcheg/contracts';

import { createAuthApplication } from './application.js';

const openApplications: Awaited<ReturnType<typeof createAuthApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

describe('auth HTTP foundation', () => {
  it('serves health endpoints and an OpenAPI document without auth behavior', async () => {
    const app = await createAuthApplication();
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const [readyResponse, openApiResponse] = await Promise.all([
      fetch(`${baseUrl}/health/ready`, {
        headers: { [correlationIdHeaderName]: 'auth-test-001' },
      }),
      fetch(`${baseUrl}/openapi.json`),
    ]);

    expect(readyResponse.status).toBe(200);
    expect(readyResponse.headers.get(correlationIdHeaderName)).toBe('auth-test-001');
    await expect(readyResponse.json()).resolves.toMatchObject({
      service: 'auth',
      state: 'ready',
      status: 'ok',
    });
    expect(openApiResponse.status).toBe(200);
    await expect(openApiResponse.json()).resolves.toMatchObject({
      info: { title: 'Kovcheg Auth' },
      openapi: expect.stringMatching(/^3\./),
    });
  });

  it('replaces an invalid correlation ID and disables Swagger UI in production', async () => {
    const app = await createAuthApplication(
      loadServiceConfig('auth', { LOG_LEVEL: 'error', NODE_ENV: 'production' }),
    );
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const [healthResponse, openApiResponse, swaggerResponse] = await Promise.all([
      fetch(`${baseUrl}/health/ready`, {
        headers: { [correlationIdHeaderName]: 'unsafe value' },
      }),
      fetch(`${baseUrl}/openapi.json`),
      fetch(`${baseUrl}/docs`),
    ]);

    expect(parseCorrelationId(healthResponse.headers.get(correlationIdHeaderName))).not.toBeNull();
    expect(healthResponse.headers.get(correlationIdHeaderName)).not.toBe('unsafe value');
    expect(openApiResponse.status).toBe(200);
    expect(swaggerResponse.status).toBe(404);
  });
});
