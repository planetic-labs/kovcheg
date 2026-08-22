import { afterEach, describe, expect, it } from 'vitest';

import { createApiApplication } from './application.js';

const openApplications: Awaited<ReturnType<typeof createApiApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

describe('API HTTP foundation', () => {
  it('serves liveness, readiness, and a local OpenAPI document', async () => {
    const app = await createApiApplication();
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const [liveResponse, readyResponse, openApiResponse] = await Promise.all([
      fetch(`${baseUrl}/health/live`),
      fetch(`${baseUrl}/health/ready`),
      fetch(`${baseUrl}/openapi.json`),
    ]);

    expect(liveResponse.status).toBe(200);
    await expect(liveResponse.json()).resolves.toMatchObject({
      service: 'api',
      state: 'live',
      status: 'ok',
    });
    expect(readyResponse.status).toBe(200);
    await expect(readyResponse.json()).resolves.toMatchObject({
      service: 'api',
      state: 'ready',
      status: 'ok',
    });
    expect(openApiResponse.status).toBe(200);
    await expect(openApiResponse.json()).resolves.toMatchObject({
      info: { title: 'Kovcheg API' },
      openapi: expect.stringMatching(/^3\./),
      paths: {
        '/health/live': expect.any(Object),
        '/health/ready': expect.any(Object),
      },
    });
  });
});
