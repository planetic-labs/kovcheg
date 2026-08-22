import { afterEach, describe, expect, it } from 'vitest';

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
      fetch(`${baseUrl}/health/ready`),
      fetch(`${baseUrl}/openapi.json`),
    ]);

    expect(readyResponse.status).toBe(200);
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
});
