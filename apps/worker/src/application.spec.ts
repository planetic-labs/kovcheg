import { afterEach, describe, expect, it } from 'vitest';

import { createWorkerApplication } from './application.js';

const openApplications: Awaited<ReturnType<typeof createWorkerApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

describe('worker HTTP foundation', () => {
  it('serves internal readiness without background product logic', async () => {
    const app = await createWorkerApplication();
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const response = await fetch(`${baseUrl}/health/ready`);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      service: 'worker',
      state: 'ready',
      status: 'ok',
    });
  });
});
