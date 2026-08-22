import { afterEach, describe, expect, it } from 'vitest';

import { correlationIdHeaderName, parseCorrelationId } from '@kovcheg/contracts';

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

    const response = await fetch(`${baseUrl}/health/ready`, {
      headers: { [correlationIdHeaderName]: 'worker-test-001' },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get(correlationIdHeaderName)).toBe('worker-test-001');
    await expect(response.json()).resolves.toMatchObject({
      service: 'worker',
      state: 'ready',
      status: 'ok',
    });
  });

  it('generates a correlation ID when the incoming value is invalid', async () => {
    const app = await createWorkerApplication();
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const response = await fetch(`${baseUrl}/health/live`, {
      headers: { [correlationIdHeaderName]: 'unsafe value' },
    });

    expect(parseCorrelationId(response.headers.get(correlationIdHeaderName))).not.toBeNull();
    expect(response.headers.get(correlationIdHeaderName)).not.toBe('unsafe value');
  });
});
