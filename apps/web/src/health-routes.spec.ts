import { describe, expect, it } from 'vitest';

import { GET as getLiveness } from './app/health/live/route.js';
import { GET as getReadiness } from './app/health/ready/route.js';

describe('web health routes', () => {
  it('returns liveness and readiness responses', async () => {
    const [live, ready] = await Promise.all([getLiveness().json(), getReadiness().json()]);

    expect(live).toMatchObject({ service: 'web', state: 'live', status: 'ok' });
    expect(ready).toMatchObject({ service: 'web', state: 'ready', status: 'ok' });
  });
});
