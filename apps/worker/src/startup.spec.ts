import { describe, expect, it, vi } from 'vitest';

import { listenWorkerApplication } from './startup.js';

describe('worker startup', () => {
  it('closes the application when startup fails after creation', async () => {
    const startupFailure = new Error('synthetic listen failure');
    const app = {
      close: vi.fn().mockResolvedValue(undefined),
      enableShutdownHooks: vi.fn(),
      listen: vi.fn().mockRejectedValue(startupFailure),
    };

    await expect(listenWorkerApplication(app, 3003, '127.0.0.1')).rejects.toBe(startupFailure);
    expect(app.enableShutdownHooks).toHaveBeenCalledOnce();
    expect(app.close).toHaveBeenCalledOnce();
  });
});
