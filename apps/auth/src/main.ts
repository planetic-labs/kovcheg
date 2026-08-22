import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';

import { createAuthApplication } from './application.js';

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('auth');
  const app = await createAuthApplication();

  app.enableShutdownHooks();
  await app.listen(config.port, config.host);
}

void bootstrap().catch((error: unknown) => {
  console.error('Auth service failed to start', error);
  process.exitCode = 1;
});
