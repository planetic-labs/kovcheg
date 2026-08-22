import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';

import { createApiApplication } from './application.js';

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('api');
  const app = await createApiApplication();

  app.enableShutdownHooks();
  await app.listen(config.port, config.host);
}

void bootstrap().catch((error: unknown) => {
  console.error('API service failed to start', error);
  process.exitCode = 1;
});
