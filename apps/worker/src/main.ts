import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';

import { createWorkerApplication } from './application.js';

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('worker');
  const app = await createWorkerApplication();

  app.enableShutdownHooks();
  await app.listen(config.port, config.host);
}

void bootstrap().catch((error: unknown) => {
  console.error('Worker service failed to start', error);
  process.exitCode = 1;
});
