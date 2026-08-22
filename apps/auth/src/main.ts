import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';
import type { BuildMetadata } from '@kovcheg/contracts';
import {
  createCorrelationId,
  createOperationalEvent,
  unknownBuildMetadata,
} from '@kovcheg/contracts';
import { Logger } from '@nestjs/common';

import { loadAuthRuntimeConfig } from './a2/runtime-config.js';
import { createAuthApplication } from './application.js';

const logger = new Logger('Bootstrap');
let buildMetadata: BuildMetadata = unknownBuildMetadata;

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('auth');
  buildMetadata = config.build;
  const runtimeConfig = loadAuthRuntimeConfig(config.nodeEnv);
  if (runtimeConfig.enabled) {
    throw new Error('Durable auth runtime infrastructure is not available');
  }
  const app = await createAuthApplication(config);

  app.enableShutdownHooks();
  await app.listen(config.port, config.host);
}

void bootstrap().catch(() => {
  logger.error(
    JSON.stringify(
      createOperationalEvent({
        build: buildMetadata,
        correlationId: createCorrelationId(),
        name: 'service.start-failed',
        outcome: 'failure',
        service: 'auth',
      }),
    ),
  );
  process.exitCode = 1;
});
