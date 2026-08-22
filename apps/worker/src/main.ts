import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';
import type { BuildMetadata } from '@kovcheg/contracts';
import {
  createCorrelationId,
  createOperationalEvent,
  unknownBuildMetadata,
} from '@kovcheg/contracts';
import { Logger } from '@nestjs/common';

import { createWorkerApplication } from './application.js';

const logger = new Logger('Bootstrap');
let buildMetadata: BuildMetadata = unknownBuildMetadata;

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('worker');
  buildMetadata = config.build;
  const app = await createWorkerApplication(config);

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
        service: 'worker',
      }),
    ),
  );
  process.exitCode = 1;
});
