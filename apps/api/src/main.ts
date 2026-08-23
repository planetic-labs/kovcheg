import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';
import type { BuildMetadata } from '@kovcheg/contracts';
import {
  createCorrelationId,
  createOperationalEvent,
  unknownBuildMetadata,
} from '@kovcheg/contracts';
import { Logger } from '@nestjs/common';

import { createApiApplication } from './application.js';
import { loadRealtimeApiRuntimeOptions } from './realtime/realtime.config.js';
import { createApplicationSessionAuthenticator } from './session/application-session.js';

const logger = new Logger('Bootstrap');
let buildMetadata: BuildMetadata = unknownBuildMetadata;

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('api');
  const realtime = loadRealtimeApiRuntimeOptions();
  buildMetadata = config.build;
  const app = await createApiApplication(config, {
    instanceId: realtime.instanceId,
    redisUrl: realtime.redisUrl,
    relayToken: realtime.relayToken,
    sessionAuthenticator: createApplicationSessionAuthenticator(config.nodeEnv),
  });

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
        service: 'api',
      }),
    ),
  );
  process.exitCode = 1;
});
