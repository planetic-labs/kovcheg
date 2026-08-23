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

const logger = new Logger('Bootstrap');
let buildMetadata: BuildMetadata = unknownBuildMetadata;

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('api');
  const realtime = loadRealtimeApiRuntimeOptions();
  const identityProvider =
    config.nodeEnv === 'test' && process.env.KOVCHEG_IDENTITY_STUB_ENABLED === 'true'
      ? await createTestIdentityProvider()
      : undefined;
  buildMetadata = config.build;
  const app = await createApiApplication(config, {
    identityProvider,
    instanceId: realtime.instanceId,
    redisUrl: realtime.redisUrl,
    relayToken: realtime.relayToken,
  });

  app.enableShutdownHooks();
  await app.listen(config.port, config.host);
}

async function createTestIdentityProvider() {
  const { createSyntheticIdentityStub } = await import('@kovcheg/contracts/testing');
  const identityStub = createSyntheticIdentityStub({ NODE_ENV: 'test' });
  return Object.freeze({
    available: true,
    findById: (userId: Parameters<typeof identityStub.findById>[0]) =>
      identityStub.findById(userId),
  });
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
