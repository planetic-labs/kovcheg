import 'reflect-metadata';

import { loadServiceConfig } from '@kovcheg/config';
import type { BuildMetadata } from '@kovcheg/contracts';
import {
  createCorrelationId,
  createOperationalEvent,
  unknownBuildMetadata,
} from '@kovcheg/contracts';
import { Logger } from '@nestjs/common';

import {
  createDurableAuthRuntime,
  loadEmailChallengeDelivery,
} from './a2/runtime-infrastructure.js';
import { loadAuthRuntimeConfig } from './a2/runtime-config.js';
import { createAuthApplication } from './application.js';

const logger = new Logger('Bootstrap');
let buildMetadata: BuildMetadata = unknownBuildMetadata;

async function bootstrap(): Promise<void> {
  const config = loadServiceConfig('auth');
  buildMetadata = config.build;
  const runtimeConfig = loadAuthRuntimeConfig(config.nodeEnv);
  const runtime = runtimeConfig.enabled
    ? await createDurableAuthRuntime({
        config: runtimeConfig,
        delivery: await loadEmailChallengeDelivery(runtimeConfig.environment),
      })
    : undefined;
  const app = await createAuthApplication(config, runtime).catch(async (error: unknown) => {
    await runtime?.close();
    throw error;
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
        service: 'auth',
      }),
    ),
  );
  process.exitCode = 1;
});
