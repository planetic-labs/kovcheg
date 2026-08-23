import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { WorkerModule } from './worker.module.js';
import type { RealtimeWorkerOptions } from './realtime/realtime.config.js';

export async function createWorkerApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('worker'),
  realtimeOptions: RealtimeWorkerOptions | null = null,
): Promise<INestApplication> {
  const app = await NestFactory.create(WorkerModule.register(realtimeOptions), {
    logger: toNestLoggerLevels(config.logLevel),
  });
  app.use(correlationIdMiddleware);
  return app;
}
