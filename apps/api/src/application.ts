import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { ApiModule } from './api.module.js';
import { configureOpenApi } from './openapi.js';

export async function createApiApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('api'),
): Promise<INestApplication> {
  const app = await NestFactory.create(ApiModule, {
    logger: toNestLoggerLevels(config.logLevel),
  });
  app.use(correlationIdMiddleware);
  configureOpenApi(app, config.nodeEnv !== 'production');
  return app;
}
