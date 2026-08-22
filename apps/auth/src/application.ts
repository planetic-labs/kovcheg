import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { AuthModule } from './auth.module.js';
import { configureOpenApi } from './openapi.js';

export async function createAuthApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('auth'),
): Promise<INestApplication> {
  const app = await NestFactory.create(AuthModule, {
    logger: toNestLoggerLevels(config.logLevel),
  });
  app.use(correlationIdMiddleware);
  configureOpenApi(app, config.nodeEnv !== 'production');
  return app;
}
