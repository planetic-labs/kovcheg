import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { ApiModule } from './api.module.js';
import type { MessageFlowModuleOptions } from './message-flow/message-flow.module.js';
import { configureOpenApi } from './openapi.js';

export async function createApiApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('api'),
  messageFlowOptions: MessageFlowModuleOptions = {},
): Promise<INestApplication> {
  const app = await NestFactory.create(ApiModule.register(messageFlowOptions), {
    logger: toNestLoggerLevels(config.logLevel),
  });
  app.use(correlationIdMiddleware);
  configureOpenApi(app, config.nodeEnv !== 'production');
  return app;
}
