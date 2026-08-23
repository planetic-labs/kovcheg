import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { ApiModule } from './api.module.js';
import type { ApiModuleOptions } from './api.module.js';
import { configureOpenApi } from './openapi.js';
import { RedisStreamsIoAdapter } from './realtime/redis-streams-io.adapter.js';

export interface ApiApplicationOptions extends ApiModuleOptions {
  readonly redisUrl?: string | null | undefined;
}

export async function createApiApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('api'),
  options: ApiApplicationOptions = {},
): Promise<INestApplication> {
  let adapter: RedisStreamsIoAdapter | undefined;
  const transportReadiness = Object.freeze({
    isReady: () =>
      options.redisUrl === null || options.redisUrl === undefined || adapter?.isReady() === true,
  });
  const app = await NestFactory.create(ApiModule.register({ ...options, transportReadiness }), {
    logger: toNestLoggerLevels(config.logLevel),
  });
  if (options.redisUrl) {
    adapter = new RedisStreamsIoAdapter(app, options.redisUrl);
    await adapter.connect();
    app.useWebSocketAdapter(adapter);
  }
  app.use(correlationIdMiddleware);
  configureOpenApi(app, config.nodeEnv !== 'production');
  return app;
}
