import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { ApiModule } from './api.module.js';
import { configureOpenApi } from './openapi.js';

export async function createApiApplication(): Promise<INestApplication> {
  const app = await NestFactory.create(ApiModule);
  configureOpenApi(app);
  return app;
}
