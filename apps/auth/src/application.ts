import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { AuthModule } from './auth.module.js';
import { configureOpenApi } from './openapi.js';

export async function createAuthApplication(): Promise<INestApplication> {
  const app = await NestFactory.create(AuthModule);
  configureOpenApi(app);
  return app;
}
