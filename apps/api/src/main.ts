import 'reflect-metadata';

import { NestFactory } from '@nestjs/core';

import { ApiModule } from './api.module.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(ApiModule);
  const port = Number.parseInt(process.env.PORT ?? '3001', 10);

  await app.listen(port, '0.0.0.0');
}

void bootstrap();
