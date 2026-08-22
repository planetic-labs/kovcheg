import 'reflect-metadata';

import { NestFactory } from '@nestjs/core';

import { AuthModule } from './auth.module.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AuthModule);
  const port = Number.parseInt(process.env.PORT ?? '3002', 10);

  await app.listen(port, '0.0.0.0');
}

void bootstrap();
