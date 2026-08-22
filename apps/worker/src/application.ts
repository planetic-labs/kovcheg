import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import { WorkerModule } from './worker.module.js';

export function createWorkerApplication(): Promise<INestApplication> {
  return NestFactory.create(WorkerModule);
}
