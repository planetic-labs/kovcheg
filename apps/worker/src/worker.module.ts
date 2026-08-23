import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { HealthController } from './health.controller.js';
import type { RealtimeWorkerOptions } from './realtime/realtime.config.js';
import { RealtimeWorkerModule } from './realtime/realtime.module.js';

@Module({})
export class WorkerModule {
  static register(options: RealtimeWorkerOptions | null = null): DynamicModule {
    return {
      controllers: [HealthController],
      imports: [RealtimeWorkerModule.register(options)],
      module: WorkerModule,
    };
  }
}
