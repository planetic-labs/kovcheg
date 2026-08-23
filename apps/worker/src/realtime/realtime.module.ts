import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import type { RealtimeWorkerOptions } from './realtime.config.js';
import { RealtimeWorkerService, realtimeWorkerOptionsToken } from './realtime-worker.service.js';

@Module({})
export class RealtimeWorkerModule {
  static register(options: RealtimeWorkerOptions | null): DynamicModule {
    return {
      module: RealtimeWorkerModule,
      providers: [
        RealtimeWorkerService,
        { provide: realtimeWorkerOptionsToken, useValue: options },
      ],
    };
  }
}
