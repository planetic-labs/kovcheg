import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { HealthController } from './health.controller.js';
import type { MessageFlowModuleOptions } from './message-flow/message-flow.module.js';
import { MessageFlowModule } from './message-flow/message-flow.module.js';
import type { RealtimeModuleOptions } from './realtime/realtime.module.js';
import { RealtimeModule } from './realtime/realtime.module.js';

export interface ApiModuleOptions extends MessageFlowModuleOptions, RealtimeModuleOptions {}

@Module({})
export class ApiModule {
  static register(options: ApiModuleOptions = {}): DynamicModule {
    return {
      controllers: [HealthController],
      imports: [MessageFlowModule.register(options), RealtimeModule.register(options)],
      module: ApiModule,
    };
  }
}
