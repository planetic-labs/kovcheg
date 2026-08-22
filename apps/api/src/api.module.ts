import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { HealthController } from './health.controller.js';
import type { MessageFlowModuleOptions } from './message-flow/message-flow.module.js';
import { MessageFlowModule } from './message-flow/message-flow.module.js';

@Module({})
export class ApiModule {
  static register(options: MessageFlowModuleOptions = {}): DynamicModule {
    return {
      controllers: [HealthController],
      imports: [MessageFlowModule.register(options)],
      module: ApiModule,
    };
  }
}
