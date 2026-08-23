import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { HealthController } from './health.controller.js';
import { MessageFlowModule } from './message-flow/message-flow.module.js';
import type { RealtimeModuleOptions } from './realtime/realtime.module.js';
import { RealtimeModule } from './realtime/realtime.module.js';
import { ApplicationSessionModule } from './session/application-session.module.js';
import type { ApplicationSessionAuthenticator } from './session/application-session.js';

export interface ApiModuleOptions extends RealtimeModuleOptions {
  readonly sessionAuthenticator?: ApplicationSessionAuthenticator | undefined;
}

@Module({})
export class ApiModule {
  static register(options: ApiModuleOptions = {}): DynamicModule {
    return {
      controllers: [HealthController],
      imports: [
        ApplicationSessionModule.register(options.sessionAuthenticator),
        MessageFlowModule.register(),
        RealtimeModule.register(options),
      ],
      module: ApiModule,
    };
  }
}
