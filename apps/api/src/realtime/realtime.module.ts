import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { RealtimeGateway, realtimeInstanceIdToken } from './realtime.gateway.js';
import { RealtimeRelayController, realtimeRelayToken } from './realtime-relay.controller.js';
import type { RealtimeRepository } from './realtime.repository.js';
import { createRealtimeRepository, realtimeRepositoryToken } from './realtime.repository.js';

export const realtimeTransportReadinessToken = Symbol('realtimeTransportReadiness');

export interface RealtimeTransportReadiness {
  isReady(): boolean;
}

export interface RealtimeModuleOptions {
  readonly instanceId?: string | undefined;
  readonly relayToken?: string | null | undefined;
  readonly repository?: RealtimeRepository | undefined;
  readonly transportReadiness?: RealtimeTransportReadiness | undefined;
}

@Module({})
export class RealtimeModule {
  static register(options: RealtimeModuleOptions = {}): DynamicModule {
    return {
      controllers: [RealtimeRelayController],
      exports: [realtimeRepositoryToken, realtimeTransportReadinessToken],
      module: RealtimeModule,
      providers: [
        RealtimeGateway,
        {
          provide: realtimeInstanceIdToken,
          useValue: options.instanceId ?? 'api',
        },
        {
          provide: realtimeRelayToken,
          useValue: options.relayToken ?? null,
        },
        {
          provide: realtimeRepositoryToken,
          useFactory: () => options.repository ?? createRealtimeRepository(),
        },
        {
          provide: realtimeTransportReadinessToken,
          useValue: options.transportReadiness ?? Object.freeze({ isReady: () => true }),
        },
      ],
    };
  }
}
