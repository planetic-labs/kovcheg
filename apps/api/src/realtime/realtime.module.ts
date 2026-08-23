import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import type { MessageFlowIdentityProvider } from '../message-flow/message-flow.repository.js';
import { messageFlowIdentityProviderToken } from '../message-flow/message-flow.repository.js';
import { RealtimeGateway, realtimeInstanceIdToken } from './realtime.gateway.js';
import { RealtimeRelayController, realtimeRelayToken } from './realtime-relay.controller.js';
import type { RealtimeRepository } from './realtime.repository.js';
import { createRealtimeRepository, realtimeRepositoryToken } from './realtime.repository.js';

const unavailableIdentityProvider: MessageFlowIdentityProvider = Object.freeze({
  available: false,
  findById: () => Promise.resolve(null),
});

export interface RealtimeModuleOptions {
  readonly identityProvider?: MessageFlowIdentityProvider | undefined;
  readonly instanceId?: string | undefined;
  readonly relayToken?: string | null | undefined;
  readonly repository?: RealtimeRepository | undefined;
}

@Module({})
export class RealtimeModule {
  static register(options: RealtimeModuleOptions = {}): DynamicModule {
    return {
      controllers: [RealtimeRelayController],
      module: RealtimeModule,
      providers: [
        RealtimeGateway,
        {
          provide: messageFlowIdentityProviderToken,
          useValue: options.identityProvider ?? unavailableIdentityProvider,
        },
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
      ],
    };
  }
}
