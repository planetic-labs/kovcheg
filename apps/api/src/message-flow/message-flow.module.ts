import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { MessageFlowController } from './message-flow.controller.js';
import type { MessageFlowIdentityProvider } from './message-flow.repository.js';
import {
  messageFlowIdentityProviderToken,
  messageFlowRepositoryToken,
} from './message-flow.repository.js';
import { MessageFlowService } from './message-flow.service.js';
import { createMessageFlowRepository } from './postgres-message-flow.repository.js';

const unavailableIdentityProvider: MessageFlowIdentityProvider = Object.freeze({
  available: false,
  findById: () => Promise.resolve(null),
});

export interface MessageFlowModuleOptions {
  readonly identityProvider?: MessageFlowIdentityProvider | undefined;
}

@Module({})
export class MessageFlowModule {
  static register(options: MessageFlowModuleOptions = {}): DynamicModule {
    return {
      controllers: [MessageFlowController],
      module: MessageFlowModule,
      providers: [
        MessageFlowService,
        {
          provide: messageFlowIdentityProviderToken,
          useValue: options.identityProvider ?? unavailableIdentityProvider,
        },
        { provide: messageFlowRepositoryToken, useFactory: createMessageFlowRepository },
      ],
    };
  }
}
