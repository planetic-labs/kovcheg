import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import { ChatListController, MessageFlowController } from './message-flow.controller.js';
import { messageFlowRepositoryToken } from './message-flow.repository.js';
import { MessageFlowService } from './message-flow.service.js';
import { createMessageFlowRepository } from './postgres-message-flow.repository.js';

@Module({})
export class MessageFlowModule {
  static register(): DynamicModule {
    return {
      controllers: [ChatListController, MessageFlowController],
      module: MessageFlowModule,
      providers: [
        MessageFlowService,
        { provide: messageFlowRepositoryToken, useFactory: createMessageFlowRepository },
      ],
    };
  }
}
