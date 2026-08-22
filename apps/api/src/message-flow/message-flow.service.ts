import { createHash } from 'node:crypto';

import type {
  CorrelationId,
  CreateTextMessageResponse,
  MessageHistoryPage,
  UserId,
} from '@kovcheg/contracts';
import { messageFlowContractVersion } from '@kovcheg/contracts';
import { HttpStatus, Inject, Injectable } from '@nestjs/common';

import { MessageFlowHttpError } from './message-flow.error.js';
import type {
  MessageFlowIdentityProvider,
  MessageFlowRepository,
} from './message-flow.repository.js';
import {
  MessageFlowRepositoryError,
  messageFlowIdentityProviderToken,
  messageFlowRepositoryToken,
} from './message-flow.repository.js';
import {
  parseAfterSequence,
  parseCreateTextMessageRequest,
  parseHistoryLimit,
  parseIdentityHeader,
  parseUuid,
} from './message-flow.validation.js';

@Injectable()
export class MessageFlowService {
  constructor(
    @Inject(messageFlowIdentityProviderToken)
    private readonly identities: MessageFlowIdentityProvider,
    @Inject(messageFlowRepositoryToken)
    private readonly repository: MessageFlowRepository,
  ) {}

  async createTextMessage(
    chatIdValue: unknown,
    identityHeaderValue: unknown,
    bodyValue: unknown,
    correlationId: CorrelationId,
  ): Promise<CreateTextMessageResponse> {
    const identity = await this.requireActiveIdentity(identityHeaderValue, correlationId);
    const chatId = parseUuid(chatIdValue);
    const body = parseCreateTextMessageRequest(bodyValue);
    if (chatId === null || body === null) {
      throw new MessageFlowHttpError(
        'message-flow.invalid-request',
        correlationId,
        HttpStatus.BAD_REQUEST,
        'The message request is invalid.',
      );
    }

    try {
      const result = await this.repository.createTextMessage({
        body: body.text,
        chatId,
        clientMessageId: body.clientMessageId,
        contentFingerprint: createHash('sha256').update(body.text, 'utf8').digest('hex'),
        correlationId,
        senderUserId: identity,
      });
      return Object.freeze({
        contractVersion: messageFlowContractVersion,
        message: result.message,
        outcome: result.wasCreated ? 'created' : 'replayed',
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  async readMessageHistory(
    chatIdValue: unknown,
    identityHeaderValue: unknown,
    afterSequenceValue: unknown,
    limitValue: unknown,
    correlationId: CorrelationId,
  ): Promise<MessageHistoryPage> {
    const identity = await this.requireActiveIdentity(identityHeaderValue, correlationId);
    const chatId = parseUuid(chatIdValue);
    const afterSequence = parseAfterSequence(afterSequenceValue);
    const limit = parseHistoryLimit(limitValue);
    if (chatId === null || afterSequence === null || limit === null) {
      throw new MessageFlowHttpError(
        'message-flow.invalid-request',
        correlationId,
        HttpStatus.BAD_REQUEST,
        'The history request is invalid.',
      );
    }

    try {
      const result = await this.repository.readMessageHistory({
        afterSequence,
        chatId,
        limit,
        userId: identity,
      });
      const lastMessage = result.items.at(-1);
      return Object.freeze({
        contractVersion: messageFlowContractVersion,
        hasMore: result.hasMore,
        items: result.items,
        nextAfterSequence:
          result.hasMore && lastMessage !== undefined ? lastMessage.chatSequence : null,
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  private async requireActiveIdentity(
    identityHeaderValue: unknown,
    correlationId: CorrelationId,
  ): Promise<UserId> {
    if (!this.identities.available) {
      throw new MessageFlowHttpError(
        'message-flow.identity-unavailable',
        correlationId,
        HttpStatus.SERVICE_UNAVAILABLE,
        'The identity provider is unavailable.',
      );
    }

    const userId = parseIdentityHeader(identityHeaderValue);
    if (userId === null) {
      throw new MessageFlowHttpError(
        'message-flow.unauthenticated',
        correlationId,
        HttpStatus.UNAUTHORIZED,
        'An active synthetic identity is required.',
      );
    }
    const identity = await this.identities.findById(userId);
    if (identity === null) {
      throw new MessageFlowHttpError(
        'message-flow.unauthenticated',
        correlationId,
        HttpStatus.UNAUTHORIZED,
        'An active synthetic identity is required.',
      );
    }
    if (identity.status !== 'active') {
      throw new MessageFlowHttpError(
        'message-flow.forbidden',
        correlationId,
        HttpStatus.FORBIDDEN,
        'The identity is not active.',
      );
    }
    return userId;
  }

  private mapRepositoryError(error: unknown, correlationId: CorrelationId): MessageFlowHttpError {
    if (!(error instanceof MessageFlowRepositoryError)) {
      return new MessageFlowHttpError(
        'message-flow.internal-error',
        correlationId,
        HttpStatus.INTERNAL_SERVER_ERROR,
        'The message operation failed.',
      );
    }

    switch (error.failure) {
      case 'forbidden':
        return new MessageFlowHttpError(
          'message-flow.forbidden',
          correlationId,
          HttpStatus.FORBIDDEN,
          'The chat operation is not allowed.',
        );
      case 'idempotency-key-reused':
        return new MessageFlowHttpError(
          'message-flow.idempotency-key-reused',
          correlationId,
          HttpStatus.CONFLICT,
          'The client message ID was reused with different content.',
        );
      case 'invalid-request':
        return new MessageFlowHttpError(
          'message-flow.invalid-request',
          correlationId,
          HttpStatus.BAD_REQUEST,
          'The message request is invalid.',
        );
      case 'internal':
        return new MessageFlowHttpError(
          'message-flow.internal-error',
          correlationId,
          HttpStatus.INTERNAL_SERVER_ERROR,
          'The message operation failed.',
        );
      case 'unavailable':
        return new MessageFlowHttpError(
          'message-flow.unavailable',
          correlationId,
          HttpStatus.SERVICE_UNAVAILABLE,
          'The message store is unavailable.',
        );
    }
  }
}
