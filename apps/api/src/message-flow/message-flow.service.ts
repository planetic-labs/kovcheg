import { createHash } from 'node:crypto';

import type {
  AvailableChatList,
  ChatAdministrationResponse,
  CorrelationId,
  CreateTextMessageResponse,
  MessageHistoryPage,
} from '@kovcheg/contracts';
import {
  chatListContractVersion,
  chatAdministrationContractVersion,
  messageFlowContractVersion,
  messageHistoryContractVersion,
} from '@kovcheg/contracts';
import { HttpStatus, Inject, Injectable } from '@nestjs/common';

import { MessageFlowHttpError } from './message-flow.error.js';
import type {
  MessageFlowRepository,
  ReadMessageHistoryCommand,
} from './message-flow.repository.js';
import {
  MessageFlowRepositoryError,
  messageFlowRepositoryToken,
} from './message-flow.repository.js';
import {
  parseAfterSequence,
  parseBeforeSequence,
  parseCreateGroupChatRequest,
  parseCreateTextMessageRequest,
  parseHistoryLimit,
  parseSetChatAdministratorRequest,
  parseUuid,
} from './message-flow.validation.js';
import type { ApplicationSessionAuthenticator } from '../session/application-session.js';
import {
  ApplicationSessionError,
  applicationSessionAuthenticatorToken,
} from '../session/application-session.js';

@Injectable()
export class MessageFlowService {
  constructor(
    @Inject(applicationSessionAuthenticatorToken)
    private readonly sessions: ApplicationSessionAuthenticator,
    @Inject(messageFlowRepositoryToken)
    private readonly repository: MessageFlowRepository,
  ) {}

  async createGroupChat(
    cookieHeader: string | undefined,
    bodyValue: unknown,
    correlationId: CorrelationId,
  ): Promise<ChatAdministrationResponse> {
    const principal = await this.requirePrincipal(cookieHeader, correlationId);
    const body = parseCreateGroupChatRequest(bodyValue);
    if (body === null) {
      throw new MessageFlowHttpError(
        'message-flow.invalid-request',
        correlationId,
        HttpStatus.BAD_REQUEST,
        'The chat administration request is invalid.',
      );
    }
    try {
      return Object.freeze({
        ...(await this.repository.createGroupChat({
          chatId: body.chatId,
          correlationId,
          operatorPrincipal: principal,
          reason: body.reason,
        })),
        contractVersion: chatAdministrationContractVersion,
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  async createTextMessage(
    chatIdValue: unknown,
    cookieHeader: string | undefined,
    bodyValue: unknown,
    correlationId: CorrelationId,
  ): Promise<CreateTextMessageResponse> {
    const principal = await this.requirePrincipal(cookieHeader, correlationId);
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
        operatorPrincipal: principal,
        ...(body.personaAccountId === undefined ? {} : { personaAccountId: body.personaAccountId }),
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
    cookieHeader: string | undefined,
    afterSequenceValue: unknown,
    beforeSequenceValue: unknown,
    limitValue: unknown,
    correlationId: CorrelationId,
  ): Promise<MessageHistoryPage> {
    const principal = await this.requirePrincipal(cookieHeader, correlationId);
    const chatId = parseUuid(chatIdValue);
    const limit = parseHistoryLimit(limitValue);
    const hasAfterSequence = afterSequenceValue !== undefined;
    const hasBeforeSequence = beforeSequenceValue !== undefined;
    const afterSequence = hasAfterSequence ? parseAfterSequence(afterSequenceValue) : null;
    const beforeSequence = hasBeforeSequence ? parseBeforeSequence(beforeSequenceValue) : null;
    if (
      chatId === null ||
      limit === null ||
      (hasAfterSequence && afterSequence === null) ||
      (hasBeforeSequence && beforeSequence === null) ||
      (hasAfterSequence && hasBeforeSequence)
    ) {
      throw new MessageFlowHttpError(
        'message-flow.invalid-request',
        correlationId,
        HttpStatus.BAD_REQUEST,
        'The history request is invalid.',
      );
    }
    const cursor: ReadMessageHistoryCommand['cursor'] =
      afterSequence !== null
        ? { direction: 'after', sequence: afterSequence }
        : beforeSequence !== null
          ? { direction: 'before', sequence: beforeSequence }
          : { direction: 'latest' };

    try {
      const result = await this.repository.readMessageHistory({
        chatId,
        cursor,
        limit,
        userId: principal.userId,
      });
      const firstMessage = result.items.at(0);
      const lastMessage = result.items.at(-1);
      return Object.freeze({
        contractVersion: messageHistoryContractVersion,
        hasMore: result.hasMore,
        items: result.items,
        nextAfterSequence:
          cursor.direction === 'after' && result.hasMore && lastMessage !== undefined
            ? lastMessage.chatSequence
            : null,
        nextBeforeSequence:
          cursor.direction !== 'after' && result.hasMore && firstMessage !== undefined
            ? firstMessage.chatSequence
            : null,
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  async listAvailableChats(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<AvailableChatList> {
    const principal = await this.requirePrincipal(cookieHeader, correlationId);
    try {
      return Object.freeze({
        contractVersion: chatListContractVersion,
        items: await this.repository.listAvailableChats(principal.userId),
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  async setChatAdministrator(
    chatIdValue: unknown,
    targetAccountIdValue: unknown,
    cookieHeader: string | undefined,
    bodyValue: unknown,
    correlationId: CorrelationId,
  ): Promise<ChatAdministrationResponse> {
    const principal = await this.requirePrincipal(cookieHeader, correlationId);
    const chatId = parseUuid(chatIdValue);
    const targetAccountId = parseUuid(targetAccountIdValue);
    const body = parseSetChatAdministratorRequest(bodyValue);
    if (chatId === null || targetAccountId === null || body === null) {
      throw new MessageFlowHttpError(
        'message-flow.invalid-request',
        correlationId,
        HttpStatus.BAD_REQUEST,
        'The chat administration request is invalid.',
      );
    }
    try {
      return Object.freeze({
        ...(await this.repository.setChatAdministrator({
          chatId,
          correlationId,
          granted: body.granted,
          operatorPrincipal: principal,
          reason: body.reason,
          targetAccountId,
          version: body.version,
        })),
        contractVersion: chatAdministrationContractVersion,
      });
    } catch (error) {
      throw this.mapRepositoryError(error, correlationId);
    }
  }

  private async requirePrincipal(cookieHeader: string | undefined, correlationId: CorrelationId) {
    try {
      return await this.sessions.authenticate(cookieHeader, correlationId);
    } catch (error) {
      const unavailable =
        error instanceof ApplicationSessionError && error.failure === 'unavailable';
      throw new MessageFlowHttpError(
        unavailable ? 'message-flow.identity-unavailable' : 'message-flow.unauthenticated',
        correlationId,
        unavailable ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.UNAUTHORIZED,
        unavailable
          ? 'The application session service is unavailable.'
          : 'A valid application session is required.',
      );
    }
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
