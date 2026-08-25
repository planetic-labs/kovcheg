import type { AvailableChat, CorrelationId, TextMessage, UserId, Uuid } from '@kovcheg/contracts';

import type { ApplicationPrincipal } from '../session/application-session.js';

export const messageFlowRepositoryToken = Symbol('messageFlowRepository');
export interface CreateTextMessageCommand {
  readonly body: string;
  readonly chatId: Uuid;
  readonly clientMessageId: string;
  readonly contentFingerprint: string;
  readonly correlationId: CorrelationId;
  readonly operatorPrincipal: ApplicationPrincipal;
  readonly personaAccountId?: Uuid;
}

export interface CreateTextMessageResult {
  readonly message: TextMessage;
  readonly wasCreated: boolean;
}

export interface ReadMessageHistoryCommand {
  readonly chatId: Uuid;
  readonly cursor:
    | { readonly direction: 'after'; readonly sequence: string }
    | { readonly direction: 'before'; readonly sequence: string }
    | { readonly direction: 'latest' };
  readonly limit: number;
  readonly userId: UserId;
}

export interface ReadMessageHistoryResult {
  readonly hasMore: boolean;
  readonly items: readonly TextMessage[];
}

export interface MessageFlowRepository {
  createTextMessage(command: CreateTextMessageCommand): Promise<CreateTextMessageResult>;
  listAvailableChats(userId: UserId): Promise<readonly AvailableChat[]>;
  readMessageHistory(command: ReadMessageHistoryCommand): Promise<ReadMessageHistoryResult>;
}

export type MessageFlowRepositoryFailure =
  'forbidden' | 'idempotency-key-reused' | 'internal' | 'invalid-request' | 'unavailable';

export class MessageFlowRepositoryError extends Error {
  constructor(readonly failure: MessageFlowRepositoryFailure) {
    super(`Message-flow repository failure: ${failure}`);
    this.name = 'MessageFlowRepositoryError';
  }
}

export class UnavailableMessageFlowRepository implements MessageFlowRepository {
  createTextMessage(): Promise<CreateTextMessageResult> {
    return Promise.reject(new MessageFlowRepositoryError('unavailable'));
  }

  listAvailableChats(): Promise<readonly AvailableChat[]> {
    return Promise.reject(new MessageFlowRepositoryError('unavailable'));
  }

  readMessageHistory(): Promise<ReadMessageHistoryResult> {
    return Promise.reject(new MessageFlowRepositoryError('unavailable'));
  }
}
