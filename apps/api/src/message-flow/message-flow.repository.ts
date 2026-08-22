import type { CorrelationId, TextMessage, UserId, Uuid } from '@kovcheg/contracts';

export const messageFlowRepositoryToken = Symbol('messageFlowRepository');
export const messageFlowIdentityProviderToken = Symbol('messageFlowIdentityProvider');

export interface MessageFlowIdentityProvider {
  readonly available: boolean;
  findById(userId: UserId): Promise<{ readonly status: 'active' | 'deactivated' } | null>;
}

export interface CreateTextMessageCommand {
  readonly body: string;
  readonly chatId: Uuid;
  readonly clientMessageId: string;
  readonly contentFingerprint: string;
  readonly correlationId: CorrelationId;
  readonly senderUserId: UserId;
}

export interface CreateTextMessageResult {
  readonly message: TextMessage;
  readonly wasCreated: boolean;
}

export interface ReadMessageHistoryCommand {
  readonly afterSequence: string;
  readonly chatId: Uuid;
  readonly limit: number;
  readonly userId: UserId;
}

export interface ReadMessageHistoryResult {
  readonly hasMore: boolean;
  readonly items: readonly TextMessage[];
}

export interface MessageFlowRepository {
  createTextMessage(command: CreateTextMessageCommand): Promise<CreateTextMessageResult>;
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

  readMessageHistory(): Promise<ReadMessageHistoryResult> {
    return Promise.reject(new MessageFlowRepositoryError('unavailable'));
  }
}
