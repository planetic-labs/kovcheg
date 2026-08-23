import type { CorrelationId, UserId, Uuid } from './index.js';

export const messageFlowContractVersion = 1 as const;
export const chatListContractVersion = 1 as const;

export const messageFlowErrorCodes = Object.freeze([
  'message-flow.invalid-request',
  'message-flow.identity-unavailable',
  'message-flow.unauthenticated',
  'message-flow.forbidden',
  'message-flow.idempotency-key-reused',
  'message-flow.unavailable',
  'message-flow.internal-error',
] as const);

export type MessageFlowErrorCode = (typeof messageFlowErrorCodes)[number];
export type ChatSequence = string;
export type ChatKind = 'direct' | 'group';

export interface AvailableChat {
  readonly id: Uuid;
  readonly kind: ChatKind;
}

export interface AvailableChatList {
  readonly contractVersion: typeof chatListContractVersion;
  readonly items: readonly AvailableChat[];
}

export interface TextMessage {
  readonly body: string;
  readonly chatId: Uuid;
  readonly chatSequence: ChatSequence;
  readonly clientMessageId: string;
  readonly createdAt: string;
  readonly id: Uuid;
  readonly senderUserId: UserId;
}

export interface CreateTextMessageRequest {
  readonly clientMessageId: string;
  readonly text: string;
}

export interface CreateTextMessageResponse {
  readonly contractVersion: typeof messageFlowContractVersion;
  readonly message: TextMessage;
  readonly outcome: 'created' | 'replayed';
}

export interface MessageHistoryPage {
  readonly contractVersion: typeof messageFlowContractVersion;
  readonly hasMore: boolean;
  readonly items: readonly TextMessage[];
  readonly nextAfterSequence: ChatSequence | null;
}

export interface MessageFlowRequestContext {
  readonly correlationId: CorrelationId;
  readonly identityStubUserId: UserId;
}

const uuidSchema = Object.freeze({ format: 'uuid', type: 'string' });
const chatSequenceSchema = Object.freeze({ pattern: '^(0|[1-9][0-9]*)$', type: 'string' });

export const availableChatJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    id: uuidSchema,
    kind: { enum: ['direct', 'group'], type: 'string' },
  },
  required: ['id', 'kind'],
  type: 'object',
});

export const availableChatListJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    contractVersion: { enum: [chatListContractVersion], type: 'integer' },
    items: { items: availableChatJsonSchema, type: 'array' },
  },
  required: ['contractVersion', 'items'],
  type: 'object',
});

export const textMessageJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    body: { maxLength: 20_000, minLength: 1, type: 'string' },
    chatId: uuidSchema,
    chatSequence: chatSequenceSchema,
    clientMessageId: {
      maxLength: 128,
      pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
      type: 'string',
    },
    createdAt: { format: 'date-time', type: 'string' },
    id: uuidSchema,
    senderUserId: uuidSchema,
  },
  required: [
    'body',
    'chatId',
    'chatSequence',
    'clientMessageId',
    'createdAt',
    'id',
    'senderUserId',
  ],
  type: 'object',
});

export const createTextMessageRequestJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    clientMessageId: {
      maxLength: 128,
      pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
      type: 'string',
    },
    text: { maxLength: 20_000, minLength: 1, type: 'string' },
  },
  required: ['clientMessageId', 'text'],
  type: 'object',
});

export const createTextMessageResponseJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    contractVersion: { enum: [messageFlowContractVersion], type: 'integer' },
    message: textMessageJsonSchema,
    outcome: { enum: ['created', 'replayed'], type: 'string' },
  },
  required: ['contractVersion', 'message', 'outcome'],
  type: 'object',
});

export const messageHistoryPageJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    contractVersion: { enum: [messageFlowContractVersion], type: 'integer' },
    hasMore: { type: 'boolean' },
    items: { items: textMessageJsonSchema, type: 'array' },
    nextAfterSequence: { nullable: true, ...chatSequenceSchema },
  },
  required: ['contractVersion', 'hasMore', 'items', 'nextAfterSequence'],
  type: 'object',
});
