import type { CorrelationId, UserId, Uuid } from './foundation-types.js';

export const messageFlowContractVersion = 2 as const;
export const messageHistoryContractVersion = 3 as const;
export const chatListContractVersion = 2 as const;

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
  readonly capabilities: ChatCapabilities;
  readonly id: Uuid;
  readonly kind: ChatKind;
}

interface ChatCapabilities {
  readonly canRead: boolean;
  readonly canWrite: boolean;
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
  readonly senderAccountId: Uuid;
}

export interface CreateTextMessageRequest {
  readonly clientMessageId: string;
  readonly personaAccountId?: Uuid;
  readonly text: string;
}

export interface CreateTextMessageResponse {
  readonly contractVersion: typeof messageFlowContractVersion;
  readonly message: TextMessage;
  readonly outcome: 'created' | 'replayed';
}

export interface MessageHistoryPage {
  readonly contractVersion: typeof messageHistoryContractVersion;
  readonly hasMore: boolean;
  readonly items: readonly TextMessage[];
  readonly nextAfterSequence: ChatSequence | null;
  readonly nextBeforeSequence: ChatSequence | null;
}

export interface MessageFlowRequestContext {
  readonly correlationId: CorrelationId;
  readonly identityStubUserId: UserId;
}

const uuidSchema = Object.freeze({ format: 'uuid', type: 'string' });
const chatSequenceSchema = Object.freeze({ pattern: '^(0|[1-9][0-9]*)$', type: 'string' });
const positiveChatSequenceSchema = Object.freeze({ pattern: '^[1-9][0-9]*$', type: 'string' });

export const availableChatJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    capabilities: {
      additionalProperties: false,
      properties: {
        canRead: { type: 'boolean' },
        canWrite: { type: 'boolean' },
      },
      required: ['canRead', 'canWrite'],
      type: 'object',
    },
    id: uuidSchema,
    kind: { enum: ['direct', 'group'], type: 'string' },
  },
  required: ['capabilities', 'id', 'kind'],
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
    senderAccountId: uuidSchema,
  },
  required: [
    'body',
    'chatId',
    'chatSequence',
    'clientMessageId',
    'createdAt',
    'id',
    'senderAccountId',
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
    personaAccountId: uuidSchema,
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
    contractVersion: { enum: [messageHistoryContractVersion], type: 'integer' },
    hasMore: {
      description: 'Whether another page exists in the requested cursor direction.',
      type: 'boolean',
    },
    items: {
      description: 'Visible messages in ascending chat-sequence order.',
      items: textMessageJsonSchema,
      type: 'array',
    },
    nextAfterSequence: {
      ...chatSequenceSchema,
      description: 'Forward cursor when another catch-up page exists.',
      nullable: true,
    },
    nextBeforeSequence: {
      ...positiveChatSequenceSchema,
      description: 'Exclusive backward cursor when another older page exists.',
      nullable: true,
    },
  },
  required: ['contractVersion', 'hasMore', 'items', 'nextAfterSequence', 'nextBeforeSequence'],
  type: 'object',
});
