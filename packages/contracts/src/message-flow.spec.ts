import { describe, expect, it } from 'vitest';

import {
  availableChatListJsonSchema,
  chatAdministrationContractVersion,
  chatListContractVersion,
  createGroupChatRequestJsonSchema,
  createTextMessageRequestJsonSchema,
  messageFlowContractVersion,
  messageFlowErrorCodes,
  messageHistoryContractVersion,
  messageHistoryPageJsonSchema,
} from './message-flow.js';

describe('message-flow contracts', () => {
  it('publishes a stable chat-list contract that permits an empty result', () => {
    expect(chatListContractVersion).toBe(2);
    expect(availableChatListJsonSchema).toMatchObject({
      additionalProperties: false,
      properties: {
        contractVersion: { enum: [2], type: 'integer' },
        items: { type: 'array' },
      },
      required: ['contractVersion', 'items'],
    });
    expect(availableChatListJsonSchema.properties.items.items).toMatchObject({
      required: ['capabilities', 'id', 'kind'],
    });
  });

  it('publishes a minimal versioned group-administration seam', () => {
    expect(chatAdministrationContractVersion).toBe(1);
    expect(createGroupChatRequestJsonSchema).toMatchObject({
      additionalProperties: false,
      required: ['chatId', 'reason'],
    });
  });

  it('publishes a versioned error boundary without a browser identity header', () => {
    expect(messageFlowContractVersion).toBe(2);
    expect(messageFlowErrorCodes).toContain('message-flow.idempotency-key-reused');
  });

  it('keeps text input and sequence cursors bounded and machine-readable', () => {
    expect(messageHistoryContractVersion).toBe(3);
    expect(createTextMessageRequestJsonSchema).toMatchObject({
      additionalProperties: false,
      required: ['clientMessageId', 'text'],
      properties: { personaAccountId: { format: 'uuid', type: 'string' } },
    });
    expect(messageHistoryPageJsonSchema.properties.nextAfterSequence).toMatchObject({
      nullable: true,
      pattern: '^(0|[1-9][0-9]*)$',
      type: 'string',
    });
    expect(messageHistoryPageJsonSchema.properties.nextBeforeSequence).toMatchObject({
      nullable: true,
      pattern: '^[1-9][0-9]*$',
      type: 'string',
    });
    expect(messageHistoryPageJsonSchema.required).toEqual([
      'contractVersion',
      'hasMore',
      'items',
      'nextAfterSequence',
      'nextBeforeSequence',
    ]);
  });
});
