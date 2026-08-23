import { describe, expect, it } from 'vitest';

import {
  availableChatListJsonSchema,
  chatListContractVersion,
  createTextMessageRequestJsonSchema,
  messageFlowContractVersion,
  messageFlowErrorCodes,
  messageHistoryPageJsonSchema,
} from './message-flow.js';

describe('message-flow contracts', () => {
  it('publishes a stable chat-list contract that permits an empty result', () => {
    expect(chatListContractVersion).toBe(1);
    expect(availableChatListJsonSchema).toMatchObject({
      additionalProperties: false,
      properties: {
        contractVersion: { enum: [1], type: 'integer' },
        items: { type: 'array' },
      },
      required: ['contractVersion', 'items'],
    });
  });

  it('publishes a versioned error boundary without a browser identity header', () => {
    expect(messageFlowContractVersion).toBe(1);
    expect(messageFlowErrorCodes).toContain('message-flow.idempotency-key-reused');
  });

  it('keeps text input and sequence cursors bounded and machine-readable', () => {
    expect(createTextMessageRequestJsonSchema).toMatchObject({
      additionalProperties: false,
      required: ['clientMessageId', 'text'],
    });
    expect(messageHistoryPageJsonSchema.properties.nextAfterSequence).toMatchObject({
      nullable: true,
      pattern: '^(0|[1-9][0-9]*)$',
      type: 'string',
    });
  });
});
