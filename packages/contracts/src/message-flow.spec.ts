import { describe, expect, it } from 'vitest';

import {
  createTextMessageRequestJsonSchema,
  identityStubHeaderName,
  messageFlowContractVersion,
  messageFlowErrorCodes,
  messageHistoryPageJsonSchema,
} from './message-flow.js';

describe('message-flow contracts', () => {
  it('publishes a versioned synthetic identity and error boundary', () => {
    expect(messageFlowContractVersion).toBe(1);
    expect(identityStubHeaderName).toBe('x-kovcheg-identity-stub-user-id');
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
