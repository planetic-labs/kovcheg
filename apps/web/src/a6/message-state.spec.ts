import type { TextMessage, UserId, Uuid } from '@kovcheg/contracts';
import { describe, expect, it } from 'vitest';

import {
  emptyMessageTimeline,
  enqueueOptimisticMessage,
  failOptimisticMessage,
  mergeStoredMessages,
} from './message-state';

const userId = '00000000-0000-4000-8000-000000000101' as UserId;
const chatId = '00000000-0000-4000-8000-000000000201' as Uuid;

function message(id: Uuid, clientMessageId: string, chatSequence: string): TextMessage {
  return Object.freeze({
    body: 'Synthetic text',
    chatId,
    chatSequence,
    clientMessageId,
    createdAt: '2026-08-23T00:00:00.000Z',
    id,
    senderAccountId: userId,
  });
}

describe('A6 optimistic message timeline', () => {
  it('reuses one optimistic bubble for a retry with the same client message ID', () => {
    const first = enqueueOptimisticMessage(emptyMessageTimeline(), {
      clientMessageId: 'web:retry-001',
      senderUserId: userId,
      text: 'Synthetic text',
    });
    const failed = failOptimisticMessage(first, 'web:retry-001');
    const retried = enqueueOptimisticMessage(failed, {
      clientMessageId: 'web:retry-001',
      senderUserId: userId,
      text: 'Synthetic text',
    });

    expect(retried.items).toHaveLength(1);
    expect(retried.items[0]).toMatchObject({ kind: 'optimistic', status: 'sending' });
  });

  it('reconciles created and replayed responses into the same stored message', () => {
    const optimistic = enqueueOptimisticMessage(emptyMessageTimeline(), {
      clientMessageId: 'web:replay-001',
      senderUserId: userId,
      text: 'Synthetic text',
    });
    const stored = message('00000000-0000-4000-8000-000000000301' as Uuid, 'web:replay-001', '8');
    const created = mergeStoredMessages(optimistic, [stored]);
    const replayed = mergeStoredMessages(created, [stored]);

    expect(replayed.items).toHaveLength(1);
    expect(replayed.items[0]).toMatchObject({ id: stored.id, kind: 'stored' });
    expect(replayed.lastSequence).toBe('8');
  });

  it('deduplicates history by message ID while advancing the catch-up cursor', () => {
    const first = message('00000000-0000-4000-8000-000000000311' as Uuid, 'web:history-001', '9');
    const second = message('00000000-0000-4000-8000-000000000312' as Uuid, 'web:history-002', '10');
    const state = mergeStoredMessages(emptyMessageTimeline(), [first, first, second]);

    expect(state.items).toHaveLength(2);
    expect(state.lastSequence).toBe('10');
  });
});
