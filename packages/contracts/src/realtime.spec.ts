import { describe, expect, it } from 'vitest';

import type { CorrelationId, Uuid } from './index.js';
import {
  createRealtimeEventDeduplicator,
  parseMessageCreatedRealtimeEvent,
  parseRealtimeSubscribeRequest,
  realtimeContractVersion,
} from './realtime.js';

const eventId = '00000000-0000-4000-8000-000000005001' as Uuid;
const messageId = '00000000-0000-4000-8000-000000005002' as Uuid;

function event() {
  return {
    contractVersion: realtimeContractVersion,
    correlationId: 'realtime-contract-001' as CorrelationId,
    eventId,
    eventName: 'message.created' as const,
    occurredAt: '2026-01-01T00:00:00.000Z',
    payload: {
      chatId: '00000000-0000-4000-8000-000000005003' as Uuid,
      chatSequence: '7',
      messageId,
    },
  };
}

describe('realtime contracts', () => {
  it('parses only sanitized message-created events', () => {
    expect(parseMessageCreatedRealtimeEvent(event())).toEqual(event());
    expect(
      parseMessageCreatedRealtimeEvent({ ...event(), payload: { ...event().payload, body: 'x' } }),
    ).toBeNull();
    expect(parseMessageCreatedRealtimeEvent({ ...event(), eventId: 'invalid' })).toBeNull();
  });

  it('parses a bounded reconnect cursor', () => {
    expect(
      parseRealtimeSubscribeRequest({
        afterSequence: '0',
        chatId: '00000000-0000-4000-8000-000000005003',
      }),
    ).toEqual({
      afterSequence: '0',
      chatId: '00000000-0000-4000-8000-000000005003',
    });
    expect(
      parseRealtimeSubscribeRequest({ afterSequence: '-1', chatId: event().payload.chatId }),
    ).toBeNull();
  });

  it('deduplicates at-least-once delivery by event and message IDs', () => {
    const deduplicator = createRealtimeEventDeduplicator(2);
    expect(deduplicator.accept(event())).toBe(true);
    expect(deduplicator.accept(event())).toBe(false);

    const second = {
      ...event(),
      eventId: '00000000-0000-4000-8000-000000005004' as Uuid,
    };
    const third = {
      ...event(),
      eventId: '00000000-0000-4000-8000-000000005005' as Uuid,
    };
    expect(deduplicator.accept(second)).toBe(true);
    expect(deduplicator.accept(third)).toBe(true);
    expect(deduplicator.accept(event())).toBe(true);
  });
});
