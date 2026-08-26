import type { MessageCreatedRealtimeEvent, Uuid } from '@kovcheg/contracts';
import { describe, expect, it } from 'vitest';

import { acceptRealtimeEvent, emptyRealtimeProjection } from './realtime-state';

const event = Object.freeze({
  eventId: '00000000-0000-4000-8000-000000000403' as Uuid,
}) satisfies Pick<MessageCreatedRealtimeEvent, 'eventId'>;

describe('A6 realtime projection', () => {
  it('accepts one event and deduplicates its ID after reconnect', () => {
    const first = acceptRealtimeEvent(emptyRealtimeProjection(), event);
    const repeated = acceptRealtimeEvent(first.state, event);

    expect(first.accepted).toBe(true);
    expect(repeated.accepted).toBe(false);
    expect(repeated.state).toBe(first.state);
  });

  it('keeps a bounded event-ID window', () => {
    const first = acceptRealtimeEvent(emptyRealtimeProjection(), event, 1);
    const second = acceptRealtimeEvent(
      first.state,
      { eventId: '00000000-0000-4000-8000-000000000404' as Uuid },
      1,
    );

    expect(second.state.acceptedEventIds).toEqual(['00000000-0000-4000-8000-000000000404']);
  });
});
