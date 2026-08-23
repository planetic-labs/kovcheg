import type { MessageCreatedRealtimeEvent, Uuid } from '@kovcheg/contracts';

export interface RealtimeProjectionState {
  readonly acceptedEventIds: readonly Uuid[];
}

export function emptyRealtimeProjection(): RealtimeProjectionState {
  return Object.freeze({ acceptedEventIds: Object.freeze([]) });
}

export function acceptRealtimeEvent(
  state: RealtimeProjectionState,
  event: Pick<MessageCreatedRealtimeEvent, 'eventId'>,
  capacity = 1_000,
): Readonly<{ accepted: boolean; state: RealtimeProjectionState }> {
  if (state.acceptedEventIds.includes(event.eventId)) {
    return Object.freeze({ accepted: false, state });
  }
  const acceptedEventIds = [...state.acceptedEventIds, event.eventId].slice(-capacity);
  return Object.freeze({
    accepted: true,
    state: Object.freeze({ acceptedEventIds: Object.freeze(acceptedEventIds) }),
  });
}
