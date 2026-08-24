import type { ChatSequence, TextMessage } from './message-flow.js';
import type { CorrelationId, UserId, Uuid } from './foundation-types.js';

export const realtimeContractVersion = 2 as const;
export const realtimeSocketPath = '/socket.io' as const;
export const realtimeApplicationStreamName = 'kovcheg:application-events:v1' as const;
export const realtimeAdapterStreamName = 'kovcheg:socket.io:v1' as const;
export const realtimeRelayConsumerGroup = 'realtime-relay' as const;

export const realtimeSocketEvents = Object.freeze({
  error: 'realtime.error',
  messageCreated: 'realtime.message-created',
  ready: 'realtime.ready',
  subscribe: 'realtime.subscribe',
} as const);

export interface MessageCreatedRealtimePayload {
  readonly chatId: Uuid;
  readonly chatSequence: ChatSequence;
  readonly messageId: Uuid;
  readonly senderAccountId: Uuid;
}

export interface MessageCreatedRealtimeEvent {
  readonly contractVersion: typeof realtimeContractVersion;
  readonly correlationId: CorrelationId;
  readonly eventId: Uuid;
  readonly eventName: 'message.created';
  readonly occurredAt: string;
  readonly payload: MessageCreatedRealtimePayload;
}

export interface RealtimeReadyEvent {
  readonly contractVersion: typeof realtimeContractVersion;
  readonly instanceId: string;
}

export interface RealtimeSubscribeRequest {
  readonly afterSequence: ChatSequence;
  readonly chatId: Uuid;
}

export interface RealtimeSubscribeResult {
  readonly contractVersion: typeof realtimeContractVersion;
  readonly history: readonly TextMessage[];
  readonly joined: boolean;
  readonly nextAfterSequence: ChatSequence;
}

export interface RealtimeSocketIdentity {
  readonly userId: UserId;
}

const uuidExpression =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const chatSequenceExpression = /^(0|[1-9][0-9]*)$/u;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function parseRealtimeSubscribeRequest(value: unknown): RealtimeSubscribeRequest | null {
  if (!isRecord(value)) {
    return null;
  }
  const { afterSequence, chatId } = value;
  if (
    typeof afterSequence !== 'string' ||
    !chatSequenceExpression.test(afterSequence) ||
    typeof chatId !== 'string' ||
    !uuidExpression.test(chatId)
  ) {
    return null;
  }
  return Object.freeze({ afterSequence, chatId: chatId as Uuid });
}

export function parseMessageCreatedRealtimeEvent(
  value: unknown,
): MessageCreatedRealtimeEvent | null {
  if (!isRecord(value) || !isRecord(value.payload)) {
    return null;
  }
  if (
    Object.keys(value).sort().join(',') !==
      'contractVersion,correlationId,eventId,eventName,occurredAt,payload' ||
    Object.keys(value.payload).sort().join(',') !== 'chatId,chatSequence,messageId,senderAccountId'
  ) {
    return null;
  }
  const { contractVersion, correlationId, eventId, eventName, occurredAt, payload } = value;
  const { chatId, chatSequence, messageId, senderAccountId } = payload;
  if (
    contractVersion !== realtimeContractVersion ||
    typeof correlationId !== 'string' ||
    correlationId.length < 1 ||
    correlationId.length > 128 ||
    typeof eventId !== 'string' ||
    !uuidExpression.test(eventId) ||
    eventName !== 'message.created' ||
    typeof occurredAt !== 'string' ||
    !Number.isFinite(Date.parse(occurredAt)) ||
    typeof chatId !== 'string' ||
    !uuidExpression.test(chatId) ||
    typeof chatSequence !== 'string' ||
    !chatSequenceExpression.test(chatSequence) ||
    typeof messageId !== 'string' ||
    !uuidExpression.test(messageId) ||
    typeof senderAccountId !== 'string' ||
    !uuidExpression.test(senderAccountId)
  ) {
    return null;
  }
  return Object.freeze({
    contractVersion,
    correlationId: correlationId as CorrelationId,
    eventId: eventId as Uuid,
    eventName,
    occurredAt,
    payload: Object.freeze({
      chatId: chatId as Uuid,
      chatSequence,
      messageId: messageId as Uuid,
      senderAccountId: senderAccountId as Uuid,
    }),
  });
}

export interface RealtimeEventDeduplicator {
  accept(event: Pick<MessageCreatedRealtimeEvent, 'eventId' | 'payload'>): boolean;
}

export function createRealtimeEventDeduplicator(capacity = 1_000): RealtimeEventDeduplicator {
  if (!Number.isSafeInteger(capacity) || capacity < 1) {
    throw new Error('Realtime deduplication capacity must be a positive safe integer');
  }
  const seen = new Map<string, true>();
  return Object.freeze({
    accept(event: Pick<MessageCreatedRealtimeEvent, 'eventId' | 'payload'>): boolean {
      const key = `${event.eventId}:${event.payload.messageId}`;
      if (seen.has(key)) {
        return false;
      }
      seen.set(key, true);
      if (seen.size > capacity) {
        const oldest = seen.keys().next().value as string | undefined;
        if (oldest !== undefined) {
          seen.delete(oldest);
        }
      }
      return true;
    },
  });
}
