import type { TextMessage, UserId, Uuid } from '@kovcheg/contracts';

export type TimelineItem =
  | {
      readonly clientMessageId: string;
      readonly id: string;
      readonly kind: 'optimistic';
      readonly senderUserId: UserId;
      readonly status: 'failed' | 'sending';
      readonly text: string;
    }
  | {
      readonly clientMessageId: string;
      readonly id: Uuid;
      readonly kind: 'stored';
      readonly message: TextMessage;
    };

export interface MessageTimelineState {
  readonly items: readonly TimelineItem[];
  readonly lastSequence: string;
}

export function emptyMessageTimeline(): MessageTimelineState {
  return Object.freeze({ items: Object.freeze([]), lastSequence: '0' });
}

function sequenceMaximum(left: string, right: string): string {
  return BigInt(left) >= BigInt(right) ? left : right;
}

function storedItem(message: TextMessage): TimelineItem {
  return Object.freeze({
    clientMessageId: message.clientMessageId,
    id: message.id,
    kind: 'stored',
    message,
  });
}

function sortTimeline(items: readonly TimelineItem[]): readonly TimelineItem[] {
  return Object.freeze(
    [...items].sort((left, right) => {
      if (left.kind === 'optimistic' && right.kind === 'optimistic') {
        return left.clientMessageId.localeCompare(right.clientMessageId);
      }
      if (left.kind === 'optimistic') {
        return 1;
      }
      if (right.kind === 'optimistic') {
        return -1;
      }
      const bySequence = BigInt(left.message.chatSequence) - BigInt(right.message.chatSequence);
      return bySequence === 0n ? left.id.localeCompare(right.id) : bySequence < 0n ? -1 : 1;
    }),
  );
}

export function enqueueOptimisticMessage(
  state: MessageTimelineState,
  input: Readonly<{ clientMessageId: string; senderUserId: UserId; text: string }>,
): MessageTimelineState {
  const current = state.items.find((item) => item.clientMessageId === input.clientMessageId);
  if (current !== undefined) {
    const items = state.items.map((item) =>
      item.clientMessageId === input.clientMessageId && item.kind === 'optimistic'
        ? Object.freeze({ ...item, status: 'sending' as const })
        : item,
    );
    return Object.freeze({ ...state, items: Object.freeze(items) });
  }
  const optimistic: TimelineItem = Object.freeze({
    clientMessageId: input.clientMessageId,
    id: `optimistic:${input.clientMessageId}`,
    kind: 'optimistic',
    senderUserId: input.senderUserId,
    status: 'sending',
    text: input.text,
  });
  return Object.freeze({ ...state, items: sortTimeline([...state.items, optimistic]) });
}

export function failOptimisticMessage(
  state: MessageTimelineState,
  clientMessageId: string,
): MessageTimelineState {
  return Object.freeze({
    ...state,
    items: Object.freeze(
      state.items.map((item) =>
        item.clientMessageId === clientMessageId && item.kind === 'optimistic'
          ? Object.freeze({ ...item, status: 'failed' as const })
          : item,
      ),
    ),
  });
}

export function mergeStoredMessages(
  state: MessageTimelineState,
  messages: readonly TextMessage[],
): MessageTimelineState {
  const byMessageId = new Map<string, TimelineItem>();
  const storedClientIds = new Set(messages.map((message) => message.clientMessageId));

  for (const item of state.items) {
    if (item.kind === 'optimistic') {
      if (!storedClientIds.has(item.clientMessageId)) {
        byMessageId.set(item.id, item);
      }
      continue;
    }
    byMessageId.set(item.id, item);
  }
  let lastSequence = state.lastSequence;
  for (const message of messages) {
    byMessageId.set(message.id, storedItem(message));
    lastSequence = sequenceMaximum(lastSequence, message.chatSequence);
  }

  return Object.freeze({
    items: sortTimeline([...byMessageId.values()]),
    lastSequence,
  });
}
