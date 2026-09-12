import type { MessageHistoryPage, TextMessage, UserId, Uuid } from '@kovcheg/contracts';

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
  readonly historySequence: string;
  readonly items: readonly TimelineItem[];
  readonly lastSequence: string;
}

export function emptyMessageTimeline(): MessageTimelineState {
  return Object.freeze({ historySequence: '0', items: Object.freeze([]), lastSequence: '0' });
}

// Keep only local sends across a conversation switch. Reopening must read history anew.
export function pendingMessageTimeline(state: MessageTimelineState): MessageTimelineState {
  return Object.freeze({
    ...emptyMessageTimeline(),
    items: Object.freeze(state.items.filter((item) => item.kind === 'optimistic')),
  });
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
        // Stable sort preserves enqueue order, including a retry with the original ID.
        return 0;
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
    historySequence: state.historySequence,
    items: sortTimeline([...byMessageId.values()]),
    lastSequence,
  });
}

// Only an authoritative history page establishes a read cursor. A POST acknowledgement
// can arrive before earlier messages from another device have been read.
export function mergeReadHistory(
  state: MessageTimelineState,
  messages: readonly TextMessage[],
): MessageTimelineState {
  return Object.freeze({
    ...mergeStoredMessages(state, messages),
    historySequence: messages.reduce(
      (cursor, message) => sequenceMaximum(cursor, message.chatSequence),
      state.historySequence,
    ),
  });
}

export function createMessageHistoryCatchUp(
  input: Readonly<{
    readCursor: () => string | null;
    readPage: (cursor: string) => Promise<MessageHistoryPage | null>;
    applyPage: (messages: readonly TextMessage[]) => void;
    onFailure: () => void;
    onSuccess: () => void;
  }>,
) {
  let disposed = false;
  let running = false;
  let requested = false;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let retryDelay = 1_000;
  // Wait for the initial latest page before establishing the forward boundary.
  // Thereafter only this ordered drain advances it, across failures and yields;
  // a newer display/POST/subscribe response cannot skip an unread interval.
  let cursor: string | null = null;

  function scheduleRetry() {
    retry = setTimeout(() => {
      retry = undefined;
      request();
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, 10_000);
  }

  async function drain() {
    if (cursor === null) return;
    running = true;
    try {
      for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
        requested = false;
        const page = await input.readPage(cursor);
        if (disposed) return;
        if (
          page === null ||
          (page.hasMore &&
            (page.nextAfterSequence === null || BigInt(page.nextAfterSequence) <= BigInt(cursor)))
        ) {
          throw new Error('History catch-up unavailable');
        }
        input.applyPage(page.items);
        cursor =
          page.nextAfterSequence ??
          page.items.reduce(
            (current, message) => sequenceMaximum(current, message.chatSequence),
            cursor,
          );
        if (!page.hasMore && !requested) {
          retryDelay = 1_000;
          input.onSuccess();
          return;
        }
      }
      // Yield between bounded batches without abandoning unread history.
      scheduleRetry();
    } catch {
      if (!disposed) {
        input.onFailure();
        scheduleRetry();
      }
    } finally {
      running = false;
    }
  }

  function request() {
    if (disposed) return;
    cursor ??= input.readCursor();
    if (cursor === null) return;
    requested = true;
    if (retry !== undefined) clearTimeout(retry);
    retry = undefined;
    if (!running) void drain();
  }

  return Object.freeze({
    request,
    dispose() {
      disposed = true;
      if (retry !== undefined) clearTimeout(retry);
    },
  });
}
