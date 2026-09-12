import type { MessageHistoryPage, TextMessage, UserId, Uuid } from '@kovcheg/contracts';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  emptyMessageTimeline,
  createMessageHistoryCatchUp,
  enqueueOptimisticMessage,
  failOptimisticMessage,
  mergeStoredMessages,
  mergeReadHistory,
  pendingMessageTimeline,
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
  it('preserves insertion order despite reverse UUIDs, manual retry and late reconciliation', () => {
    const ids = [
      'web:ffffffff-ffff-4fff-8fff-ffffffffffff',
      'web:00000000-0000-4000-8000-000000000001',
    ];
    let state = emptyMessageTimeline();
    for (const [index, clientMessageId] of ids.entries()) {
      state = enqueueOptimisticMessage(state, {
        clientMessageId,
        senderUserId: userId,
        text: `Synthetic ${index}`,
      });
    }
    expect(state.items.map((item) => item.clientMessageId)).toEqual(ids);
    state = pendingMessageTimeline(failOptimisticMessage(state, ids[0]!));
    state = enqueueOptimisticMessage(state, {
      clientMessageId: ids[0]!,
      senderUserId: userId,
      text: 'Synthetic 0',
    });
    state = mergeStoredMessages(state, [sequenced(1)]);
    expect(
      state.items.filter((item) => item.kind === 'optimistic').map((item) => item.clientMessageId),
    ).toEqual(ids);
    state = mergeStoredMessages(state, [message(sequenced(2).id, ids[0]!, '2')]);
    state = failOptimisticMessage(state, ids[0]!);
    expect(
      state.items.filter((item) => item.kind === 'optimistic').map((item) => item.clientMessageId),
    ).toEqual([ids[1]]);
    expect(state.items.find((item) => item.clientMessageId === ids[0])?.kind).toBe('stored');
    expect(state.historySequence).toBe('0');
  });
  it('retains sending and failed items without retaining a history cursor across a switch', () => {
    let state = enqueueOptimisticMessage(emptyMessageTimeline(), {
      clientMessageId: 'web:pending-switch',
      senderUserId: userId,
      text: 'Synthetic pending',
    });
    state = enqueueOptimisticMessage(state, {
      clientMessageId: 'web:failed-switch',
      senderUserId: userId,
      text: 'Synthetic failed',
    });
    state = failOptimisticMessage(state, 'web:failed-switch');
    state = mergeReadHistory(state, [
      message('00000000-0000-4000-8000-000000000321' as Uuid, 'web:stored-switch', '41'),
    ]);
    const pending = pendingMessageTimeline(state);
    expect(pending.historySequence).toBe('0');
    expect(pending.lastSequence).toBe('0');
    expect(pending.items).toEqual(state.items.filter((item) => item.kind === 'optimistic'));
    expect(pending.items).toHaveLength(2);
    expect(pending.items.map((item) => item.kind === 'optimistic' && item.status).sort()).toEqual([
      'failed',
      'sending',
    ]);
  });

  it('keeps the original text and client ID for a manual retry after a late failure', () => {
    const sending = enqueueOptimisticMessage(emptyMessageTimeline(), {
      clientMessageId: 'web:late-failure',
      senderUserId: userId,
      text: 'Synthetic retained text',
    });
    const failed = pendingMessageTimeline(failOptimisticMessage(sending, 'web:late-failure'));
    expect(failed.items[0]).toMatchObject({ status: 'failed', text: 'Synthetic retained text' });
    const retry = enqueueOptimisticMessage(failed, {
      clientMessageId: 'web:late-failure',
      senderUserId: userId,
      text: 'Synthetic retained text',
    });
    expect(retry.items).toHaveLength(1);
    expect(retry.items[0]).toMatchObject({
      clientMessageId: 'web:late-failure',
      status: 'sending',
    });
  });

  it('removes pending state when an acknowledgement or history reconciles the send', () => {
    const sending = enqueueOptimisticMessage(emptyMessageTimeline(), {
      clientMessageId: 'web:late-success',
      senderUserId: userId,
      text: 'Synthetic text',
    });
    const stored = message(
      '00000000-0000-4000-8000-000000000322' as Uuid,
      'web:late-success',
      '42',
    );
    expect(pendingMessageTimeline(mergeStoredMessages(sending, [stored]))).toEqual(
      emptyMessageTimeline(),
    );
    expect(pendingMessageTimeline(mergeReadHistory(sending, [stored]))).toEqual(
      emptyMessageTimeline(),
    );
  });

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

function sequenced(sequence: number): TextMessage {
  return message(
    `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}` as Uuid,
    `web:sequence-${sequence}`,
    String(sequence),
  );
}

function page(items: readonly TextMessage[], hasMore = false): MessageHistoryPage {
  return {
    contractVersion: 3,
    items,
    hasMore,
    nextAfterSequence: hasMore ? (items.at(-1)?.chatSequence ?? null) : null,
    nextBeforeSequence: null,
  };
}

function catchUpFixture(readPage: (cursor: string) => Promise<MessageHistoryPage | null>) {
  let state = mergeReadHistory(emptyMessageTimeline(), [sequenced(1)]);
  const applyPage = vi.fn((items: readonly TextMessage[]) => {
    state = mergeReadHistory(state, items);
  });
  const onFailure = vi.fn();
  const onSuccess = vi.fn();
  const catchUp = createMessageHistoryCatchUp({
    readCursor: () => state.historySequence,
    readPage,
    applyPage,
    onFailure,
    onSuccess,
  });
  return {
    catchUp,
    applyPage,
    onFailure,
    onSuccess,
    state: () => state,
    acknowledge(item: TextMessage) {
      state = mergeStoredMessages(state, [item]);
    },
  };
}

describe('A6 read-history cursor and catch-up lifecycle', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it('waits for successful initial latest and starts at its boundary, not the beginning', async () => {
    let initialCursor: string | null = null;
    const readPage = vi.fn().mockResolvedValue(page([]));
    const catchUp = createMessageHistoryCatchUp({
      readCursor: () => initialCursor,
      readPage,
      applyPage: vi.fn(),
      onFailure: vi.fn(),
      onSuccess: vi.fn(),
    });
    // Online, visible, and message wakeups cannot initiate a scan while initial
    // latest is loading or failed; its successful retry establishes the baseline.
    catchUp.request();
    catchUp.request();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(readPage).not.toHaveBeenCalled();
    initialCursor = '500';
    catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(readPage.mock.calls).toEqual([['500']]);
    catchUp.dispose();
  });

  it.each(['latest-during-page', 'latest-before-subscribe-ack'] as const)(
    'never skips an unread range when %s for 500 messages',
    async (order) => {
      const all = Array.from({ length: 500 }, (_, index) => sequenced(index + 1));
      let state = mergeReadHistory(emptyMessageTimeline(), all.slice(0, 50));
      const initialCursor = state.historySequence;
      let release: (value: MessageHistoryPage) => void = () => undefined;
      const first = new Promise<MessageHistoryPage>((resolve) => {
        release = resolve;
      });
      const readPage = vi.fn(async (cursor: string) => {
        const remaining = all.filter((item) => BigInt(item.chatSequence) > BigInt(cursor));
        if (readPage.mock.calls.length === 1 && order === 'latest-during-page') return first;
        return page(remaining.slice(0, 100), remaining.length > 100);
      });
      const success = vi.fn();
      const catchUp = createMessageHistoryCatchUp({
        readCursor: () => initialCursor,
        readPage,
        applyPage: (items) => {
          state = mergeReadHistory(state, items);
        },
        onFailure: () => {
          throw new Error('Unexpected catch-up failure');
        },
        onSuccess: success,
      });
      if (order === 'latest-during-page') {
        state = mergeReadHistory(state, all.slice(0, 100));
        catchUp.request();
        state = mergeReadHistory(state, all.slice(450));
        release(
          page(
            all.slice(Number(readPage.mock.calls[0]![0]), Number(readPage.mock.calls[0]![0]) + 100),
            true,
          ),
        );
      } else {
        state = mergeReadHistory(state, all.slice(450));
        state = mergeReadHistory(state, all.slice(0, 100));
        catchUp.request();
      }
      await vi.advanceTimersByTimeAsync(0);
      expect(state.items.map((item) => item.id)).toEqual(all.map((item) => item.id));
      expect(success).toHaveBeenCalledOnce();
      catchUp.dispose();
    },
  );

  it('retains its lower bound through failure and a twenty-page yield despite newer history', async () => {
    let state = emptyMessageTimeline();
    let fail = true;
    const all = Array.from({ length: 23 }, (_, index) => sequenced(index + 1));
    const readPage = vi.fn(async (cursor: string) => {
      if (cursor === '1' && fail) {
        fail = false;
        return null;
      }
      const remaining = all.filter((item) => BigInt(item.chatSequence) > BigInt(cursor));
      return page(remaining.slice(0, 1), remaining.length > 1);
    });
    const success = vi.fn();
    const failure = vi.fn();
    const catchUp = createMessageHistoryCatchUp({
      readCursor: () => state.historySequence,
      readPage,
      applyPage: (items) => {
        state = mergeReadHistory(state, items);
      },
      onFailure: failure,
      onSuccess: success,
    });
    catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(failure).toHaveBeenCalledOnce();
    state = mergeReadHistory(state, [sequenced(23)]);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(success).not.toHaveBeenCalled();
    expect(readPage.mock.calls.at(-1)).toEqual(['20']);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(state.items.map((item) => item.id)).toEqual(all.map((item) => item.id));
    expect(readPage.mock.calls.map(([cursor]) => cursor)).toEqual([
      '0',
      '1',
      ...Array.from({ length: 22 }, (_, index) => String(index + 1)),
    ]);
    expect(success).toHaveBeenCalledOnce();
    catchUp.dispose();
  });

  it('reads missing sequence 2 after ACK 3, including on reconnect, without duplicate bubbles', async () => {
    const readPage = vi.fn().mockResolvedValue(page([sequenced(2), sequenced(3), sequenced(4)]));
    const fixture = catchUpFixture(readPage);
    fixture.acknowledge(sequenced(3));
    expect(fixture.state().lastSequence).toBe('3');
    expect(fixture.state().historySequence).toBe('1');
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(readPage).toHaveBeenCalledWith('1');
    expect(fixture.state().items.map((item) => item.id)).toEqual(
      [1, 2, 3, 4].map((sequence) => sequenced(sequence).id),
    );
    expect(fixture.state().historySequence).toBe('4');
    readPage.mockResolvedValue(page([]));
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(readPage).toHaveBeenLastCalledWith('4');
    expect(fixture.state().items).toHaveLength(4);
    fixture.catchUp.dispose();
  });

  it('does not let a late initial history response regress the read cursor or erase messages', () => {
    const complete = mergeReadHistory(emptyMessageTimeline(), [1, 2, 3, 4].map(sequenced));
    const late = mergeReadHistory(complete, [sequenced(1), sequenced(2)]);
    expect(late.historySequence).toBe('4');
    expect(late.items).toHaveLength(4);
  });

  it.each(['null', 'transport'] as const)(
    'retries a failed %s catch-up without needing another realtime event',
    async (failure) => {
      const readPage = vi.fn<(cursor: string) => Promise<MessageHistoryPage | null>>();
      if (failure === 'null') readPage.mockResolvedValueOnce(null);
      else readPage.mockRejectedValueOnce(new Error('Synthetic transport failure'));
      readPage.mockResolvedValue(page([sequenced(2)]));
      const fixture = catchUpFixture(readPage);
      fixture.catchUp.request();
      await vi.advanceTimersByTimeAsync(0);
      expect(fixture.onFailure).toHaveBeenCalledOnce();
      expect(fixture.state().historySequence).toBe('1');
      await vi.advanceTimersByTimeAsync(1_000);
      expect(readPage).toHaveBeenCalledTimes(2);
      expect(readPage).toHaveBeenLastCalledWith('1');
      expect(fixture.state().historySequence).toBe('2');
      expect(fixture.onSuccess).toHaveBeenCalledOnce();
      fixture.catchUp.dispose();
    },
  );

  it('coalesces events during an in-flight request, then reads again rather than losing the wakeup', async () => {
    let complete: (value: MessageHistoryPage) => void = () => undefined;
    const pending = new Promise<MessageHistoryPage>((resolve) => {
      complete = resolve;
    });
    const readPage = vi
      .fn()
      .mockReturnValueOnce(pending)
      .mockResolvedValue(page([sequenced(3)]));
    const fixture = catchUpFixture(readPage);
    fixture.catchUp.request();
    fixture.catchUp.request();
    fixture.catchUp.request();
    expect(readPage).toHaveBeenCalledTimes(1);
    complete(page([sequenced(2)]));
    await vi.advanceTimersByTimeAsync(0);
    expect(readPage.mock.calls).toEqual([['1'], ['2']]);
    expect(fixture.state().historySequence).toBe('3');
    fixture.catchUp.dispose();
  });

  it('walks paginated history from the read cursor, not a newer isolated acknowledgement', async () => {
    const readPage = vi
      .fn()
      .mockResolvedValueOnce(page([sequenced(2)], true))
      .mockResolvedValueOnce(page([sequenced(3)], true))
      .mockResolvedValueOnce(page([sequenced(4)]));
    const fixture = catchUpFixture(readPage);
    fixture.acknowledge(sequenced(4));
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(readPage.mock.calls).toEqual([['1'], ['2'], ['3']]);
    expect(fixture.state().items).toHaveLength(4);
    fixture.catchUp.dispose();
  });

  it('rejects a non-advancing pagination cursor without applying it', async () => {
    const readPage = vi
      .fn()
      .mockResolvedValue({ ...page([sequenced(2)], true), nextAfterSequence: '1' });
    const fixture = catchUpFixture(readPage);
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    expect(fixture.applyPage).not.toHaveBeenCalled();
    expect(fixture.onFailure).toHaveBeenCalledOnce();
    fixture.catchUp.dispose();
  });

  it('cancels retry timers on chat disposal and ignores later requests', async () => {
    const readPage = vi.fn().mockResolvedValue(null);
    const fixture = catchUpFixture(readPage);
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    fixture.catchUp.dispose();
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(readPage).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores a late response from a disposed previous chat even when transport did not abort', async () => {
    let complete: (value: MessageHistoryPage) => void = () => undefined;
    const pending = new Promise<MessageHistoryPage>((resolve) => {
      complete = resolve;
    });
    const fixture = catchUpFixture(() => pending);
    fixture.catchUp.request();
    fixture.catchUp.dispose();
    complete(page([sequenced(99)]));
    await vi.advanceTimersByTimeAsync(0);
    expect(fixture.applyPage).not.toHaveBeenCalled();
    expect(fixture.onSuccess).not.toHaveBeenCalled();
    expect(fixture.onFailure).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('bounds retry backoff to ten seconds without concurrent requests', async () => {
    const readPage = vi.fn().mockResolvedValue(null);
    const fixture = catchUpFixture(readPage);
    fixture.catchUp.request();
    await vi.advanceTimersByTimeAsync(0);
    for (const delay of [1_000, 2_000, 4_000, 8_000, 10_000, 10_000]) {
      const previousCalls = readPage.mock.calls.length;
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(readPage).toHaveBeenCalledTimes(previousCalls);
      await vi.advanceTimersByTimeAsync(1);
      expect(readPage).toHaveBeenCalledTimes(previousCalls + 1);
    }
    fixture.catchUp.dispose();
  });
});
