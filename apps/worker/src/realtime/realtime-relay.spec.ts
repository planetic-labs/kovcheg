import { describe, expect, it, vi } from 'vitest';

import type { RedisClientType } from 'redis';

import { RealtimeRelay, parseXAutoClaimReply, parseXReadGroupReply } from './realtime-relay.js';

const serializedEvent = JSON.stringify({
  contractVersion: 2,
  correlationId: 'realtime-relay-001',
  eventId: '00000000-0000-4000-8000-000000005301',
  eventName: 'message.created',
  occurredAt: '2026-01-01T00:00:00.000Z',
  payload: {
    chatId: '00000000-0000-4000-8000-000000005302',
    chatSequence: '12',
    messageId: '00000000-0000-4000-8000-000000005303',
    senderAccountId: '00000000-0000-4000-8000-000000005304',
  },
});

describe('realtime relay', () => {
  it('parses new and reclaimed Redis Stream entries', () => {
    const entries = [['1-0', ['event', serializedEvent]]];
    expect(parseXReadGroupReply([['stream', entries]])).toEqual([
      { id: '1-0', value: serializedEvent },
    ]);
    expect(parseXAutoClaimReply(['0-0', entries, []])).toEqual([
      { id: '1-0', value: serializedEvent },
    ]);
  });

  it('acknowledges only after one API accepted the relay request', async () => {
    const sendCommand = vi
      .fn()
      .mockResolvedValueOnce('OK')
      .mockResolvedValueOnce(['0-0', [], []])
      .mockResolvedValueOnce([['stream', [['1-0', ['event', serializedEvent]]]]])
      .mockResolvedValueOnce(1);
    const deliver = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    const relay = new RealtimeRelay(
      { sendCommand } as unknown as Pick<RedisClientType, 'sendCommand'>,
      'worker-test',
      'http://edge:8080/api/internal/realtime/events',
      'realtime-test-token-0000000000000001',
      deliver,
    );

    await expect(relay.relayOnce()).resolves.toBe(true);
    expect(deliver).toHaveBeenCalledWith(
      'http://edge:8080/api/internal/realtime/events',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(sendCommand).toHaveBeenLastCalledWith([
      'XACK',
      'kovcheg:application-events:v1',
      'realtime-relay',
      '1-0',
    ]);
  });

  it('keeps the entry pending when every API delivery attempt fails', async () => {
    const sendCommand = vi
      .fn()
      .mockResolvedValueOnce('OK')
      .mockResolvedValueOnce(['0-0', [], []])
      .mockResolvedValueOnce([['stream', [['1-0', ['event', serializedEvent]]]]]);
    const relay = new RealtimeRelay(
      { sendCommand } as unknown as Pick<RedisClientType, 'sendCommand'>,
      'worker-test',
      'http://edge:8080/api/internal/realtime/events',
      'realtime-test-token-0000000000000001',
      vi.fn().mockResolvedValue(new Response(null, { status: 503 })),
    );

    await expect(relay.relayOnce()).resolves.toBe(true);
    expect(sendCommand).toHaveBeenCalledTimes(3);
  });
});
