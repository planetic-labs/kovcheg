import { describe, expect, it, vi } from 'vitest';

import type { CorrelationId, Uuid } from '@kovcheg/contracts';
import type { RedisClientType } from 'redis';

import { OutboxPublisher } from './outbox-publisher.js';
import type { OutboxRepository } from './outbox.repository.js';

const claimed = Object.freeze({
  claimToken: '00000000-0000-4000-8000-000000005201' as Uuid,
  correlationId: 'outbox-publisher-001' as CorrelationId,
  eventId: '00000000-0000-4000-8000-000000005202' as Uuid,
  eventName: 'message.created',
  occurredAt: '2026-01-01T00:00:00.000Z',
  payload: Object.freeze({
    chatId: '00000000-0000-4000-8000-000000005203',
    chatSequence: '9',
    messageId: '00000000-0000-4000-8000-000000005204',
    senderAccountId: '00000000-0000-4000-8000-000000005205',
  }),
});

describe('outbox publisher', () => {
  it('records delivery only after Redis accepts the immutable event ID', async () => {
    const repository: OutboxRepository = {
      claimNext: vi.fn().mockResolvedValue(claimed),
      markPublished: vi.fn().mockResolvedValue(true),
      release: vi.fn().mockResolvedValue(undefined),
    };
    const sendCommand = vi.fn().mockResolvedValue('1-0');
    const publisher = new OutboxPublisher(repository, { sendCommand } as unknown as Pick<
      RedisClientType,
      'sendCommand'
    >);

    await expect(publisher.publishOnce()).resolves.toBe(true);
    expect(sendCommand).toHaveBeenCalledWith([
      'XADD',
      'kovcheg:application-events:v1',
      '*',
      'event',
      expect.any(String),
    ]);
    const serialized = (sendCommand.mock.calls[0]?.[0] as string[] | undefined)?.[4];
    expect(JSON.parse(serialized ?? '{}')).toMatchObject({
      contractVersion: 2,
      payload: {
        chatSequence: '9',
        senderAccountId: claimed.payload.senderAccountId,
      },
    });
    expect(serialized).not.toContain('operatorAccountId');
    expect(repository.markPublished).toHaveBeenCalledWith(claimed.eventId, claimed.claimToken);
    expect(repository.release).not.toHaveBeenCalled();
  });

  it('releases the PostgreSQL lease when Redis is unavailable', async () => {
    const repository: OutboxRepository = {
      claimNext: vi.fn().mockResolvedValue(claimed),
      markPublished: vi.fn().mockResolvedValue(true),
      release: vi.fn().mockResolvedValue(undefined),
    };
    const publisher = new OutboxPublisher(repository, {
      sendCommand: vi.fn().mockRejectedValue(new Error('redis unavailable')),
    } as unknown as Pick<RedisClientType, 'sendCommand'>);

    await expect(publisher.publishOnce()).rejects.toThrow('redis unavailable');
    expect(repository.markPublished).not.toHaveBeenCalled();
    expect(repository.release).toHaveBeenCalledWith(claimed.eventId, claimed.claimToken);
  });
});
