import {
  parseMessageCreatedRealtimeEvent,
  realtimeApplicationStreamName,
  realtimeContractVersion,
} from '@kovcheg/contracts';
import type { RedisClientType } from 'redis';

import type { OutboxRepository } from './outbox.repository.js';

export class OutboxPublisher {
  constructor(
    private readonly repository: OutboxRepository,
    private readonly redis: Pick<RedisClientType, 'sendCommand'>,
  ) {}

  async publishOnce(): Promise<boolean> {
    const claimed = await this.repository.claimNext(30_000);
    if (claimed === null) {
      return false;
    }
    const event = parseMessageCreatedRealtimeEvent({
      contractVersion: realtimeContractVersion,
      correlationId: claimed.correlationId,
      eventId: claimed.eventId,
      eventName: claimed.eventName,
      occurredAt: claimed.occurredAt,
      payload: {
        chatId: claimed.payload.chatId,
        chatSequence: claimed.payload.chatSequence,
        messageId: claimed.payload.messageId,
      },
    });
    if (event === null) {
      await this.repository.release(claimed.eventId, claimed.claimToken);
      throw new Error('Outbox event violates the realtime contract');
    }
    try {
      await this.redis.sendCommand([
        'XADD',
        realtimeApplicationStreamName,
        '*',
        'event',
        JSON.stringify(event),
      ]);
      if (!(await this.repository.markPublished(claimed.eventId, claimed.claimToken))) {
        throw new Error('Outbox claim expired before publication was recorded');
      }
      return true;
    } catch (error) {
      await this.repository.release(claimed.eventId, claimed.claimToken).catch(() => undefined);
      throw error;
    }
  }
}
