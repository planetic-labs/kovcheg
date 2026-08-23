import {
  parseMessageCreatedRealtimeEvent,
  realtimeApplicationStreamName,
  realtimeRelayConsumerGroup,
} from '@kovcheg/contracts';
import type { MessageCreatedRealtimeEvent } from '@kovcheg/contracts';
import type { RedisClientType } from 'redis';

interface StreamEntry {
  readonly id: string;
  readonly value: string;
}

function parseFieldArray(value: unknown): string | null {
  if (!Array.isArray(value)) {
    return null;
  }
  for (let index = 0; index < value.length - 1; index += 2) {
    if (value[index] === 'event' && typeof value[index + 1] === 'string') {
      return value[index + 1];
    }
  }
  return null;
}

function parseEntries(value: unknown): readonly StreamEntry[] {
  if (!Array.isArray(value)) {
    return Object.freeze([]);
  }
  const result: StreamEntry[] = [];
  for (const item of value) {
    if (!Array.isArray(item) || typeof item[0] !== 'string') {
      continue;
    }
    const event = parseFieldArray(item[1]);
    if (event !== null) {
      result.push(Object.freeze({ id: item[0], value: event }));
    }
  }
  return Object.freeze(result);
}

export function parseXReadGroupReply(value: unknown): readonly StreamEntry[] {
  if (!Array.isArray(value)) {
    return Object.freeze([]);
  }
  const stream = value[0];
  return Array.isArray(stream) ? parseEntries(stream[1]) : Object.freeze([]);
}

export function parseXAutoClaimReply(value: unknown): readonly StreamEntry[] {
  return Array.isArray(value) ? parseEntries(value[1]) : Object.freeze([]);
}

export class RealtimeRelay {
  private groupReady = false;

  constructor(
    private readonly redis: Pick<RedisClientType, 'sendCommand'>,
    private readonly consumerName: string,
    private readonly relayUrl: string,
    private readonly relayToken: string,
    private readonly deliver: typeof fetch = fetch,
  ) {}

  async relayOnce(): Promise<boolean> {
    await this.ensureGroup();
    const reclaimed = parseXAutoClaimReply(
      await this.redis.sendCommand([
        'XAUTOCLAIM',
        realtimeApplicationStreamName,
        realtimeRelayConsumerGroup,
        this.consumerName,
        '5000',
        '0-0',
        'COUNT',
        '20',
      ]),
    );
    const entries =
      reclaimed.length > 0
        ? reclaimed
        : parseXReadGroupReply(
            await this.redis.sendCommand([
              'XREADGROUP',
              'GROUP',
              realtimeRelayConsumerGroup,
              this.consumerName,
              'COUNT',
              '20',
              'BLOCK',
              '1000',
              'STREAMS',
              realtimeApplicationStreamName,
              '>',
            ]),
          );
    if (entries.length === 0) {
      return false;
    }
    for (const entry of entries) {
      const event = this.parseEvent(entry.value);
      if (event === null || (await this.deliverEvent(event))) {
        await this.acknowledge(entry.id);
      }
    }
    return true;
  }

  resetGroup(): void {
    this.groupReady = false;
  }

  private async ensureGroup(): Promise<void> {
    if (this.groupReady) {
      return;
    }
    try {
      await this.redis.sendCommand([
        'XGROUP',
        'CREATE',
        realtimeApplicationStreamName,
        realtimeRelayConsumerGroup,
        '0',
        'MKSTREAM',
      ]);
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes('BUSYGROUP')) {
        throw error;
      }
    }
    this.groupReady = true;
  }

  private parseEvent(value: string): MessageCreatedRealtimeEvent | null {
    try {
      return parseMessageCreatedRealtimeEvent(JSON.parse(value) as unknown);
    } catch {
      return null;
    }
  }

  private async deliverEvent(event: MessageCreatedRealtimeEvent): Promise<boolean> {
    try {
      const response = await this.deliver(this.relayUrl, {
        body: JSON.stringify(event),
        headers: {
          authorization: `Bearer ${this.relayToken}`,
          'content-type': 'application/json',
        },
        method: 'POST',
        signal: AbortSignal.timeout(5_000),
      });
      return response.status === 202;
    } catch {
      return false;
    }
  }

  private async acknowledge(entryId: string): Promise<void> {
    await this.redis.sendCommand([
      'XACK',
      realtimeApplicationStreamName,
      realtimeRelayConsumerGroup,
      entryId,
    ]);
  }
}
