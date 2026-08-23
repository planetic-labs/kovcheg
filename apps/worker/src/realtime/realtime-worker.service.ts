import { Inject, Injectable, Logger } from '@nestjs/common';
import type { OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { createClient } from 'redis';

import { OutboxPublisher } from './outbox-publisher.js';
import { createPostgresOutboxRepository } from './outbox.repository.js';
import { RealtimeRelay } from './realtime-relay.js';
import type { RealtimeWorkerOptions } from './realtime.config.js';

export const realtimeWorkerOptionsToken = Symbol('realtimeWorkerOptions');

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
}

@Injectable()
export class RealtimeWorkerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly abort = new AbortController();
  private readonly logger = new Logger(RealtimeWorkerService.name);
  private publisherClient: ReturnType<typeof createClient> | null = null;
  private relayClient: ReturnType<typeof createClient> | null = null;
  private repository: ReturnType<typeof createPostgresOutboxRepository> | null = null;
  private loops: readonly Promise<void>[] = Object.freeze([]);

  constructor(
    @Inject(realtimeWorkerOptionsToken)
    private readonly options: RealtimeWorkerOptions | null,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (this.options === null) {
      return;
    }
    this.repository = createPostgresOutboxRepository();
    this.publisherClient = createClient({ url: this.options.redisUrl });
    this.relayClient = this.publisherClient.duplicate();
    this.publisherClient.on('error', () => undefined);
    this.relayClient.on('error', () => undefined);
    await Promise.all([this.publisherClient.connect(), this.relayClient.connect()]);

    const publisher = new OutboxPublisher(this.repository, this.publisherClient);
    const relay = new RealtimeRelay(
      this.relayClient,
      this.options.consumerName,
      this.options.relayUrl,
      this.options.relayToken,
    );
    this.loops = Object.freeze([
      this.publisherLoop(publisher, this.abort.signal),
      this.relayLoop(relay, this.abort.signal),
    ]);
  }

  async onApplicationShutdown(): Promise<void> {
    this.abort.abort();
    await Promise.all(this.loops);
    await Promise.all([
      this.publisherClient?.quit().catch(() => undefined),
      this.relayClient?.quit().catch(() => undefined),
      this.repository?.close().catch(() => undefined),
    ]);
  }

  private async publisherLoop(publisher: OutboxPublisher, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        if (!(await publisher.publishOnce())) {
          await delay(200, signal);
        }
      } catch {
        this.logger.warn('Outbox publication temporarily unavailable');
        await delay(500, signal);
      }
    }
  }

  private async relayLoop(relay: RealtimeRelay, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        await relay.relayOnce();
      } catch {
        relay.resetGroup();
        this.logger.warn('Realtime relay temporarily unavailable');
        await delay(500, signal);
      }
    }
  }
}
