import { Inject, Injectable, Logger } from '@nestjs/common';
import type { OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { createClient } from 'redis';
import type { RedisClientType } from 'redis';

import { OutboxPublisher } from './outbox-publisher.js';
import { createPostgresOutboxRepository } from './outbox.repository.js';
import { RealtimeRelay } from './realtime-relay.js';
import type { RealtimeWorkerOptions } from './realtime.config.js';

export const realtimeWorkerOptionsToken = Symbol('realtimeWorkerOptions');
export const realtimeWorkerDependenciesToken = Symbol('realtimeWorkerDependencies');

type RedisWorkerClient = Pick<
  RedisClientType,
  'close' | 'connect' | 'duplicate' | 'on' | 'sendCommand'
>;
type RealtimeOutboxRepository = ReturnType<typeof createPostgresOutboxRepository>;

export interface RealtimeWorkerDependencies {
  createRedisClient(url: string): RedisWorkerClient;
  createRepository(): RealtimeOutboxRepository;
}

export const defaultRealtimeWorkerDependencies: RealtimeWorkerDependencies = Object.freeze({
  createRedisClient: (url: string) => createClient({ url }),
  createRepository: () => createPostgresOutboxRepository(),
});

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const finish = () => {
      clearTimeout(timeout);
      signal.removeEventListener('abort', finish);
      resolve();
    };
    const timeout = setTimeout(finish, milliseconds);
    signal.addEventListener('abort', finish, { once: true });
  });
}

@Injectable()
export class RealtimeWorkerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly abort = new AbortController();
  private readonly logger = new Logger(RealtimeWorkerService.name);
  private cleanupPromise: Promise<void> | null = null;
  private publisherClient: RedisWorkerClient | null = null;
  private relayClient: RedisWorkerClient | null = null;
  private repository: RealtimeOutboxRepository | null = null;
  private loops: readonly Promise<void>[] = Object.freeze([]);

  constructor(
    @Inject(realtimeWorkerOptionsToken)
    private readonly options: RealtimeWorkerOptions | null,
    @Inject(realtimeWorkerDependenciesToken)
    private readonly dependencies: RealtimeWorkerDependencies,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (this.options === null) {
      return;
    }
    try {
      this.repository = this.dependencies.createRepository();
      this.publisherClient = this.dependencies.createRedisClient(this.options.redisUrl);
      this.relayClient = this.publisherClient.duplicate();
      this.publisherClient.on('error', () => undefined);
      this.relayClient.on('error', () => undefined);
      const connectionResults = await Promise.allSettled([
        this.publisherClient.connect(),
        this.relayClient.connect(),
      ]);
      const connectionFailure = connectionResults.find(
        (result): result is PromiseRejectedResult => result.status === 'rejected',
      );
      if (connectionFailure !== undefined) {
        throw connectionFailure.reason;
      }

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
    } catch (error) {
      await this.cleanup();
      throw error;
    }
  }

  async onApplicationShutdown(): Promise<void> {
    await this.cleanup();
  }

  private cleanup(): Promise<void> {
    this.cleanupPromise ??= this.cleanupResources();
    return this.cleanupPromise;
  }

  private async cleanupResources(): Promise<void> {
    this.abort.abort();
    await Promise.allSettled(this.loops);
    this.loops = Object.freeze([]);

    const publisherClient = this.publisherClient;
    const relayClient = this.relayClient;
    const repository = this.repository;
    this.publisherClient = null;
    this.relayClient = null;
    this.repository = null;
    await Promise.allSettled([
      Promise.resolve().then(() => publisherClient?.close()),
      Promise.resolve().then(() => relayClient?.close()),
      Promise.resolve().then(() => repository?.close()),
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
