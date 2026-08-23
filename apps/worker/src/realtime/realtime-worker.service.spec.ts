import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type RealtimeWorkerDependencies,
  RealtimeWorkerService,
} from './realtime-worker.service.js';
import type { RealtimeWorkerOptions } from './realtime.config.js';

type RedisWorkerClient = ReturnType<RealtimeWorkerDependencies['createRedisClient']>;
type RealtimeOutboxRepository = ReturnType<RealtimeWorkerDependencies['createRepository']>;

const options: RealtimeWorkerOptions = Object.freeze({
  consumerName: 'worker-test',
  redisUrl: 'redis://redis:6379',
  relayToken: 'realtime-test-token-0000000000000001',
  relayUrl: 'http://edge:8081/internal/realtime/events',
});

function createRedisDouble(connect: () => Promise<void> = () => Promise.resolve()) {
  return {
    close: vi.fn().mockResolvedValue(undefined),
    connect: vi.fn(connect),
    duplicate: vi.fn(),
    on: vi.fn(),
    sendCommand: vi.fn().mockRejectedValue(new Error('synthetic loop pause')),
  };
}

function createRepositoryDouble() {
  return {
    claimNext: vi.fn().mockResolvedValue(null),
    close: vi.fn().mockResolvedValue(undefined),
    markPublished: vi.fn().mockResolvedValue(true),
    release: vi.fn().mockResolvedValue(undefined),
  };
}

function createHarness(
  publisher = createRedisDouble(),
  relay = createRedisDouble(),
  repository = createRepositoryDouble(),
) {
  publisher.duplicate.mockReturnValue(relay as unknown as RedisWorkerClient);
  const dependencies: RealtimeWorkerDependencies = {
    createRedisClient: vi.fn().mockReturnValue(publisher as unknown as RedisWorkerClient),
    createRepository: vi.fn().mockReturnValue(repository as unknown as RealtimeOutboxRepository),
  };
  return {
    publisher,
    relay,
    repository,
    service: new RealtimeWorkerService(options, dependencies),
  };
}

beforeEach(() => {
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('RealtimeWorkerService lifecycle', () => {
  it('connects both Redis clients and closes every resource after a successful start', async () => {
    vi.useFakeTimers();
    const { publisher, relay, repository, service } = createHarness();

    await service.onApplicationBootstrap();
    await Promise.resolve();
    await Promise.resolve();

    expect(publisher.connect).toHaveBeenCalledOnce();
    expect(relay.connect).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    await service.onApplicationShutdown();

    expect(publisher.close).toHaveBeenCalledOnce();
    expect(relay.close).toHaveBeenCalledOnce();
    expect(repository.close).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rejects startup and closes all resources when only one Redis client connects', async () => {
    vi.useFakeTimers();
    const startupFailure = new Error('synthetic relay connection failure');
    const publisher = createRedisDouble();
    const relay = createRedisDouble(() => Promise.reject(startupFailure));
    const { repository, service } = createHarness(publisher, relay);

    await expect(service.onApplicationBootstrap()).rejects.toBe(startupFailure);

    expect(publisher.close).toHaveBeenCalledOnce();
    expect(relay.close).toHaveBeenCalledOnce();
    expect(repository.close).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('closes each resource created before a synchronous initialization failure', async () => {
    const startupFailure = new Error('synthetic duplicate failure');
    const publisher = createRedisDouble();
    const { repository, service } = createHarness(publisher);
    publisher.close.mockRejectedValue(new Error('synthetic publisher close failure'));
    publisher.duplicate.mockImplementation(() => {
      throw startupFailure;
    });

    await expect(service.onApplicationBootstrap()).rejects.toBe(startupFailure);

    expect(publisher.close).toHaveBeenCalledOnce();
    expect(repository.close).toHaveBeenCalledOnce();
  });

  it('cancels loop timers and does not close resources twice after startup aborts', async () => {
    vi.useFakeTimers();
    const { publisher, relay, repository, service } = createHarness();
    await service.onApplicationBootstrap();
    await Promise.resolve();
    await Promise.resolve();
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    await service.onApplicationShutdown();
    await service.onApplicationShutdown();

    expect(vi.getTimerCount()).toBe(0);
    expect(publisher.close).toHaveBeenCalledOnce();
    expect(relay.close).toHaveBeenCalledOnce();
    expect(repository.close).toHaveBeenCalledOnce();
  });
});
