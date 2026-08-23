import { afterEach, describe, expect, it } from 'vitest';

import {
  realtimeContractVersion,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '@kovcheg/contracts';
import type { CorrelationId, SessionId, UserId, Uuid } from '@kovcheg/contracts';
import { syntheticUserIds } from '@kovcheg/contracts/testing';
import { io } from 'socket.io-client';
import type { Socket } from 'socket.io-client';

import { createApiApplication } from '../application.js';
import type { ApplicationSessionAuthenticator } from '../session/application-session.js';
import { ApplicationSessionError } from '../session/application-session.js';
import { RealtimeRepositoryError } from './realtime.repository.js';

const openApplications: Awaited<ReturnType<typeof createApiApplication>>[] = [];
const openSockets: Socket[] = [];

afterEach(async () => {
  for (const socket of openSockets.splice(0)) {
    socket.disconnect();
  }
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

function nextEvent<T>(socket: Socket, eventName: string): Promise<T> {
  return new Promise((resolve) => socket.once(eventName, resolve));
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function sessionCookie(userId: UserId): string {
  return `kovcheg_session=${userId}`;
}

function sessionAuthenticator(
  isAllowed: (userId: UserId) => boolean = () => true,
): ApplicationSessionAuthenticator {
  const authenticate: ApplicationSessionAuthenticator['authenticate'] = (cookieHeader) => {
    const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
    const userId = match?.[1] as UserId | undefined;
    if (userId === undefined || !isAllowed(userId)) {
      return Promise.reject(new ApplicationSessionError('unauthenticated'));
    }
    return Promise.resolve({ sessionId: userId as SessionId, userId });
  };
  return {
    authenticate,
    isReady: () => Promise.resolve(true),
    validate: authenticate,
  };
}

describe('realtime gateway', () => {
  it('authenticates through the injected test identity boundary and catches up from PostgreSQL', async () => {
    const app = await createApiApplication(undefined, {
      sessionAuthenticator: sessionAuthenticator(
        (userId) => userId === syntheticUserIds.activePrimary,
      ),
      instanceId: 'api-test-1',
      relayToken: 'realtime-test-token-0000000000000001',
      repository: {
        canReadChat: () => Promise.resolve(true),
        isReady: () => Promise.resolve(true),
        subscribe: () =>
          Promise.resolve({
            history: Object.freeze([
              Object.freeze({
                body: 'Synthetic history message',
                chatId: '00000000-0000-4000-8000-000000005101' as Uuid,
                chatSequence: '3',
                clientMessageId: 'realtime-history-001',
                createdAt: '2026-01-01T00:00:00.000Z',
                id: '00000000-0000-4000-8000-000000005102' as Uuid,
                senderUserId: syntheticUserIds.activePrimary,
              }),
            ]),
          }),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      transports: ['websocket'],
    });
    openSockets.push(socket);

    await expect(nextEvent(socket, realtimeSocketEvents.ready)).resolves.toEqual({
      contractVersion: realtimeContractVersion,
      instanceId: 'api-test-1',
    });
    const subscription = await new Promise((resolve) => {
      socket.emit(
        realtimeSocketEvents.subscribe,
        { afterSequence: '0', chatId: '00000000-0000-4000-8000-000000005101' },
        resolve,
      );
    });
    expect(subscription).toMatchObject({ joined: true, nextAfterSequence: '3' });

    const delivered = nextEvent(socket, realtimeSocketEvents.messageCreated);
    const response = await fetch(`${await app.getUrl()}/internal/realtime/events`, {
      body: JSON.stringify({
        contractVersion: realtimeContractVersion,
        correlationId: 'realtime-gateway-001' as CorrelationId,
        eventId: '00000000-0000-4000-8000-000000005103',
        eventName: 'message.created',
        occurredAt: '2026-01-01T00:00:01.000Z',
        payload: {
          chatId: '00000000-0000-4000-8000-000000005101',
          chatSequence: '4',
          messageId: '00000000-0000-4000-8000-000000005104',
        },
      }),
      headers: {
        authorization: 'Bearer realtime-test-token-0000000000000001',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(response.status).toBe(202);
    await expect(delivered).resolves.toMatchObject({
      eventId: '00000000-0000-4000-8000-000000005103',
      payload: { messageId: '00000000-0000-4000-8000-000000005104' },
    });
  });

  it('joins before catch-up so a concurrent relay event is not lost', async () => {
    const queryStarted = deferred<void>();
    const queryResult = deferred<{ readonly history: readonly [] }>();
    const app = await createApiApplication(undefined, {
      sessionAuthenticator: sessionAuthenticator(),
      relayToken: 'realtime-test-token-0000000000000001',
      repository: {
        canReadChat: () => Promise.resolve(true),
        isReady: () => Promise.resolve(true),
        subscribe: () => {
          queryStarted.resolve();
          return queryResult.promise;
        },
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await nextEvent(socket, realtimeSocketEvents.ready);

    const subscription = new Promise((resolve) => {
      socket.emit(
        realtimeSocketEvents.subscribe,
        { afterSequence: '0', chatId: '00000000-0000-4000-8000-000000005201' },
        resolve,
      );
    });
    await queryStarted.promise;
    const delivered = nextEvent(socket, realtimeSocketEvents.messageCreated);
    const response = await fetch(`${await app.getUrl()}/internal/realtime/events`, {
      body: JSON.stringify({
        contractVersion: realtimeContractVersion,
        correlationId: 'realtime-race-001',
        eventId: '00000000-0000-4000-8000-000000005202',
        eventName: 'message.created',
        occurredAt: '2026-01-01T00:00:01.000Z',
        payload: {
          chatId: '00000000-0000-4000-8000-000000005201',
          chatSequence: '1',
          messageId: '00000000-0000-4000-8000-000000005203',
        },
      }),
      headers: {
        authorization: 'Bearer realtime-test-token-0000000000000001',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(response.status).toBe(202);
    await expect(delivered).resolves.toMatchObject({
      eventId: '00000000-0000-4000-8000-000000005202',
    });
    queryResult.resolve({ history: Object.freeze([]) });
    await expect(subscription).resolves.toMatchObject({ joined: true });
  });

  it('leaves the room when the catch-up authorization check rejects the subscription', async () => {
    const app = await createApiApplication(undefined, {
      sessionAuthenticator: sessionAuthenticator(),
      relayToken: 'realtime-test-token-0000000000000001',
      repository: {
        canReadChat: () => Promise.resolve(true),
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.reject(new RealtimeRepositoryError('forbidden')),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await nextEvent(socket, realtimeSocketEvents.ready);
    const subscription = await new Promise((resolve) => {
      socket.emit(
        realtimeSocketEvents.subscribe,
        { afterSequence: '0', chatId: '00000000-0000-4000-8000-000000005301' },
        resolve,
      );
    });
    expect(subscription).toMatchObject({ joined: false });

    let delivered = false;
    socket.once(realtimeSocketEvents.messageCreated, () => {
      delivered = true;
    });
    const response = await fetch(`${await app.getUrl()}/internal/realtime/events`, {
      body: JSON.stringify({
        contractVersion: realtimeContractVersion,
        correlationId: 'realtime-denied-001',
        eventId: '00000000-0000-4000-8000-000000005302',
        eventName: 'message.created',
        occurredAt: '2026-01-01T00:00:01.000Z',
        payload: {
          chatId: '00000000-0000-4000-8000-000000005301',
          chatSequence: '1',
          messageId: '00000000-0000-4000-8000-000000005303',
        },
      }),
      headers: {
        authorization: 'Bearer realtime-test-token-0000000000000001',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(response.status).toBe(202);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(delivered).toBe(false);
  });

  it('rechecks logout or revoke state on an active socket and on reconnect', async () => {
    let sessionActive = true;
    const app = await createApiApplication(undefined, {
      sessionAuthenticator: sessionAuthenticator(() => sessionActive),
      repository: {
        canReadChat: () => Promise.resolve(true),
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.resolve({ history: Object.freeze([]) }),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      reconnection: false,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await nextEvent(socket, realtimeSocketEvents.ready);

    sessionActive = false;
    const rejected = nextEvent<{ readonly code: string }>(socket, realtimeSocketEvents.error);
    const disconnected = nextEvent<string>(socket, 'disconnect');
    socket.emit(realtimeSocketEvents.subscribe, {
      afterSequence: '0',
      chatId: '00000000-0000-4000-8000-000000005401',
    });
    await expect(rejected).resolves.toEqual({ code: 'realtime.unauthenticated' });
    await expect(disconnected).resolves.toBe('io server disconnect');

    const reconnectRejected = nextEvent<{ readonly code: string }>(
      socket,
      realtimeSocketEvents.error,
    );
    socket.connect();
    await expect(reconnectRejected).resolves.toEqual({ code: 'realtime.unauthenticated' });
  });

  it('rechecks PostgreSQL membership before delivering to an already joined socket', async () => {
    let membershipActive = true;
    const chatId = '00000000-0000-4000-8000-000000005501';
    const app = await createApiApplication(undefined, {
      relayToken: 'realtime-test-token-0000000000000001',
      sessionAuthenticator: sessionAuthenticator(),
      repository: {
        canReadChat: () => Promise.resolve(membershipActive),
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.resolve({ history: Object.freeze([]) }),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      reconnection: false,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await nextEvent(socket, realtimeSocketEvents.ready);
    const subscription = await new Promise((resolve) => {
      socket.emit(realtimeSocketEvents.subscribe, { afterSequence: '0', chatId }, resolve);
    });
    expect(subscription).toMatchObject({ joined: true });

    let delivered = false;
    socket.once(realtimeSocketEvents.messageCreated, () => {
      delivered = true;
    });
    membershipActive = false;
    const disconnected = nextEvent<string>(socket, 'disconnect');
    const response = await fetch(`${await app.getUrl()}/internal/realtime/events`, {
      body: JSON.stringify({
        contractVersion: realtimeContractVersion,
        correlationId: 'realtime-membership-revoked',
        eventId: '00000000-0000-4000-8000-000000005502',
        eventName: 'message.created',
        occurredAt: '2026-01-01T00:00:01.000Z',
        payload: {
          chatId,
          chatSequence: '1',
          messageId: '00000000-0000-4000-8000-000000005503',
        },
      }),
      headers: {
        authorization: 'Bearer realtime-test-token-0000000000000001',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(response.status).toBe(202);
    await expect(disconnected).resolves.toBe('io server disconnect');
    expect(delivered).toBe(false);
  });

  it('uses non-touch validation and rejects a principal change before delivery', async () => {
    const chatId = '00000000-0000-4000-8000-000000005601';
    let validatedUserId: UserId = syntheticUserIds.activePrimary;
    const app = await createApiApplication(undefined, {
      relayToken: 'realtime-test-token-0000000000000001',
      sessionAuthenticator: {
        authenticate: () =>
          Promise.resolve({
            sessionId: syntheticUserIds.activePrimary as SessionId,
            userId: syntheticUserIds.activePrimary,
          }),
        isReady: () => Promise.resolve(true),
        validate: () =>
          Promise.resolve({
            sessionId: validatedUserId as SessionId,
            userId: validatedUserId,
          }),
      },
      repository: {
        canReadChat: () => Promise.resolve(true),
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.resolve({ history: Object.freeze([]) }),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      extraHeaders: { cookie: sessionCookie(syntheticUserIds.activePrimary) },
      path: realtimeSocketPath,
      reconnection: false,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await nextEvent(socket, realtimeSocketEvents.ready);
    const subscription = await new Promise((resolve) => {
      socket.emit(realtimeSocketEvents.subscribe, { afterSequence: '0', chatId }, resolve);
    });
    expect(subscription).toMatchObject({ joined: true });

    validatedUserId = syntheticUserIds.activeSecondary;
    let delivered = false;
    socket.once(realtimeSocketEvents.messageCreated, () => {
      delivered = true;
    });
    const disconnected = nextEvent<string>(socket, 'disconnect');
    const response = await fetch(`${await app.getUrl()}/internal/realtime/events`, {
      body: JSON.stringify({
        contractVersion: realtimeContractVersion,
        correlationId: 'realtime-principal-change',
        eventId: '00000000-0000-4000-8000-000000005602',
        eventName: 'message.created',
        occurredAt: '2026-01-01T00:00:01.000Z',
        payload: {
          chatId,
          chatSequence: '1',
          messageId: '00000000-0000-4000-8000-000000005603',
        },
      }),
      headers: {
        authorization: 'Bearer realtime-test-token-0000000000000001',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
    expect(response.status).toBe(202);
    await expect(disconnected).resolves.toBe('io server disconnect');
    expect(delivered).toBe(false);
  });

  it('rejects missing or unknown sessions before room subscription', async () => {
    const app = await createApiApplication(undefined, {
      sessionAuthenticator: sessionAuthenticator(() => false),
      repository: {
        canReadChat: () => Promise.reject(new Error('must not be called')),
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.reject(new Error('must not be called')),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      auth: { 'x-kovcheg-identity-stub-user-id': syntheticUserIds.activeSecondary },
      path: realtimeSocketPath,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await expect(nextEvent(socket, realtimeSocketEvents.error)).resolves.toEqual({
      code: 'realtime.unauthenticated',
    });
  });
});
