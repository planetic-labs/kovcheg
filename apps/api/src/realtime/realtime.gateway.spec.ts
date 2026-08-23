import { afterEach, describe, expect, it } from 'vitest';

import {
  identityStubHeaderName,
  realtimeContractVersion,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '@kovcheg/contracts';
import type { CorrelationId, Uuid } from '@kovcheg/contracts';
import { syntheticUserIds } from '@kovcheg/contracts/testing';
import { io } from 'socket.io-client';
import type { Socket } from 'socket.io-client';

import { createApiApplication } from '../application.js';

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

describe('realtime gateway', () => {
  it('authenticates through the injected test identity boundary and catches up from PostgreSQL', async () => {
    const app = await createApiApplication(undefined, {
      identityProvider: {
        available: true,
        findById: (userId) =>
          Promise.resolve(
            userId === syntheticUserIds.activePrimary ? { status: 'active' as const } : null,
          ),
      },
      instanceId: 'api-test-1',
      relayToken: 'realtime-test-token-0000000000000001',
      repository: {
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
      auth: { [identityStubHeaderName]: syntheticUserIds.activePrimary },
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

  it('rejects unknown synthetic identities before room subscription', async () => {
    const app = await createApiApplication(undefined, {
      identityProvider: { available: true, findById: () => Promise.resolve(null) },
      repository: { subscribe: () => Promise.reject(new Error('must not be called')) },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const socket = io(await app.getUrl(), {
      auth: { [identityStubHeaderName]: syntheticUserIds.activeSecondary },
      path: realtimeSocketPath,
      transports: ['websocket'],
    });
    openSockets.push(socket);
    await expect(nextEvent(socket, realtimeSocketEvents.error)).resolves.toEqual({
      code: 'realtime.unauthenticated',
    });
  });
});
