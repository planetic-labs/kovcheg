import type { CorrelationId, TextMessage, Uuid } from '@kovcheg/contracts';
import { syntheticUserIds } from '@kovcheg/contracts/testing';
import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import type { ApplicationSessionAuthenticator } from '../session/application-session.js';
import { ApplicationSessionError } from '../session/application-session.js';
import type { MessageFlowRepository } from './message-flow.repository.js';
import { MessageFlowRepositoryError } from './message-flow.repository.js';
import { MessageFlowService } from './message-flow.service.js';

const correlationId = 'message-flow-service-test' as CorrelationId;
const chatId = '00000000-0000-4000-8000-000000004001' as Uuid;
const activeCookie = 'kovcheg_session=active-session-token-0000000000000001';
const message: TextMessage = Object.freeze({
  body: 'Synthetic message',
  chatId,
  chatSequence: '7',
  clientMessageId: 'client-message-001',
  createdAt: '2026-01-01T00:00:00.000Z',
  id: '00000000-0000-4000-8000-000000004101',
  senderUserId: syntheticUserIds.activePrimary,
});

function createSessionAuthenticator(
  failureByCookie: Readonly<Record<string, 'unauthenticated' | 'unavailable'>> = {},
): ApplicationSessionAuthenticator {
  return {
    authenticate(cookieHeader) {
      const failure =
        cookieHeader === undefined ? 'unauthenticated' : failureByCookie[cookieHeader];
      if (failure !== undefined) {
        return Promise.reject(new ApplicationSessionError(failure));
      }
      return Promise.resolve({
        sessionId: '00000000-0000-4000-8000-000000006101',
        userId: syntheticUserIds.activePrimary,
      });
    },
  };
}

function createRepository(overrides: Partial<MessageFlowRepository> = {}): MessageFlowRepository {
  return {
    createTextMessage: () => Promise.resolve({ message, wasCreated: true }),
    listAvailableChats: () => Promise.resolve(Object.freeze([{ id: chatId, kind: 'direct' }])),
    readMessageHistory: () => Promise.resolve({ hasMore: false, items: [message] }),
    ...overrides,
  };
}

async function expectMachineError(
  operation: Promise<unknown>,
  status: number,
  code: string,
): Promise<void> {
  try {
    await operation;
    throw new Error('Expected the operation to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(HttpException);
    const httpError = error as HttpException;
    expect(httpError.getStatus()).toBe(status);
    expect(httpError.getResponse()).toMatchObject({ code, correlationId, httpStatus: status });
  }
}

describe('MessageFlowService', () => {
  it('creates a text message and returns a replay without changing the contract shape', async () => {
    const createdService = new MessageFlowService(createSessionAuthenticator(), createRepository());
    await expect(
      createdService.createTextMessage(
        chatId,
        activeCookie,
        { clientMessageId: 'client-message-001', text: 'Synthetic message' },
        correlationId,
      ),
    ).resolves.toEqual({ contractVersion: 1, message, outcome: 'created' });

    const replayedService = new MessageFlowService(
      createSessionAuthenticator(),
      createRepository({
        createTextMessage: () => Promise.resolve({ message, wasCreated: false }),
      }),
    );
    await expect(
      replayedService.createTextMessage(
        chatId,
        activeCookie,
        { clientMessageId: 'client-message-001', text: 'Synthetic message' },
        correlationId,
      ),
    ).resolves.toEqual({ contractVersion: 1, message, outcome: 'replayed' });
  });

  it('rejects missing, unknown, and deactivated sessions before repository access', async () => {
    const unknownCookie = 'kovcheg_session=unknown-session-token-000000000000000';
    const deactivatedCookie = 'kovcheg_session=deactivated-session-token-0000000000';
    const service = new MessageFlowService(
      createSessionAuthenticator({
        [deactivatedCookie]: 'unauthenticated',
        [unknownCookie]: 'unauthenticated',
      }),
      createRepository(),
    );
    const request = { clientMessageId: 'client-message-001', text: 'Synthetic message' };

    await expectMachineError(
      service.createTextMessage(chatId, undefined, request, correlationId),
      401,
      'message-flow.unauthenticated',
    );
    await expectMachineError(
      service.createTextMessage(chatId, unknownCookie, request, correlationId),
      401,
      'message-flow.unauthenticated',
    );
    await expectMachineError(
      service.createTextMessage(chatId, deactivatedCookie, request, correlationId),
      401,
      'message-flow.unauthenticated',
    );
  });

  it('fails closed when the A2 session service is unavailable', async () => {
    const service = new MessageFlowService(
      createSessionAuthenticator({ [activeCookie]: 'unavailable' }),
      createRepository(),
    );
    await expectMachineError(
      service.readMessageHistory(chatId, activeCookie, '0', '50', correlationId),
      503,
      'message-flow.identity-unavailable',
    );
  });

  it('returns a versioned active chat list and permits zero chats', async () => {
    const listed = new MessageFlowService(createSessionAuthenticator(), createRepository());
    await expect(listed.listAvailableChats(activeCookie, correlationId)).resolves.toEqual({
      contractVersion: 1,
      items: [{ id: chatId, kind: 'direct' }],
    });

    const empty = new MessageFlowService(
      createSessionAuthenticator(),
      createRepository({ listAvailableChats: () => Promise.resolve(Object.freeze([])) }),
    );
    await expect(empty.listAvailableChats(activeCookie, correlationId)).resolves.toEqual({
      contractVersion: 1,
      items: [],
    });
  });

  it('validates exact message and pagination inputs', async () => {
    const service = new MessageFlowService(createSessionAuthenticator(), createRepository());
    await expectMachineError(
      service.createTextMessage(
        chatId,
        activeCookie,
        { clientMessageId: 'client-message-001', extra: true, text: 'Synthetic message' },
        correlationId,
      ),
      400,
      'message-flow.invalid-request',
    );
    await expectMachineError(
      service.readMessageHistory(chatId, activeCookie, '-1', '101', correlationId),
      400,
      'message-flow.invalid-request',
    );
  });

  it('maps authorization, idempotency, and availability failures without database details', async () => {
    const cases = [
      ['forbidden', 403, 'message-flow.forbidden'],
      ['idempotency-key-reused', 409, 'message-flow.idempotency-key-reused'],
      ['unavailable', 503, 'message-flow.unavailable'],
    ] as const;

    for (const [failure, status, code] of cases) {
      const service = new MessageFlowService(
        createSessionAuthenticator(),
        createRepository({
          createTextMessage: () => Promise.reject(new MessageFlowRepositoryError(failure)),
        }),
      );
      await expectMachineError(
        service.createTextMessage(
          chatId,
          activeCookie,
          { clientMessageId: 'client-message-001', text: 'Synthetic message' },
          correlationId,
        ),
        status,
        code,
      );
    }
  });

  it('returns a deterministic next cursor only when another page exists', async () => {
    const secondMessage = {
      ...message,
      chatSequence: '8',
      id: '00000000-0000-4000-8000-000000004102' as Uuid,
    };
    const service = new MessageFlowService(
      createSessionAuthenticator(),
      createRepository({
        readMessageHistory: () =>
          Promise.resolve({ hasMore: true, items: [message, secondMessage] }),
      }),
    );

    await expect(
      service.readMessageHistory(chatId, activeCookie, '6', '2', correlationId),
    ).resolves.toEqual({
      contractVersion: 1,
      hasMore: true,
      items: [message, secondMessage],
      nextAfterSequence: '8',
    });
  });
});
