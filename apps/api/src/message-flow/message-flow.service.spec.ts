import type { CorrelationId, TextMessage, UserId, Uuid } from '@kovcheg/contracts';
import { syntheticUserIds } from '@kovcheg/contracts/testing';
import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';

import type {
  MessageFlowIdentityProvider,
  MessageFlowRepository,
} from './message-flow.repository.js';
import { MessageFlowRepositoryError } from './message-flow.repository.js';
import { MessageFlowService } from './message-flow.service.js';

const correlationId = 'message-flow-service-test' as CorrelationId;
const chatId = '00000000-0000-4000-8000-000000004001' as Uuid;
const message: TextMessage = Object.freeze({
  body: 'Synthetic message',
  chatId,
  chatSequence: '7',
  clientMessageId: 'client-message-001',
  createdAt: '2026-01-01T00:00:00.000Z',
  id: '00000000-0000-4000-8000-000000004101',
  senderUserId: syntheticUserIds.activePrimary,
});

function createIdentityProvider(
  statuses: Readonly<Record<string, 'active' | 'deactivated'>> = {
    [syntheticUserIds.activePrimary]: 'active',
    [syntheticUserIds.deactivated]: 'deactivated',
  },
): MessageFlowIdentityProvider {
  return {
    available: true,
    findById(userId: UserId) {
      const status = statuses[userId];
      return Promise.resolve(status === undefined ? null : { status });
    },
  };
}

function createRepository(overrides: Partial<MessageFlowRepository> = {}): MessageFlowRepository {
  return {
    createTextMessage: () => Promise.resolve({ message, wasCreated: true }),
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
    const createdService = new MessageFlowService(createIdentityProvider(), createRepository());
    await expect(
      createdService.createTextMessage(
        chatId,
        syntheticUserIds.activePrimary,
        { clientMessageId: 'client-message-001', text: 'Synthetic message' },
        correlationId,
      ),
    ).resolves.toEqual({ contractVersion: 1, message, outcome: 'created' });

    const replayedService = new MessageFlowService(
      createIdentityProvider(),
      createRepository({
        createTextMessage: () => Promise.resolve({ message, wasCreated: false }),
      }),
    );
    await expect(
      replayedService.createTextMessage(
        chatId,
        syntheticUserIds.activePrimary,
        { clientMessageId: 'client-message-001', text: 'Synthetic message' },
        correlationId,
      ),
    ).resolves.toEqual({ contractVersion: 1, message, outcome: 'replayed' });
  });

  it('rejects missing, unknown, and deactivated identities before repository access', async () => {
    const service = new MessageFlowService(createIdentityProvider(), createRepository());
    const request = { clientMessageId: 'client-message-001', text: 'Synthetic message' };

    await expectMachineError(
      service.createTextMessage(chatId, undefined, request, correlationId),
      401,
      'message-flow.unauthenticated',
    );
    await expectMachineError(
      service.createTextMessage(
        chatId,
        '00000000-0000-4000-8000-000000000099',
        request,
        correlationId,
      ),
      401,
      'message-flow.unauthenticated',
    );
    await expectMachineError(
      service.createTextMessage(chatId, syntheticUserIds.deactivated, request, correlationId),
      403,
      'message-flow.forbidden',
    );
  });

  it('rejects an identity stub in production mode', async () => {
    const service = new MessageFlowService(
      { available: false, findById: () => Promise.resolve(null) },
      createRepository(),
    );
    await expectMachineError(
      service.readMessageHistory(chatId, syntheticUserIds.activePrimary, '0', '50', correlationId),
      503,
      'message-flow.identity-unavailable',
    );
  });

  it('validates exact message and pagination inputs', async () => {
    const service = new MessageFlowService(createIdentityProvider(), createRepository());
    await expectMachineError(
      service.createTextMessage(
        chatId,
        syntheticUserIds.activePrimary,
        { clientMessageId: 'client-message-001', extra: true, text: 'Synthetic message' },
        correlationId,
      ),
      400,
      'message-flow.invalid-request',
    );
    await expectMachineError(
      service.readMessageHistory(
        chatId,
        syntheticUserIds.activePrimary,
        '-1',
        '101',
        correlationId,
      ),
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
        createIdentityProvider(),
        createRepository({
          createTextMessage: () => Promise.reject(new MessageFlowRepositoryError(failure)),
        }),
      );
      await expectMachineError(
        service.createTextMessage(
          chatId,
          syntheticUserIds.activePrimary,
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
      createIdentityProvider(),
      createRepository({
        readMessageHistory: () =>
          Promise.resolve({ hasMore: true, items: [message, secondMessage] }),
      }),
    );

    await expect(
      service.readMessageHistory(chatId, syntheticUserIds.activePrimary, '6', '2', correlationId),
    ).resolves.toEqual({
      contractVersion: 1,
      hasMore: true,
      items: [message, secondMessage],
      nextAfterSequence: '8',
    });
  });
});
