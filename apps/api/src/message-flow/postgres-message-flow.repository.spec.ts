import type { CorrelationId, UserId, Uuid } from '@kovcheg/contracts';
import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { MessageFlowRepositoryError } from './message-flow.repository.js';
import {
  createMessageFlowRepository,
  PostgresMessageFlowRepository,
} from './postgres-message-flow.repository.js';

const command = Object.freeze({
  body: 'Synthetic repository message',
  chatId: '00000000-0000-4000-8000-000000004001' as Uuid,
  clientMessageId: 'repository-message-001',
  contentFingerprint: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  correlationId: 'repository-message-created' as CorrelationId,
  senderUserId: '00000000-0000-4000-8000-000000000001' as UserId,
});

const messageRow = Object.freeze({
  body: command.body,
  chat_id: command.chatId,
  chat_sequence: '9',
  client_idempotency_key: command.clientMessageId,
  created_at: new Date('2026-01-01T00:00:00.000Z'),
  id: '00000000-0000-4000-8000-000000004101',
  sender_account_id: command.senderUserId,
  was_created: true,
});

describe('PostgresMessageFlowRepository', () => {
  it('calls the atomic entrypoint and maps bigint sequences as strings', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [messageRow] });
    const repository = new PostgresMessageFlowRepository({ query } as unknown as Pool);

    await expect(repository.createTextMessage(command)).resolves.toEqual({
      message: {
        body: command.body,
        chatId: command.chatId,
        chatSequence: '9',
        clientMessageId: command.clientMessageId,
        createdAt: '2026-01-01T00:00:00.000Z',
        id: messageRow.id,
        senderUserId: command.senderUserId,
      },
      wasCreated: true,
    });
    expect(query).toHaveBeenCalledWith(expect.stringContaining('create_text_message'), [
      command.chatId,
      command.senderUserId,
      command.clientMessageId,
      command.contentFingerprint,
      command.body,
      command.correlationId,
    ]);
  });

  it('maps the canonical fingerprint conflict without exposing a database error', async () => {
    const repository = new PostgresMessageFlowRepository({
      query: vi.fn().mockRejectedValue({
        code: '23505',
        constraint: 'messages_idempotency_unique',
      }),
    } as unknown as Pool);

    await expect(repository.createTextMessage(command)).rejects.toMatchObject({
      failure: 'idempotency-key-reused',
    });
  });

  it('checks read authorization and uses a repeatable deterministic page query', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ allowed: true }] })
      .mockResolvedValueOnce({ rows: [messageRow, { ...messageRow, chat_sequence: '10' }] })
      .mockResolvedValueOnce({ rows: [] });
    const release = vi.fn();
    const client = { query, release } as unknown as PoolClient;
    const repository = new PostgresMessageFlowRepository({
      connect: vi.fn().mockResolvedValue(client),
    } as unknown as Pool);

    await expect(
      repository.readMessageHistory({
        afterSequence: '8',
        chatId: command.chatId,
        limit: 1,
        userId: command.senderUserId,
      }),
    ).resolves.toMatchObject({ hasMore: true, items: [{ chatSequence: '9' }] });
    expect(query.mock.calls[0]?.[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    expect(query.mock.calls[2]?.[0]).toContain('ORDER BY message.chat_sequence ASC');
    expect(query.mock.calls[2]?.[1]).toEqual([command.senderUserId, command.chatId, '8', 2]);
    expect(query.mock.calls[3]?.[0]).toBe('COMMIT');
    expect(release).toHaveBeenCalledOnce();
  });

  it('fails closed when PostgreSQL configuration is incomplete', async () => {
    const repository = createMessageFlowRepository({});
    await expect(repository.createTextMessage(command)).rejects.toBeInstanceOf(
      MessageFlowRepositoryError,
    );
    await expect(repository.createTextMessage(command)).rejects.toMatchObject({
      failure: 'unavailable',
    });
  });
});
