import type { CorrelationId, SessionId, UserId, Uuid } from '@kovcheg/contracts';
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
  operatorPrincipal: Object.freeze({
    sessionId: '00000000-0000-4000-8000-000000000101' as SessionId,
    userId: '00000000-0000-4000-8000-000000000001' as UserId,
  }),
});
const now = new Date('2026-01-01T00:00:00.000Z');

const messageRow = Object.freeze({
  body: command.body,
  chat_id: command.chatId,
  chat_sequence: '9',
  client_idempotency_key: command.clientMessageId,
  created_at: new Date('2026-01-01T00:00:00.000Z'),
  id: '00000000-0000-4000-8000-000000004101',
  sender_account_id: command.operatorPrincipal.userId,
  was_created: true,
});

describe('PostgresMessageFlowRepository', () => {
  it('calls the atomic entrypoint and maps bigint sequences as strings', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [messageRow] });
    const repository = new PostgresMessageFlowRepository({ query } as unknown as Pool, () => now);

    await expect(repository.createTextMessage(command)).resolves.toEqual({
      message: {
        body: command.body,
        chatId: command.chatId,
        chatSequence: '9',
        clientMessageId: command.clientMessageId,
        createdAt: '2026-01-01T00:00:00.000Z',
        id: messageRow.id,
        senderAccountId: command.operatorPrincipal.userId,
      },
      wasCreated: true,
    });
    expect(query).toHaveBeenCalledWith(expect.stringContaining('create_text_message'), [
      command.chatId,
      command.operatorPrincipal.sessionId,
      command.operatorPrincipal.userId,
      null,
      command.clientMessageId,
      command.contentFingerprint,
      command.body,
      command.correlationId,
      now,
    ]);
  });

  it('uses session-bound group creation and scoped administrator entrypoints', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            authorization_version: '1',
            chat_id: command.chatId,
            is_administrator: true,
            target_account_id: command.operatorPrincipal.userId,
          },
        ],
      })
      .mockResolvedValueOnce({
        rows: [
          {
            authorization_version: '2',
            chat_id: command.chatId,
            is_administrator: true,
            target_account_id: '00000000-0000-4000-8000-000000000002',
          },
        ],
      });
    const repository = new PostgresMessageFlowRepository({ query } as unknown as Pool, () => now);

    await expect(
      repository.createGroupChat({
        chatId: command.chatId,
        correlationId: command.correlationId,
        operatorPrincipal: command.operatorPrincipal,
        reason: 'group-created',
      }),
    ).resolves.toMatchObject({ authorizationVersion: 1, isAdministrator: true });
    await expect(
      repository.setChatAdministrator({
        chatId: command.chatId,
        correlationId: command.correlationId,
        granted: true,
        operatorPrincipal: command.operatorPrincipal,
        reason: 'creator-assigned',
        targetAccountId: '00000000-0000-4000-8000-000000000002' as UserId,
        version: 2,
      }),
    ).resolves.toMatchObject({ authorizationVersion: 2, isAdministrator: true });
    expect(query.mock.calls[0]?.[0]).toContain('create_group_chat_for_session');
    expect(query.mock.calls[1]?.[0]).toContain('set_chat_administrator_for_session');
  });

  it('passes a requested persona without exposing or replacing the operator principal', async () => {
    const personaAccountId = '00000000-0000-4000-8000-000000000201' as Uuid;
    const query = vi.fn().mockResolvedValue({
      rows: [{ ...messageRow, sender_account_id: personaAccountId }],
    });
    const repository = new PostgresMessageFlowRepository({ query } as unknown as Pool, () => now);

    await expect(
      repository.createTextMessage({ ...command, personaAccountId }),
    ).resolves.toMatchObject({ message: { senderAccountId: personaAccountId } });
    expect(query).toHaveBeenCalledWith(expect.stringContaining('create_text_message_for_session'), [
      command.chatId,
      command.operatorPrincipal.sessionId,
      command.operatorPrincipal.userId,
      personaAccountId,
      command.clientMessageId,
      command.contentFingerprint,
      command.body,
      command.correlationId,
      now,
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
        chatId: command.chatId,
        cursor: { direction: 'after', sequence: '8' },
        limit: 1,
        userId: command.operatorPrincipal.userId,
      }),
    ).resolves.toMatchObject({ hasMore: true, items: [{ chatSequence: '9' }] });
    expect(query.mock.calls[0]?.[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    expect(query.mock.calls[2]?.[0]).toContain('ORDER BY message.chat_sequence ASC');
    expect(query.mock.calls[2]?.[1]).toEqual([command.chatId, '8', 2]);
    expect(query.mock.calls[3]?.[0]).toBe('COMMIT');
    expect(release).toHaveBeenCalledOnce();
  });

  it('reads the latest bounded window in ascending response order', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ allowed: true }] })
      .mockResolvedValueOnce({
        rows: [
          { ...messageRow, chat_sequence: '11' },
          { ...messageRow, chat_sequence: '10' },
          { ...messageRow, chat_sequence: '9' },
        ],
      })
      .mockResolvedValueOnce({ rows: [] });
    const release = vi.fn();
    const repository = new PostgresMessageFlowRepository({
      connect: vi.fn().mockResolvedValue({ query, release } as unknown as PoolClient),
    } as unknown as Pool);

    await expect(
      repository.readMessageHistory({
        chatId: command.chatId,
        cursor: { direction: 'latest' },
        limit: 2,
        userId: command.operatorPrincipal.userId,
      }),
    ).resolves.toMatchObject({
      hasMore: true,
      items: [{ chatSequence: '10' }, { chatSequence: '11' }],
    });
    expect(query.mock.calls[2]?.[0]).toContain('ORDER BY message.chat_sequence DESC');
    expect(query.mock.calls[2]?.[0]).not.toContain('message.chat_sequence < $2');
    expect(query.mock.calls[2]?.[0]).not.toContain('message.chat_sequence > $2');
    expect(query.mock.calls[2]?.[1]).toEqual([command.chatId, 3]);
    expect(release).toHaveBeenCalledOnce();
  });

  it('reads an exclusive older page and restores ascending response order', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ allowed: true }] })
      .mockResolvedValueOnce({
        rows: [
          { ...messageRow, chat_sequence: '8' },
          { ...messageRow, chat_sequence: '7' },
        ],
      })
      .mockResolvedValueOnce({ rows: [] });
    const release = vi.fn();
    const repository = new PostgresMessageFlowRepository({
      connect: vi.fn().mockResolvedValue({ query, release } as unknown as PoolClient),
    } as unknown as Pool);

    await expect(
      repository.readMessageHistory({
        chatId: command.chatId,
        cursor: { direction: 'before', sequence: '9' },
        limit: 1,
        userId: command.operatorPrincipal.userId,
      }),
    ).resolves.toMatchObject({ hasMore: true, items: [{ chatSequence: '8' }] });
    expect(query.mock.calls[2]?.[0]).toContain('message.chat_sequence < $2::bigint');
    expect(query.mock.calls[2]?.[0]).toContain('ORDER BY message.chat_sequence DESC');
    expect(query.mock.calls[2]?.[1]).toEqual([command.chatId, '9', 2]);
    expect(release).toHaveBeenCalledOnce();
  });

  it('lists only PostgreSQL-selected active memberships in stable order', async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          can_read: true,
          can_write: true,
          id: command.chatId,
          kind: 'direct',
        },
        {
          can_read: true,
          can_write: false,
          id: '00000000-0000-4000-8000-000000004002',
          kind: 'group',
        },
      ],
    });
    const repository = new PostgresMessageFlowRepository({ query } as unknown as Pool);

    await expect(repository.listAvailableChats(command.operatorPrincipal.userId)).resolves.toEqual([
      {
        capabilities: { canRead: true, canWrite: true },
        id: command.chatId,
        kind: 'direct',
      },
      {
        capabilities: { canRead: true, canWrite: false },
        id: '00000000-0000-4000-8000-000000004002',
        kind: 'group',
      },
    ]);
    expect(query).toHaveBeenCalledWith(expect.stringContaining('list_account_chat_capabilities'), [
      command.operatorPrincipal.userId,
    ]);
  });

  it('returns full history for current read capability without a join-period cutoff', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ allowed: true }] })
      .mockResolvedValueOnce({ rows: [messageRow] })
      .mockResolvedValueOnce({ rows: [] });
    const release = vi.fn();
    const repository = new PostgresMessageFlowRepository({
      connect: vi.fn().mockResolvedValue({ query, release } as unknown as PoolClient),
    } as unknown as Pool);

    await repository.readMessageHistory({
      chatId: command.chatId,
      cursor: { direction: 'latest' },
      limit: 10,
      userId: command.operatorPrincipal.userId,
    });
    expect(query.mock.calls[2]?.[0]).not.toContain('chat_membership_periods');
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
