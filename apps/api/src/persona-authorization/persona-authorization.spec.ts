import type { SessionId, UserId } from '@kovcheg/contracts';
import {
  createTextMessageResponseJsonSchema,
  messageHistoryPageJsonSchema,
  parseMessageCreatedRealtimeEvent,
  realtimeContractVersion,
} from '@kovcheg/contracts';
import type { QueryResult } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import type { PersonaAuthorizationTransaction } from './persona-authorization.js';
import { PostgresPersonaAuthorizer } from './persona-authorization.js';

const operatorAccountId = '00000000-0000-4000-8000-000000009001' as UserId;
const sessionId = '00000000-0000-4000-8000-000000009201' as SessionId;
const personaAccountId = '00000000-0000-4000-8000-000000009101';
const command = Object.freeze({
  now: new Date('2030-01-01T01:00:00.000Z'),
  operatorPrincipal: Object.freeze({ sessionId, userId: operatorAccountId }),
  personaAccountId,
});

function transaction(query: ReturnType<typeof vi.fn>): PersonaAuthorizationTransaction {
  return { query } as unknown as PersonaAuthorizationTransaction;
}

function authorizedRow(): QueryResult<{
  operator_account_id: string;
  persona_account_id: string;
}> {
  return {
    command: 'SELECT',
    fields: [],
    oid: 0,
    rowCount: 1,
    rows: [
      {
        operator_account_id: operatorAccountId,
        persona_account_id: personaAccountId,
      },
    ],
  };
}

describe('PostgresPersonaAuthorizer', () => {
  it('returns separate operator and persona identities from the supplied transaction', async () => {
    const query = vi.fn().mockResolvedValue(authorizedRow());
    const authorizer = new PostgresPersonaAuthorizer();

    await expect(authorizer.authorizeInTransaction(transaction(query), command)).resolves.toEqual({
      operatorAccountId,
      personaAccountId,
    });
    expect(query).toHaveBeenCalledWith(expect.stringContaining('authorize_system_persona_action'), [
      sessionId,
      operatorAccountId,
      personaAccountId,
      command.now,
    ]);
  });

  it('does not cache authorization between calls', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce(authorizedRow())
      .mockRejectedValueOnce({ code: '42501' });
    const authorizer = new PostgresPersonaAuthorizer();

    await expect(
      authorizer.authorizeInTransaction(transaction(query), command),
    ).resolves.toMatchObject({ operatorAccountId, personaAccountId });
    await expect(
      authorizer.authorizeInTransaction(transaction(query), command),
    ).rejects.toMatchObject({ failure: 'forbidden' });
    expect(query).toHaveBeenCalledTimes(2);
  });

  it('rejects an untrusted invalid persona UUID before PostgreSQL is called', async () => {
    const query = vi.fn();
    const authorizer = new PostgresPersonaAuthorizer();

    await expect(
      authorizer.authorizeInTransaction(transaction(query), {
        ...command,
        personaAccountId: 'not-a-uuid',
      }),
    ).rejects.toMatchObject({ failure: 'forbidden' });
    expect(query).not.toHaveBeenCalled();
  });

  it('fails closed on database errors and inconsistent database results', async () => {
    const authorizer = new PostgresPersonaAuthorizer();
    for (const query of [
      vi.fn().mockRejectedValue({ code: 'ECONNREFUSED' }),
      vi.fn().mockResolvedValue({ ...authorizedRow(), rows: [] }),
      vi.fn().mockResolvedValue({
        ...authorizedRow(),
        rows: [{ ...authorizedRow().rows[0], persona_account_id: operatorAccountId }],
      }),
    ]) {
      await expect(
        authorizer.authorizeInTransaction(transaction(query), command),
      ).rejects.toMatchObject({ name: 'PersonaAuthorizationError' });
    }
  });

  it('keeps the operator identity out of public message and realtime contracts', () => {
    expect(JSON.stringify(createTextMessageResponseJsonSchema)).not.toContain('operatorAccountId');
    expect(JSON.stringify(messageHistoryPageJsonSchema)).not.toContain('operatorAccountId');
    expect(
      parseMessageCreatedRealtimeEvent({
        contractVersion: realtimeContractVersion,
        correlationId: 'persona-authorization-contract-check',
        eventId: '00000000-0000-4000-8000-000000009301',
        eventName: 'message.created',
        occurredAt: '2030-01-01T01:00:00.000Z',
        payload: {
          chatId: '00000000-0000-4000-8000-000000009401',
          chatSequence: '1',
          messageId: '00000000-0000-4000-8000-000000009501',
          operatorAccountId,
        },
      }),
    ).toBeNull();
  });
});
