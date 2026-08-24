import { readFileSync } from 'node:fs';

import type { ChatSequence, TextMessage, UserId, Uuid } from '@kovcheg/contracts';
import type { OnModuleDestroy } from '@nestjs/common';
import type { PoolClient, QueryResultRow } from 'pg';
import { Pool } from 'pg';

export const realtimeRepositoryToken = Symbol('realtimeRepository');

export interface RealtimeSubscriptionCommand {
  readonly afterSequence: ChatSequence;
  readonly chatId: Uuid;
  readonly limit: number;
  readonly userId: UserId;
}

export interface RealtimeSubscriptionData {
  readonly history: readonly TextMessage[];
}

export interface RealtimeRepository {
  canReadChat(userId: UserId, chatId: Uuid): Promise<boolean>;
  isReady(): Promise<boolean>;
  subscribe(command: RealtimeSubscriptionCommand): Promise<RealtimeSubscriptionData>;
}

export class RealtimeRepositoryError extends Error {
  constructor(readonly failure: 'forbidden' | 'unavailable') {
    super(`Realtime repository failure: ${failure}`);
    this.name = 'RealtimeRepositoryError';
  }
}

interface MessageRow extends QueryResultRow {
  readonly body: string;
  readonly chat_id: string;
  readonly chat_sequence: string;
  readonly client_idempotency_key: string;
  readonly created_at: Date;
  readonly id: string;
  readonly sender_account_id: string;
}

interface AuthorizationRow extends QueryResultRow {
  readonly allowed: boolean;
}

interface PostgresEnvironment {
  readonly PGDATABASE?: string | undefined;
  readonly PGHOST?: string | undefined;
  readonly PGPASSWORD_FILE?: string | undefined;
  readonly PGPORT?: string | undefined;
  readonly PGUSER?: string | undefined;
}

function mapMessage(row: MessageRow): TextMessage {
  return Object.freeze({
    body: row.body,
    chatId: row.chat_id as Uuid,
    chatSequence: row.chat_sequence,
    clientMessageId: row.client_idempotency_key,
    createdAt: row.created_at.toISOString(),
    id: row.id as Uuid,
    senderAccountId: row.sender_account_id as Uuid,
  });
}

export class UnavailableRealtimeRepository implements RealtimeRepository {
  canReadChat(): Promise<boolean> {
    return Promise.reject(new RealtimeRepositoryError('unavailable'));
  }

  isReady(): Promise<boolean> {
    return Promise.resolve(false);
  }

  subscribe(): Promise<RealtimeSubscriptionData> {
    return Promise.reject(new RealtimeRepositoryError('unavailable'));
  }
}

export class PostgresRealtimeRepository implements RealtimeRepository, OnModuleDestroy {
  constructor(private readonly pool: Pool) {}

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  async isReady(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async canReadChat(userId: UserId, chatId: Uuid): Promise<boolean> {
    try {
      const authorization = await this.pool.query<AuthorizationRow>(
        'SELECT kovcheg.can_account_read_chat($1, $2) AS allowed',
        [userId, chatId],
      );
      return authorization.rows[0]?.allowed === true;
    } catch {
      throw new RealtimeRepositoryError('unavailable');
    }
  }

  async subscribe(command: RealtimeSubscriptionCommand): Promise<RealtimeSubscriptionData> {
    const client = await this.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const authorization = await client.query<AuthorizationRow>(
        'SELECT kovcheg.can_account_read_chat($1, $2) AS allowed',
        [command.userId, command.chatId],
      );
      if (authorization.rows[0]?.allowed !== true) {
        throw new RealtimeRepositoryError('forbidden');
      }

      const result = await client.query<MessageRow>(
        `SELECT
           message.id,
           message.chat_id,
           message.sender_account_id,
           message.chat_sequence,
           message.client_idempotency_key,
           message.body,
           message.created_at
         FROM kovcheg.messages AS message
         JOIN kovcheg.chat_memberships AS membership
           ON membership.chat_id = message.chat_id
          AND membership.account_id = $1
          AND membership.status = 'active'
         WHERE message.chat_id = $2
           AND message.chat_sequence > $3::bigint
           AND EXISTS (
             SELECT 1
             FROM kovcheg.chat_membership_periods AS period
             WHERE period.membership_id = membership.id
               AND message.chat_sequence > period.joined_after_sequence
               AND (
                 period.revoked_after_sequence IS NULL
                 OR message.chat_sequence <= period.revoked_after_sequence
               )
           )
         ORDER BY message.chat_sequence ASC, message.id ASC
         LIMIT $4`,
        [command.userId, command.chatId, command.afterSequence, command.limit],
      );
      await client.query('COMMIT');
      return Object.freeze({ history: Object.freeze(result.rows.map(mapMessage)) });
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (error instanceof RealtimeRepositoryError) {
        throw error;
      }
      throw new RealtimeRepositoryError('unavailable');
    } finally {
      client.release();
    }
  }

  private async connect(): Promise<PoolClient> {
    try {
      return await this.pool.connect();
    } catch {
      throw new RealtimeRepositoryError('unavailable');
    }
  }
}

export function createRealtimeRepository(
  environment: PostgresEnvironment = process.env,
): RealtimeRepository {
  const host = environment.PGHOST?.trim();
  const database = environment.PGDATABASE?.trim();
  const user = environment.PGUSER?.trim();
  const passwordFile = environment.PGPASSWORD_FILE?.trim();
  const portValue = environment.PGPORT?.trim() || '5432';
  if (!host || !database || !user || !passwordFile || !/^\d+$/u.test(portValue)) {
    return new UnavailableRealtimeRepository();
  }
  const port = Number.parseInt(portValue, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    return new UnavailableRealtimeRepository();
  }
  try {
    const password = readFileSync(passwordFile, 'utf8').replace(/[\r\n]+$/u, '');
    if (password.length === 0) {
      return new UnavailableRealtimeRepository();
    }
    return new PostgresRealtimeRepository(
      new Pool({
        application_name: 'kovcheg-api-realtime',
        database,
        host,
        max: 5,
        password,
        port,
        user,
      }),
    );
  } catch {
    return new UnavailableRealtimeRepository();
  }
}
