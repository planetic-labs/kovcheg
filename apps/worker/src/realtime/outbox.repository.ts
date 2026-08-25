import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

import type { CorrelationId, Uuid } from '@kovcheg/contracts';
import type { QueryResultRow } from 'pg';
import { Pool } from 'pg';

export interface ClaimedOutboxEvent {
  readonly claimToken: Uuid;
  readonly correlationId: CorrelationId;
  readonly eventId: Uuid;
  readonly eventName: string;
  readonly occurredAt: string;
  readonly payload: Readonly<{
    chatId: string;
    chatSequence: string;
    messageId: string;
    senderAccountId: string;
  }>;
}

export interface OutboxRepository {
  claimNext(leaseMilliseconds: number): Promise<ClaimedOutboxEvent | null>;
  markPublished(eventId: Uuid, claimToken: Uuid): Promise<boolean>;
  release(eventId: Uuid, claimToken: Uuid): Promise<void>;
}

interface OutboxRow extends QueryResultRow {
  readonly chat_id: string;
  readonly chat_sequence: string;
  readonly correlation_id: string;
  readonly event_name: string;
  readonly id: string;
  readonly occurred_at: Date;
  readonly message_id: string;
  readonly sender_account_id: string;
}

interface PostgresEnvironment {
  readonly PGDATABASE?: string | undefined;
  readonly PGHOST?: string | undefined;
  readonly PGPASSWORD_FILE?: string | undefined;
  readonly PGPORT?: string | undefined;
  readonly PGUSER?: string | undefined;
}

export class PostgresOutboxRepository implements OutboxRepository {
  constructor(private readonly pool: Pool) {}

  async close(): Promise<void> {
    await this.pool.end();
  }

  async claimNext(leaseMilliseconds: number): Promise<ClaimedOutboxEvent | null> {
    if (!Number.isSafeInteger(leaseMilliseconds) || leaseMilliseconds < 1_000) {
      throw new Error('Outbox claim lease is invalid');
    }
    const claimToken = randomUUID() as Uuid;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query<OutboxRow>(
        `WITH candidate AS (
           SELECT id
           FROM kovcheg.outbox_events
           WHERE delivered_at IS NULL
             AND event_name = 'message.created'
             AND available_at <= clock_timestamp()
             AND (claim_token IS NULL OR claim_expires_at <= clock_timestamp())
           ORDER BY available_at, occurred_at, id
           LIMIT 1
           FOR UPDATE SKIP LOCKED
         )
         UPDATE kovcheg.outbox_events AS event
         SET claim_token = $1,
             claim_expires_at = clock_timestamp() + ($2::bigint * interval '1 millisecond'),
             attempt_count = attempt_count + 1
         FROM candidate
         WHERE event.id = candidate.id
         RETURNING
           event.id,
           event.event_name,
           event.correlation_id,
           event.payload ->> 'chatId' AS chat_id,
           event.payload ->> 'chatSequence' AS chat_sequence,
           event.payload ->> 'messageId' AS message_id,
           event.payload ->> 'senderAccountId' AS sender_account_id,
           event.occurred_at`,
        [claimToken, leaseMilliseconds],
      );
      await client.query('COMMIT');
      const row = result.rows[0];
      if (row === undefined) {
        return null;
      }
      return Object.freeze({
        claimToken,
        correlationId: row.correlation_id as CorrelationId,
        eventId: row.id as Uuid,
        eventName: row.event_name,
        occurredAt: row.occurred_at.toISOString(),
        payload: Object.freeze({
          chatId: row.chat_id,
          chatSequence: row.chat_sequence,
          messageId: row.message_id,
          senderAccountId: row.sender_account_id,
        }),
      });
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async markPublished(eventId: Uuid, claimToken: Uuid): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE kovcheg.outbox_events
       SET delivered_at = clock_timestamp(), claim_token = NULL, claim_expires_at = NULL
       WHERE id = $1 AND claim_token = $2 AND delivered_at IS NULL`,
      [eventId, claimToken],
    );
    return result.rowCount === 1;
  }

  async release(eventId: Uuid, claimToken: Uuid): Promise<void> {
    await this.pool.query(
      `UPDATE kovcheg.outbox_events
       SET claim_token = NULL, claim_expires_at = NULL
       WHERE id = $1 AND claim_token = $2 AND delivered_at IS NULL`,
      [eventId, claimToken],
    );
  }
}

export function createPostgresOutboxRepository(
  environment: PostgresEnvironment = process.env,
): PostgresOutboxRepository {
  const host = environment.PGHOST?.trim();
  const database = environment.PGDATABASE?.trim();
  const user = environment.PGUSER?.trim();
  const passwordFile = environment.PGPASSWORD_FILE?.trim();
  const portValue = environment.PGPORT?.trim() || '5432';
  if (!host || !database || !user || !passwordFile || !/^\d+$/u.test(portValue)) {
    throw new Error('PostgreSQL outbox configuration is incomplete');
  }
  const port = Number.parseInt(portValue, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('PostgreSQL outbox port is invalid');
  }
  const password = readFileSync(passwordFile, 'utf8').replace(/[\r\n]+$/u, '');
  if (password.length === 0) {
    throw new Error('PostgreSQL outbox credential is empty');
  }
  return new PostgresOutboxRepository(
    new Pool({
      application_name: 'kovcheg-outbox-publisher',
      database,
      host,
      max: 3,
      password,
      port,
      user,
    }),
  );
}
