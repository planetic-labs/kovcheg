import { readFileSync } from 'node:fs';

import type { AvailableChat, ChatKind, TextMessage, UserId, Uuid } from '@kovcheg/contracts';
import type { OnModuleDestroy } from '@nestjs/common';
import type { PoolClient, QueryResultRow } from 'pg';
import { Pool } from 'pg';

import type {
  CreateTextMessageCommand,
  CreateTextMessageResult,
  MessageFlowRepository,
  ReadMessageHistoryCommand,
  ReadMessageHistoryResult,
} from './message-flow.repository.js';
import {
  MessageFlowRepositoryError,
  UnavailableMessageFlowRepository,
} from './message-flow.repository.js';

interface PostgresEnvironment {
  readonly PGDATABASE?: string | undefined;
  readonly PGHOST?: string | undefined;
  readonly PGPASSWORD_FILE?: string | undefined;
  readonly PGPORT?: string | undefined;
  readonly PGUSER?: string | undefined;
}

interface MessageRow extends QueryResultRow {
  readonly body: string;
  readonly chat_id: string;
  readonly chat_sequence: string;
  readonly client_idempotency_key: string;
  readonly created_at: Date;
  readonly id: string;
  readonly sender_account_id: string;
  readonly was_created?: boolean;
}

interface AuthorizationRow extends QueryResultRow {
  readonly allowed: boolean;
}

interface ChatRow extends QueryResultRow {
  readonly can_read: boolean;
  readonly can_write: boolean;
  readonly id: string;
  readonly kind: string;
}

function mapChat(row: ChatRow): AvailableChat {
  if (row.kind !== 'direct' && row.kind !== 'group') {
    throw new MessageFlowRepositoryError('internal');
  }
  if (row.can_read !== true || typeof row.can_write !== 'boolean') {
    throw new MessageFlowRepositoryError('internal');
  }
  return Object.freeze({
    capabilities: Object.freeze({ canRead: row.can_read, canWrite: row.can_write }),
    id: row.id as Uuid,
    kind: row.kind as ChatKind,
  });
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

function mapPostgresError(error: unknown): MessageFlowRepositoryError {
  if (error instanceof MessageFlowRepositoryError) {
    return error;
  }

  const postgresError = error as { readonly code?: string; readonly constraint?: string };
  if (postgresError.code === '42501') {
    return new MessageFlowRepositoryError('forbidden');
  }
  if (
    postgresError.code === '23505' &&
    postgresError.constraint === 'messages_idempotency_unique'
  ) {
    return new MessageFlowRepositoryError('idempotency-key-reused');
  }
  if (
    postgresError.code === '22001' ||
    postgresError.code === '22P02' ||
    postgresError.code === '23514'
  ) {
    return new MessageFlowRepositoryError('invalid-request');
  }
  if (
    postgresError.code?.startsWith('08') === true ||
    postgresError.code === 'ECONNREFUSED' ||
    postgresError.code === 'ENOTFOUND' ||
    postgresError.code === 'ETIMEDOUT' ||
    postgresError.code === '57P01' ||
    postgresError.code === '57P02' ||
    postgresError.code === '57P03'
  ) {
    return new MessageFlowRepositoryError('unavailable');
  }
  return new MessageFlowRepositoryError('internal');
}

export class PostgresMessageFlowRepository implements MessageFlowRepository, OnModuleDestroy {
  constructor(
    private readonly pool: Pool,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async close(): Promise<void> {
    await this.pool.end();
  }

  onModuleDestroy(): Promise<void> {
    return this.close();
  }

  async createTextMessage(command: CreateTextMessageCommand): Promise<CreateTextMessageResult> {
    try {
      const result = await this.pool.query<MessageRow>(
        `SELECT
           message_id AS id,
           message_chat_id AS chat_id,
           sender_account_id,
           chat_sequence,
           client_idempotency_key,
           message_body AS body,
           created_at,
           was_created
         FROM kovcheg.create_text_message_for_session($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          command.chatId,
          command.operatorPrincipal.sessionId,
          command.operatorPrincipal.userId,
          command.personaAccountId ?? null,
          command.clientMessageId,
          command.contentFingerprint,
          command.body,
          command.correlationId,
          this.clock(),
        ],
      );
      const row = result.rows[0];
      if (row === undefined) {
        throw new MessageFlowRepositoryError('unavailable');
      }
      return Object.freeze({ message: mapMessage(row), wasCreated: row.was_created === true });
    } catch (error) {
      throw mapPostgresError(error);
    }
  }

  async listAvailableChats(userId: UserId): Promise<readonly AvailableChat[]> {
    try {
      const result = await this.pool.query<ChatRow>(
        `SELECT id, kind, can_read, can_write
         FROM kovcheg.list_account_chat_capabilities($1)`,
        [userId],
      );
      return Object.freeze(result.rows.map(mapChat));
    } catch (error) {
      throw mapPostgresError(error);
    }
  }

  async readMessageHistory(command: ReadMessageHistoryCommand): Promise<ReadMessageHistoryResult> {
    const client = await this.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const authorization = await client.query<AuthorizationRow>(
        'SELECT kovcheg.can_account_read_chat($1, $2) AS allowed',
        [command.userId, command.chatId],
      );
      if (authorization.rows[0]?.allowed !== true) {
        throw new MessageFlowRepositoryError('forbidden');
      }

      const descending = command.cursor.direction !== 'after';
      const cursorPredicate =
        command.cursor.direction === 'latest'
          ? ''
          : command.cursor.direction === 'after'
            ? 'AND message.chat_sequence > $2::bigint'
            : 'AND message.chat_sequence < $2::bigint';
      const limitParameter = command.cursor.direction === 'latest' ? '$2' : '$3';
      const parameters =
        command.cursor.direction === 'latest'
          ? [command.chatId, command.limit + 1]
          : [command.chatId, command.cursor.sequence, command.limit + 1];
      const order = descending ? 'DESC' : 'ASC';
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
         WHERE message.chat_id = $1
           ${cursorPredicate}
         ORDER BY message.chat_sequence ${order}, message.id ${order}
         LIMIT ${limitParameter}`,
        parameters,
      );
      await client.query('COMMIT');

      const hasMore = result.rows.length > command.limit;
      const pageRows = hasMore ? result.rows.slice(0, command.limit) : result.rows;
      const rows = descending ? [...pageRows].reverse() : pageRows;
      return Object.freeze({
        hasMore,
        items: Object.freeze(rows.map(mapMessage)),
      });
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw mapPostgresError(error);
    } finally {
      client.release();
    }
  }

  private async connect(): Promise<PoolClient> {
    try {
      return await this.pool.connect();
    } catch (error) {
      throw mapPostgresError(error);
    }
  }
}

export function createMessageFlowRepository(
  environment: PostgresEnvironment = process.env,
): MessageFlowRepository {
  const host = environment.PGHOST?.trim();
  const database = environment.PGDATABASE?.trim();
  const user = environment.PGUSER?.trim();
  const passwordFile = environment.PGPASSWORD_FILE?.trim();
  if (!host || !database || !user || !passwordFile) {
    return new UnavailableMessageFlowRepository();
  }

  const portValue = environment.PGPORT?.trim() || '5432';
  if (!/^\d+$/.test(portValue)) {
    return new UnavailableMessageFlowRepository();
  }
  const port = Number.parseInt(portValue, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    return new UnavailableMessageFlowRepository();
  }

  try {
    const password = readFileSync(passwordFile, 'utf8').replace(/[\r\n]+$/u, '');
    if (password.length === 0) {
      return new UnavailableMessageFlowRepository();
    }
    return new PostgresMessageFlowRepository(
      new Pool({
        application_name: 'kovcheg-api',
        database,
        host,
        max: 10,
        password,
        port,
        user,
      }),
    );
  } catch {
    return new UnavailableMessageFlowRepository();
  }
}
