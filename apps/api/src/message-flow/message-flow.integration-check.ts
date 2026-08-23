import { readFileSync } from 'node:fs';

import type { SessionId, UserId } from '@kovcheg/contracts';
import { correlationIdHeaderName } from '@kovcheg/contracts';
import { syntheticUserIds } from '@kovcheg/contracts/testing';
import { Pool } from 'pg';

import { createApiApplication } from '../application.js';
import { ApplicationSessionError } from '../session/application-session.js';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

async function main(): Promise<void> {
  const passwordFile = process.env.PGPASSWORD_FILE;
  assert(passwordFile !== undefined, 'PGPASSWORD_FILE is required');
  const password = readFileSync(passwordFile, 'utf8').replace(/[\r\n]+$/u, '');
  const pool = new Pool({
    database: process.env.PGDATABASE,
    host: process.env.PGHOST,
    password,
    port: Number.parseInt(process.env.PGPORT ?? '5432', 10),
    user: process.env.PGUSER,
  });

  for (const userId of [syntheticUserIds.activePrimary, syntheticUserIds.activeSecondary]) {
    const account = await pool.query<{ readonly present: boolean }>(
      'SELECT EXISTS (SELECT 1 FROM kovcheg.accounts WHERE id = $1) AS present',
      [userId],
    );
    if (account.rows[0]?.present !== true) {
      await pool.query('SELECT * FROM kovcheg.provision_account_with_starter_set($1, $2)', [
        userId,
        `message-flow-provision-${userId.slice(-4)}`,
      ]);
    }
  }

  const chat = await pool.query<{ readonly id: string }>(
    `SELECT id
     FROM kovcheg.chats
     WHERE provisioned_for_account_id = $1
     ORDER BY id
     LIMIT 1`,
    [syntheticUserIds.activePrimary],
  );
  const chatId = chat.rows[0]?.id;
  assert(chatId !== undefined, 'A synthetic direct chat is required');

  const app = await createApiApplication(undefined, {
    sessionAuthenticator: {
      authenticate(cookieHeader) {
        const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
        const userId = match?.[1] as UserId | undefined;
        if (
          userId !== syntheticUserIds.activePrimary &&
          userId !== syntheticUserIds.activeSecondary
        ) {
          return Promise.reject(new ApplicationSessionError('unauthenticated'));
        }
        return Promise.resolve({ sessionId: userId as SessionId, userId });
      },
      isReady: () => Promise.resolve(true),
      validate(cookieHeader) {
        const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
        const userId = match?.[1] as UserId | undefined;
        if (
          userId !== syntheticUserIds.activePrimary &&
          userId !== syntheticUserIds.activeSecondary
        ) {
          return Promise.reject(new ApplicationSessionError('unauthenticated'));
        }
        return Promise.resolve({ sessionId: userId as SessionId, userId });
      },
    },
  });
  await app.listen(0, '127.0.0.1');
  const baseUrl = await app.getUrl();
  const endpoint = `${baseUrl}/chats/${chatId}/messages`;
  const headers = {
    cookie: `kovcheg_session=${syntheticUserIds.activePrimary}`,
    'content-type': 'application/json',
  };

  try {
    const body = JSON.stringify({
      clientMessageId: 'integration-message-001',
      text: 'Synthetic integration message',
    });
    const created = await fetch(endpoint, {
      body,
      headers: { ...headers, [correlationIdHeaderName]: 'integration-message-created' },
      method: 'POST',
    });
    assert(created.status === 201, 'The first send must return 201');
    const createdPayload = await readJson(created);
    assert(createdPayload.outcome === 'created', 'The first send must report created');

    const replayed = await fetch(endpoint, {
      body,
      headers: { ...headers, [correlationIdHeaderName]: 'integration-message-replayed' },
      method: 'POST',
    });
    assert(replayed.status === 200, 'The idempotent replay must return 200');
    const replayedPayload = await readJson(replayed);
    assert(replayedPayload.outcome === 'replayed', 'The replay must report replayed');
    assert(
      (createdPayload.message as Record<string, unknown>).id ===
        (replayedPayload.message as Record<string, unknown>).id,
      'The replay must return the original message',
    );

    const conflict = await fetch(endpoint, {
      body: JSON.stringify({
        clientMessageId: 'integration-message-001',
        text: 'Synthetic conflicting message',
      }),
      headers: { ...headers, [correlationIdHeaderName]: 'integration-message-conflict' },
      method: 'POST',
    });
    assert(conflict.status === 409, 'Reusing a client message ID with new content must return 409');
    const conflictPayload = await readJson(conflict);
    assert(
      conflictPayload.code === 'message-flow.idempotency-key-reused' &&
        conflictPayload.correlationId === 'integration-message-conflict',
      'The conflict must be machine-readable and correlation-bound',
    );

    const forbidden = await fetch(endpoint, {
      headers: {
        cookie: `kovcheg_session=${syntheticUserIds.activeSecondary}`,
        [correlationIdHeaderName]: 'integration-history-forbidden',
      },
    });
    assert(forbidden.status === 403, 'A non-member must not read another direct chat');

    const history = await fetch(`${endpoint}?afterSequence=0&limit=1`, {
      headers: {
        cookie: `kovcheg_session=${syntheticUserIds.activePrimary}`,
        [correlationIdHeaderName]: 'integration-history-page',
      },
    });
    assert(history.status === 200, 'An active member must read message history');
    const historyPayload = await readJson(history);
    assert(Array.isArray(historyPayload.items), 'History must return an item array');

    const chatList = await fetch(`${baseUrl}/chats`, {
      headers: {
        cookie: `kovcheg_session=${syntheticUserIds.activePrimary}`,
        [correlationIdHeaderName]: 'integration-chat-list',
      },
    });
    assert(chatList.status === 200, 'An active session must list its chats');
    const chatListPayload = await readJson(chatList);
    assert(chatListPayload.contractVersion === 1, 'The chat list must be versioned');
    assert(
      Array.isArray(chatListPayload.items) &&
        chatListPayload.items.some((item) => (item as Record<string, unknown>).id === chatId),
      'The chat list must contain the active membership',
    );

    const raceBody = JSON.stringify({
      clientMessageId: 'integration-message-race-001',
      text: 'Synthetic concurrent retry',
    });
    const raceResponses = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        fetch(endpoint, {
          body: raceBody,
          headers: {
            ...headers,
            [correlationIdHeaderName]: `integration-message-race-${index + 1}`,
          },
          method: 'POST',
        }),
      ),
    );
    const racePayloads = await Promise.all(raceResponses.map(readJson));
    assert(
      raceResponses.every((response) => response.status === 200 || response.status === 201),
      'Concurrent identical retries must all succeed',
    );
    assert(
      racePayloads.filter((payload) => payload.outcome === 'created').length === 1,
      'Concurrent identical retries must create exactly once',
    );
    assert(
      new Set(
        racePayloads.map((payload) => (payload.message as Record<string, unknown>).id as string),
      ).size === 1,
      'Concurrent identical retries must return one message ID',
    );
  } finally {
    await app.close();
    await pool.end();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown integration failure';
  process.stderr.write(`Message-flow integration check failed: ${message}\n`);
  process.exitCode = 1;
});
