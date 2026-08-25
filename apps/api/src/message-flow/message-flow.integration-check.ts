import { readFileSync } from 'node:fs';

import type { SessionId, UserId } from '@kovcheg/contracts';
import { correlationIdHeaderName } from '@kovcheg/contracts';
import { Pool } from 'pg';

import { createApiApplication } from '../application.js';
import { ApplicationSessionError } from '../session/application-session.js';

const primaryUserId = '00000000-0000-4000-8000-000000009001' as UserId;
const primarySessionId = '00000000-0000-4000-8000-000000009291' as SessionId;
const secondaryUserId = '00000000-0000-4000-8000-000000009002' as UserId;
const secondarySessionId = '00000000-0000-4000-8000-000000009202' as SessionId;
const messageChatId = '00000000-0000-4000-8000-000000009402';

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

  const chat = await pool.query<{ readonly present: boolean }>(
    'SELECT EXISTS (SELECT 1 FROM kovcheg.chats WHERE id = $1) AS present',
    [messageChatId],
  );
  assert(chat.rows[0]?.present === true, 'The synthetic message-audit chat is required');
  const chatId = messageChatId;

  const authenticate = (cookieHeader: string | undefined) => {
    const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
    const userId = match?.[1] as UserId | undefined;
    if (userId === primaryUserId) {
      return Promise.resolve({ sessionId: primarySessionId, userId });
    }
    if (userId === secondaryUserId) {
      return Promise.resolve({ sessionId: secondarySessionId, userId });
    }
    return Promise.reject(new ApplicationSessionError('unauthenticated'));
  };

  const app = await createApiApplication(undefined, {
    sessionAuthenticator: {
      authenticate,
      isReady: () => Promise.resolve(true),
      validate: authenticate,
    },
  });
  await app.listen(0, '127.0.0.1');
  const baseUrl = await app.getUrl();
  const endpoint = `${baseUrl}/chats/${chatId}/messages`;
  const headers = {
    cookie: `kovcheg_session=${primaryUserId}`,
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
    assert(createdPayload.contractVersion === 2, 'Message creation must use contract version 2');
    assert(
      (createdPayload.message as Record<string, unknown>).senderAccountId === primaryUserId,
      'An ordinary message must expose the personal account as its public sender',
    );

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

    const historyClientMessageIds = Array.from(
      { length: 5 },
      (_, index) => `integration-history-${String(index + 1).padStart(3, '0')}`,
    );
    for (const [index, clientMessageId] of historyClientMessageIds.entries()) {
      const response = await fetch(endpoint, {
        body: JSON.stringify({
          clientMessageId,
          text: `Synthetic history message ${index + 1}`,
        }),
        headers: {
          ...headers,
          [correlationIdHeaderName]: `integration-history-create-${index + 1}`,
        },
        method: 'POST',
      });
      assert(response.status === 201, 'Each synthetic history message must be created once');
    }

    const forbidden = await fetch(endpoint, {
      headers: {
        cookie: `kovcheg_session=${secondaryUserId}`,
        [correlationIdHeaderName]: 'integration-history-forbidden',
      },
    });
    assert(forbidden.status === 403, 'A non-member must not read another direct chat');

    const latestHistory = await fetch(`${endpoint}?limit=2`, {
      headers: {
        cookie: `kovcheg_session=${primaryUserId}`,
        [correlationIdHeaderName]: 'integration-history-latest',
      },
    });
    assert(latestHistory.status === 200, 'An active member must read the latest history window');
    const latestPayload = await readJson(latestHistory);
    assert(latestPayload.contractVersion === 3, 'History pagination must use contract version 3');
    assert(Array.isArray(latestPayload.items), 'Latest history must return an item array');
    const latestItems = latestPayload.items as Record<string, unknown>[];
    assert(
      latestItems.map((item) => item.clientMessageId).join(',') ===
        historyClientMessageIds.slice(-2).join(','),
      'The default history page must contain the newest bounded window in ascending order',
    );
    const latestBeforeSequence = latestPayload.nextBeforeSequence;
    assert(
      latestPayload.hasMore === true &&
        typeof latestBeforeSequence === 'string' &&
        latestPayload.nextAfterSequence === null,
      'The latest page must expose only the older-page cursor when older messages exist',
    );

    const middleHistory = await fetch(
      `${endpoint}?beforeSequence=${latestBeforeSequence}&limit=2`,
      {
        headers: {
          cookie: `kovcheg_session=${primaryUserId}`,
          [correlationIdHeaderName]: 'integration-history-middle',
        },
      },
    );
    assert(middleHistory.status === 200, 'The next older history page must be readable');
    const middlePayload = await readJson(middleHistory);
    assert(Array.isArray(middlePayload.items), 'The middle history page must return an item array');
    const middleItems = middlePayload.items as Record<string, unknown>[];
    assert(
      middleItems.map((item) => item.clientMessageId).join(',') ===
        historyClientMessageIds.slice(1, 3).join(','),
      'The older cursor must be exclusive and preserve ascending response order',
    );
    const middleBeforeSequence = middlePayload.nextBeforeSequence;
    assert(
      middlePayload.hasMore === true && typeof middleBeforeSequence === 'string',
      'The middle page must expose another older-page cursor',
    );

    const oldestHistory = await fetch(
      `${endpoint}?beforeSequence=${middleBeforeSequence}&limit=2`,
      {
        headers: {
          cookie: `kovcheg_session=${primaryUserId}`,
          [correlationIdHeaderName]: 'integration-history-oldest',
        },
      },
    );
    assert(oldestHistory.status === 200, 'The oldest bounded history page must be readable');
    const oldestPayload = await readJson(oldestHistory);
    assert(Array.isArray(oldestPayload.items), 'The oldest history page must return an item array');
    const oldestItems = oldestPayload.items as Record<string, unknown>[];
    assert(
      oldestItems.map((item) => item.clientMessageId).join(',') ===
        ['integration-message-001', historyClientMessageIds[0]].join(','),
      'Backward pagination must reach the first visible message without a gap',
    );
    assert(
      oldestPayload.hasMore === false && oldestPayload.nextBeforeSequence === null,
      'The oldest page must terminate backward pagination',
    );

    const completeHistory = [...oldestItems, ...middleItems, ...latestItems];
    const completeMessageIds = completeHistory.map((item) => item.id);
    assert(
      completeHistory.map((item) => item.clientMessageId).join(',') ===
        ['integration-message-001', ...historyClientMessageIds].join(','),
      'Backward pages must reconstruct the visible history in exact order',
    );
    assert(
      new Set(completeMessageIds).size === completeMessageIds.length,
      'Backward pages must not duplicate a message at cursor boundaries',
    );
    for (let index = 1; index < completeHistory.length; index += 1) {
      const previousSequence = completeHistory[index - 1]?.chatSequence;
      const currentSequence = completeHistory[index]?.chatSequence;
      assert(
        typeof previousSequence === 'string' &&
          typeof currentSequence === 'string' &&
          BigInt(currentSequence) > BigInt(previousSequence),
        'Backward pages must preserve strictly increasing chat sequence order',
      );
    }

    const createdSequence = (createdPayload.message as Record<string, unknown>).chatSequence;
    assert(typeof createdSequence === 'string', 'The created message must expose chatSequence');
    const catchUpHistory = await fetch(`${endpoint}?afterSequence=${createdSequence}&limit=2`, {
      headers: {
        cookie: `kovcheg_session=${primaryUserId}`,
        [correlationIdHeaderName]: 'integration-history-catch-up',
      },
    });
    assert(catchUpHistory.status === 200, 'Explicit afterSequence catch-up must remain available');
    const catchUpPayload = await readJson(catchUpHistory);
    assert(Array.isArray(catchUpPayload.items), 'Catch-up history must return an item array');
    const catchUpItems = catchUpPayload.items as Record<string, unknown>[];
    assert(
      catchUpItems.map((item) => item.clientMessageId).join(',') ===
        historyClientMessageIds.slice(0, 2).join(',') &&
        catchUpPayload.hasMore === true &&
        catchUpPayload.nextAfterSequence === catchUpItems.at(-1)?.chatSequence &&
        catchUpPayload.nextBeforeSequence === null,
      'Forward catch-up must preserve its cursor and ascending page semantics',
    );

    const conflictingCursors = await fetch(
      `${endpoint}?afterSequence=${createdSequence}&beforeSequence=${latestBeforeSequence}`,
      {
        headers: {
          cookie: `kovcheg_session=${primaryUserId}`,
          [correlationIdHeaderName]: 'integration-history-conflicting-cursors',
        },
      },
    );
    assert(conflictingCursors.status === 400, 'Two history cursor directions must be rejected');

    const chatList = await fetch(`${baseUrl}/chats`, {
      headers: {
        cookie: `kovcheg_session=${primaryUserId}`,
        [correlationIdHeaderName]: 'integration-chat-list',
      },
    });
    assert(chatList.status === 200, 'An active session must list its chats');
    const chatListPayload = await readJson(chatList);
    assert(chatListPayload.contractVersion === 2, 'The chat list must be versioned');
    assert(Array.isArray(chatListPayload.items), 'The chat list must return an item array');
    const availableChat = (chatListPayload.items as Record<string, unknown>[]).find(
      (item) => item.id === chatId,
    );
    assert(availableChat !== undefined, 'The chat list must contain the active membership');
    assert(
      (availableChat.capabilities as Record<string, unknown>).canRead === true &&
        (availableChat.capabilities as Record<string, unknown>).canWrite === true,
      'The chat list must expose server-authoritative read and write capabilities',
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
