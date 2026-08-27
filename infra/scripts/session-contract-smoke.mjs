/* global clearTimeout, fetch, process, setTimeout */

import assert from 'node:assert/strict';

import { io } from 'socket.io-client';

const baseUrl = process.argv[2];
const sessionToken = process.env.KOVCHEG_SMOKE_SESSION_TOKEN;
const deactivatedSessionToken = process.env.KOVCHEG_SMOKE_DEACTIVATED_SESSION_TOKEN;
assert.ok(baseUrl, 'A loopback base URL is required');
assert.match(sessionToken ?? '', /^[A-Za-z0-9_-]{43}$/u, 'A synthetic session token is required');
assert.match(
  deactivatedSessionToken ?? '',
  /^[A-Za-z0-9_-]{43}$/u,
  'A synthetic deactivated session token is required',
);

const cookie = `__Host-kovcheg_session=${sessionToken}`;
const deactivatedCookie = `__Host-kovcheg_session=${deactivatedSessionToken}`;

async function request(path, init = {}) {
  return fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      'x-correlation-id': 'session-contract-smoke-001',
    },
  });
}

function onceWithTimeout(socket, event, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`Timed out waiting for ${event}`)),
      timeoutMs,
    );
    socket.once(event, (value) => {
      clearTimeout(timeout);
      resolve(value);
    });
  });
}

async function assertSocketRejected(cookieHeader, reason) {
  const headers = {
    'x-correlation-id': `session-contract-smoke-${reason}`,
    ...(cookieHeader === null ? {} : { cookie: cookieHeader }),
  };
  const candidate = io(baseUrl, {
    autoConnect: false,
    extraHeaders: headers,
    path: '/socket.io',
    reconnection: false,
    transports: ['websocket'],
  });
  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error(`Timed out waiting for rejected Socket.IO ${reason}`)),
        5_000,
      );
      const rejected = () => {
        clearTimeout(timeout);
        resolve();
      };
      candidate.once('connect_error', rejected);
      candidate.once('disconnect', rejected);
      candidate.once('realtime.error', rejected);
      candidate.once('realtime.ready', () => {
        clearTimeout(timeout);
        reject(new Error(`Rejected Socket.IO ${reason} received realtime.ready`));
      });
      candidate.connect();
    });
  } finally {
    candidate.disconnect();
  }
}

for (const protectedPath of ['/bff/chats', '/api/chats']) {
  assert.equal(
    (await request(protectedPath)).status,
    401,
    `Missing session must not access ${protectedPath}`,
  );
  assert.equal(
    (await request(protectedPath, { headers: { cookie: deactivatedCookie } })).status,
    401,
    `Deactivated session must not access ${protectedPath}`,
  );
}
await assertSocketRejected(null, 'missing-session');
await assertSocketRejected(deactivatedCookie, 'deactivated-session');

const hiddenInternalSession = await request('/auth/internal/session', {
  headers: { cookie },
});
assert.equal(
  hiddenInternalSession.status,
  404,
  'The non-touch session endpoint must stay internal',
);

const spoofedIdentity = await request('/api/chats', {
  headers: {
    authorization: 'Bearer synthetic-browser-token',
    'x-user-id': '00000000-0000-4000-8000-000000009801',
  },
});
assert.equal(spoofedIdentity.status, 401, 'Browser identity hints must not authenticate REST');

const chatListResponse = await request('/api/chats', { headers: { cookie } });
assert.equal(chatListResponse.status, 200, 'A valid A2 session must authenticate REST');
const chatList = await chatListResponse.json();
assert.equal(chatList.contractVersion, 2);
assert.ok(Array.isArray(chatList.items) && chatList.items.length > 0);
assert.equal(chatList.items[0]?.capabilities?.canRead, true);
assert.equal(chatList.items[0]?.capabilities?.canWrite, true);
const chatId = chatList.items[0]?.id;
assert.match(chatId ?? '', /^[0-9a-f-]{36}$/iu);

const socket = io(baseUrl, {
  autoConnect: false,
  extraHeaders: {
    cookie,
    'x-correlation-id': 'session-contract-smoke-socket-001',
  },
  path: '/socket.io',
  reconnection: false,
  transports: ['websocket'],
});

try {
  const ready = onceWithTimeout(socket, 'realtime.ready');
  socket.connect();
  assert.equal((await ready).contractVersion, 2, 'A valid A2 session must authenticate Socket.IO');

  const subscription = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timed out subscribing to the chat')), 5_000);
    socket.emit('realtime.subscribe', { afterSequence: '0', chatId }, (value) => {
      clearTimeout(timeout);
      resolve(value);
    });
  });
  assert.equal(
    subscription.joined,
    true,
    'The session principal must access its active membership',
  );

  const deliveredMessage = onceWithTimeout(socket, 'realtime.message-created', 20_000);
  const createMessageResponse = await request(`/api/chats/${chatId}/messages`, {
    body: JSON.stringify({
      clientMessageId: 'session-contract-smoke-message-001',
      text: 'Synthetic session contract smoke message',
    }),
    headers: { cookie, 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal(createMessageResponse.status, 201, 'The authenticated message must be created');
  const createdMessage = await createMessageResponse.json();
  assert.equal(createdMessage.contractVersion, 2);
  const realtimeMessage = await deliveredMessage;
  assert.equal(
    realtimeMessage.payload?.messageId,
    createdMessage.message?.id,
    'The live subscribed socket must receive the outbox-backed realtime event',
  );
  assert.equal(realtimeMessage.payload?.chatId, chatId);
  assert.equal(realtimeMessage.payload?.chatSequence, createdMessage.message?.chatSequence);
  assert.equal(realtimeMessage.payload?.senderAccountId, createdMessage.message?.senderAccountId);
  assert.equal('operatorAccountId' in realtimeMessage.payload, false);

  const logoutResponse = await request('/auth/session', {
    headers: { cookie },
    method: 'DELETE',
  });
  assert.equal(logoutResponse.status, 204, 'Logout must revoke the current application session');

  const rejectedRest = await request('/api/chats', { headers: { cookie } });
  assert.equal(rejectedRest.status, 401, 'A revoked session must fail the next REST operation');

  const rejectedSocket = onceWithTimeout(socket, 'realtime.error');
  const disconnected = onceWithTimeout(socket, 'disconnect');
  socket.emit('realtime.subscribe', { afterSequence: '0', chatId }, () => undefined);
  assert.deepEqual(await rejectedSocket, { code: 'realtime.unauthenticated' });
  assert.equal(await disconnected, 'io server disconnect');
} finally {
  socket.disconnect();
}

process.stdout.write(
  'A2 session fail-closed and positive REST, Web BFF, and Socket.IO contract smoke passed.\n',
);
