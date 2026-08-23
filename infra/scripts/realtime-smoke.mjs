/* global fetch, process, setTimeout */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

import {
  createRealtimeEventDeduplicator,
  identityStubHeaderName,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '../../packages/contracts/dist/index.js';
import { syntheticUserIds } from '../../packages/contracts/dist/testing/index.js';
import { io } from 'socket.io-client';

const baseUrl = process.argv[2];
const transport = process.argv[3];
const composeProject = process.env.REALTIME_COMPOSE_PROJECT;
assert.ok(baseUrl, 'A loopback base URL is required');
assert.ok(transport === 'polling' || transport === 'websocket', 'A transport is required');
assert.match(composeProject ?? '', /^[A-Za-z0-9_-]+$/);

const chatId = '00000000-0000-4000-8000-000000001201';
const clients = [];
let clientMessageCounter = 0;

function compose(...args) {
  return execFileSync(
    'sh',
    [
      'infra/scripts/compose.sh',
      '-f',
      'compose.yaml',
      '-f',
      'infra/realtime/compose.test.yaml',
      '-p',
      composeProject,
      ...args,
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] },
  );
}

async function waitUntil(predicate, message, timeoutMilliseconds = 20_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(message);
}

function createClient(userId) {
  const deduplicator = createRealtimeEventDeduplicator();
  const state = {
    connectErrors: [],
    disconnectReasons: [],
    events: [],
    instanceId: null,
    lastSequence: '0',
    readyCount: 0,
    socket: null,
  };
  const socket = io(baseUrl, {
    auth: { [identityStubHeaderName]: userId },
    forceNew: true,
    path: realtimeSocketPath,
    reconnection: true,
    reconnectionDelay: 100,
    reconnectionDelayMax: 500,
    transports: [transport],
    withCredentials: true,
  });
  state.socket = socket;
  socket.on(realtimeSocketEvents.ready, (ready) => {
    state.instanceId = ready.instanceId;
    state.readyCount += 1;
  });
  socket.on(realtimeSocketEvents.messageCreated, (event) => {
    if (deduplicator.accept(event)) {
      state.events.push(event);
      state.lastSequence = event.payload.chatSequence;
    }
  });
  socket.on('connect_error', (error) => state.connectErrors.push(error.message));
  socket.on('disconnect', (reason) => state.disconnectReasons.push(reason));
  clients.push(state);
  return state;
}

async function waitForReady(client, previousCount = 0) {
  await waitUntil(
    () => client.socket.connected && client.readyCount > previousCount,
    `Socket.IO client did not become ready: ${JSON.stringify({
      active: client.socket.active,
      connectErrors: client.connectErrors,
      connected: client.socket.connected,
      disconnectReasons: client.disconnectReasons,
      readyCount: client.readyCount,
    })}`,
  );
  return client.instanceId;
}

async function subscribe(client) {
  const result = await new Promise((resolve, reject) => {
    client.socket
      .timeout(5_000)
      .emit(
        realtimeSocketEvents.subscribe,
        { afterSequence: client.lastSequence, chatId },
        (error, response) => (error ? reject(error) : resolve(response)),
      );
  });
  assert.equal(result.joined, true, 'Authorized synthetic member must join the chat room');
  for (const message of result.history) {
    const numericCurrent = BigInt(client.lastSequence);
    if (BigInt(message.chatSequence) > numericCurrent) {
      client.lastSequence = message.chatSequence;
    }
  }
  return result;
}

async function sendMessage(userId, label) {
  clientMessageCounter += 1;
  const request = {
    body: JSON.stringify({
      clientMessageId: `realtime-${transport}-${label}-${clientMessageCounter}`,
      text: `Synthetic realtime check ${clientMessageCounter}`,
    }),
    headers: {
      'content-type': 'application/json',
      [identityStubHeaderName]: userId,
      'x-correlation-id': `realtime-${transport}-${label}-${clientMessageCounter}`,
    },
    method: 'POST',
  };
  let response;
  await waitUntil(async () => {
    response = await fetch(`${baseUrl}/api/chats/${chatId}/messages`, request);
    return response.status !== 502 && response.status !== 503;
  }, `${label} message did not reach a ready API instance during bounded failover`);
  assert.ok(response !== undefined);
  assert.equal(response.status, 201, `${label} message must be stored in PostgreSQL`);
  return response.json();
}

async function waitForMessage(client, messageId) {
  await waitUntil(
    () => client.events.some((event) => event.payload.messageId === messageId),
    `Realtime message ${messageId} was not delivered`,
  );
  assert.equal(
    client.events.filter((event) => event.payload.messageId === messageId).length,
    1,
    'Client-side event/message deduplication must keep one delivery',
  );
}

function outboxState(messageId) {
  const sql =
    `SELECT CASE WHEN delivered_at IS NULL THEN 'pending' ELSE 'published' END || ':' || attempt_count::text ` +
    `FROM kovcheg.outbox_events WHERE aggregate_id = '${messageId}'::uuid`;
  return compose(
    'exec',
    '-T',
    'postgres',
    'sh',
    '-c',
    `PGPASSWORD=$(cat /run/secrets/postgres_superuser_password) psql --username postgres --dbname kovcheg --tuples-only --no-align --command "${sql}"`,
  ).trim();
}

try {
  const affinity = await fetch(`${baseUrl}/api/health/ready`);
  assert.equal(affinity.status, 200);
  assert.match(affinity.headers.get('set-cookie') ?? '', /kovcheg_affinity=/u);

  const primary = createClient(syntheticUserIds.activePrimary);
  await waitForReady(primary);

  let secondary;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const candidate = createClient(syntheticUserIds.activeSecondary);
    await waitForReady(candidate);
    if (candidate.instanceId !== primary.instanceId) {
      secondary = candidate;
      break;
    }
    candidate.socket.disconnect();
  }
  assert.ok(secondary, `${transport} clients must be distributed across both sticky API instances`);
  await Promise.all([subscribe(primary), subscribe(secondary)]);

  const crossInstance = await sendMessage(syntheticUserIds.activePrimary, 'cross-instance');
  await Promise.all([
    waitForMessage(primary, crossInstance.message.id),
    waitForMessage(secondary, crossInstance.message.id),
  ]);

  const secondaryReadyBeforeReconnect = secondary.readyCount;
  secondary.socket.disconnect();
  const missed = await sendMessage(syntheticUserIds.activePrimary, 'reconnect-gap');
  secondary.socket.connect();
  await waitForReady(secondary, secondaryReadyBeforeReconnect);
  const catchUp = await subscribe(secondary);
  assert.equal(
    catchUp.history.filter((message) => message.id === missed.message.id).length,
    1,
    'Reconnect must catch up exactly once from PostgreSQL history',
  );
  secondary.lastSequence = catchUp.nextAfterSequence;

  const activeClients = clients.filter((client) => client.socket.active);
  const redisReadyCounts = new Map(activeClients.map((client) => [client, client.readyCount]));
  compose('stop', 'redis');
  await waitUntil(
    () =>
      clients.filter((client) => client.socket.active).every((client) => !client.socket.connected),
    'Redis loss must disconnect realtime clients before unsafe partial fanout',
  );
  const duringRedisDown = await sendMessage(syntheticUserIds.activePrimary, 'redis-down');
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  assert.match(outboxState(duringRedisDown.message.id), /^pending:[1-9][0-9]*$/u);

  compose('up', '--detach', '--wait', 'redis');
  await Promise.all(
    activeClients.map((client) => waitForReady(client, redisReadyCounts.get(client) ?? 0)),
  );
  for (const client of activeClients) {
    const recovery = await subscribe(client);
    assert.equal(
      recovery.history.filter((message) => message.id === duringRedisDown.message.id).length,
      1,
      'Redis recovery must catch up the durable message from PostgreSQL',
    );
    client.lastSequence = recovery.nextAfterSequence;
  }
  await waitUntil(
    () => /^published:[1-9][0-9]*$/u.test(outboxState(duringRedisDown.message.id)),
    'Outbox publisher did not recover after Redis returned',
  );

  const afterRedisRecovery = await sendMessage(syntheticUserIds.activePrimary, 'redis-recovered');
  await Promise.all(
    activeClients.map((client) => waitForMessage(client, afterRedisRecovery.message.id)),
  );

  const apiReadyCounts = clients.map((client) => client.readyCount);
  compose('stop', 'api-1');
  await waitUntil(
    () => activeClients.every((client) => client.socket.connected && client.instanceId === 'api-2'),
    'Clients did not fail over to the surviving API instance',
  );
  for (const [index, client] of clients.entries()) {
    if (!client.socket.active) {
      continue;
    }
    if (client.readyCount > (apiReadyCounts[index] ?? 0)) {
      await subscribe(client);
    }
  }
  const oneApi = await sendMessage(syntheticUserIds.activePrimary, 'one-api');
  await Promise.all(activeClients.map((client) => waitForMessage(client, oneApi.message.id)));
  compose('up', '--detach', '--wait', 'api-1');
} finally {
  for (const client of clients) {
    client.socket.disconnect();
  }
}
