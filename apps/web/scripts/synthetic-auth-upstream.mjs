/* global Buffer, URL, process */

import { createServer, request as httpRequest } from 'node:http';
import { Server as SocketIoServer } from 'socket.io';

function port(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? fallback, 10);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) {
    throw new Error(`${name} must be a valid TCP port`);
  }
  return value;
}

const authPort = port('SYNTHETIC_AUTH_PORT', '4302');
const apiPort = port('SYNTHETIC_API_PORT', '4301');

function syntheticWebOrigin(value) {
  let configured;
  try {
    configured = new URL(value);
  } catch {
    throw new Error('SYNTHETIC_WEB_ORIGIN must be a valid URL');
  }
  if (
    configured.protocol !== 'http:' ||
    configured.username !== '' ||
    configured.password !== '' ||
    configured.pathname !== '/' ||
    configured.search !== '' ||
    configured.hash !== ''
  ) {
    throw new Error('SYNTHETIC_WEB_ORIGIN must be a credential-free HTTP origin');
  }
  let hostname;
  switch (configured.hostname) {
    case '127.0.0.1':
      hostname = '127.0.0.1';
      break;
    case 'localhost':
      hostname = 'localhost';
      break;
    case '[::1]':
      hostname = '::1';
      break;
    default:
      throw new Error('SYNTHETIC_WEB_ORIGIN must use a loopback hostname');
  }
  const configuredPort = configured.port === '' ? 80 : Number.parseInt(configured.port, 10);
  if (!Number.isSafeInteger(configuredPort) || configuredPort < 1 || configuredPort > 65_535) {
    throw new Error('SYNTHETIC_WEB_ORIGIN must use a valid port');
  }
  return Object.freeze({ hostname, port: configuredPort });
}

const webOrigin = syntheticWebOrigin(process.env.SYNTHETIC_WEB_ORIGIN ?? 'http://127.0.0.1:3400');
const sessionCookie = 'kovcheg_session=synthetic-local-session';
const administrator = Object.freeze({
  accountAccess: 'member',
  accountStatus: 'active',
  administrativeCapabilities: Object.freeze({
    canManageAccounts: true,
    canManageDomainStatus: true,
    canManageFunctionalGrants: true,
    canManagePlatformAdministrators: true,
  }),
  contractVersion: 2,
  diagnosticCapabilities: Object.freeze({
    canReadBuildAndMigrationVersions: false,
    canReadHealthAndReadiness: false,
    canReadQueueAndTechnicalState: false,
    canReadSanitizedDiagnostics: false,
  }),
  displayName: 'Synthetic Administrator',
  domainStatus: 'disciple',
  email: 'administrator@example.invalid',
  functionalGrants: Object.freeze(['platform_administrator']),
  isServerOwner: false,
  materialCapabilities: Object.freeze([]),
  sensitiveCapabilities: Object.freeze({ canPerformSensitiveActions: false }),
  sessionId: '00000000-0000-4000-8000-000000000702',
  sessionStatus: 'active',
  status: 'active',
  userId: '00000000-0000-4000-8000-000000000701',
});
const syntheticAccountId = '00000000-0000-4000-8000-000000000703';
const chatId = '00000000-0000-4000-8000-000000000705';
const activeChallenges = new Set();
const messages = [];
const messagesByClientId = new Map();
let challengeCounter = 720;
let messageCounter = 800;
let sessionActive = true;

function json(response, status, body, headers = {}) {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json',
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function noContent(response, headers = {}) {
  response.writeHead(204, { 'cache-control': 'no-store', ...headers });
  response.end();
}

function authenticated(request) {
  return (
    sessionActive &&
    request.headers.cookie?.split(';').some((part) => part.trim() === sessionCookie) === true
  );
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return null;
  }
}

function proxyTarget(requestTarget) {
  const hasUnsafeCharacter =
    typeof requestTarget === 'string' &&
    [...requestTarget].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x20 || codePoint === 0x7f;
    });
  if (
    typeof requestTarget !== 'string' ||
    !requestTarget.startsWith('/') ||
    requestTarget.startsWith('//') ||
    requestTarget.includes('\\') ||
    hasUnsafeCharacter
  ) {
    return null;
  }
  let incoming;
  try {
    incoming = new URL(requestTarget, 'http://synthetic.invalid');
  } catch {
    return null;
  }
  if (incoming.origin !== 'http://synthetic.invalid' || incoming.hash !== '') {
    return null;
  }
  let segments;
  try {
    segments = incoming.pathname.split('/').map((segment) => decodeURIComponent(segment));
  } catch {
    return null;
  }
  if (segments.some((segment) => segment === '.' || segment === '..')) return null;
  const pathname = segments.map((segment) => encodeURIComponent(segment)).join('/');
  const query = incoming.searchParams.toString();
  return query === '' ? pathname : `${pathname}?${query}`;
}

async function proxyWeb(request, response) {
  const headers = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (
      value !== undefined &&
      !['connection', 'content-length', 'host', 'transfer-encoding'].includes(name)
    ) {
      headers[name] = value;
    }
  }
  const method = request.method ?? 'GET';
  const body = method === 'GET' || method === 'HEAD' ? undefined : await readRawBody(request);
  const target = proxyTarget(request.url);
  if (target === null) {
    json(response, 400, { error: 'synthetic.invalid-proxy-target' });
    return;
  }
  await new Promise((resolve, reject) => {
    const upstreamRequest = httpRequest(
      {
        headers,
        hostname: webOrigin.hostname,
        method,
        path: target,
        port: webOrigin.port,
      },
      (upstreamResponse) => {
        const downstreamHeaders = {};
        for (const [name, value] of Object.entries(upstreamResponse.headers)) {
          if (value !== undefined && !['connection', 'transfer-encoding'].includes(name)) {
            downstreamHeaders[name] = value;
          }
        }
        response.writeHead(upstreamResponse.statusCode ?? 502, downstreamHeaders);
        upstreamResponse.once('error', reject);
        upstreamResponse.once('end', resolve);
        upstreamResponse.pipe(response);
      },
    );
    upstreamRequest.once('error', reject);
    upstreamRequest.end(body);
  });
}

async function readRawBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function nextChallengeId() {
  challengeCounter += 1;
  return `00000000-0000-4000-8000-${String(challengeCounter).padStart(12, '0')}`;
}

function account(body = {}) {
  return Object.freeze({
    accountAccess: 'member',
    displayName: body.displayName ?? 'Synthetic Member',
    domainStatus: body.domainStatus ?? 'incubator_participant',
    email: body.email ?? 'member@example.invalid',
    functionalGrants: Object.freeze(body.functionalGrants ?? []),
    status: body.status ?? 'active',
    userId: syntheticAccountId,
  });
}

const authServer = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1');

  if (request.method === 'POST' && url.pathname === '/session/challenges') {
    const body = await readBody(request);
    const displayEmail = typeof body?.email === 'string' ? body.email.trim() : '';
    if (
      displayEmail.length < 3 ||
      displayEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+$/u.test(displayEmail)
    ) {
      json(response, 400, { error: 'auth.invalid-input' });
      return;
    }
    const challengeId = nextChallengeId();
    if (displayEmail.toLowerCase() === administrator.email) {
      activeChallenges.clear();
      activeChallenges.add(challengeId);
    }
    json(response, 202, { challengeId, email: displayEmail, next: 'code', status: 'accepted' });
    return;
  }

  const verification = url.pathname.match(/^\/session\/challenges\/([^/]+)\/verify$/u);
  if (request.method === 'POST' && verification !== null) {
    const body = await readBody(request);
    const challengeId = verification[1];
    if (
      challengeId !== undefined &&
      activeChallenges.delete(challengeId) &&
      body?.code === '246810'
    ) {
      sessionActive = true;
      json(
        response,
        200,
        {
          absoluteExpiresAt: Date.now() + 3_600_000,
          idleExpiresAt: Date.now() + 3_600_000,
          sessionId: administrator.sessionId,
          userId: administrator.userId,
        },
        { 'set-cookie': `${sessionCookie}; Path=/; HttpOnly; SameSite=Lax` },
      );
      return;
    }
    json(response, 401, { error: 'auth.invalid-or-expired-challenge' });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/session') {
    if (!authenticated(request)) {
      json(response, 401, { error: 'auth.invalid-session' });
      return;
    }
    const { displayName, email, status, ...principal } = administrator;
    void displayName;
    void email;
    void status;
    json(response, 200, principal);
    return;
  }

  if (request.method === 'DELETE' && url.pathname === '/session') {
    sessionActive = false;
    noContent(response, {
      'set-cookie': 'kovcheg_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
    });
    return;
  }

  if (!authenticated(request) || !url.pathname.startsWith('/admin/accounts')) {
    json(response, 403, { error: 'auth.forbidden' });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/admin/accounts') {
    json(response, 201, account(await readBody(request)));
    return;
  }

  if (request.method === 'PATCH' && /\/status$/u.test(url.pathname)) {
    json(response, 200, account(await readBody(request)));
    return;
  }

  if (request.method === 'PATCH' && /\/domain-status$/u.test(url.pathname)) {
    json(response, 200, account(await readBody(request)));
    return;
  }

  if (request.method === 'PATCH' && url.pathname === `/admin/accounts/${syntheticAccountId}`) {
    json(response, 200, account(await readBody(request)));
    return;
  }

  const grantRoute = url.pathname.match(/\/functional-grants\/([^/]+)$/u);
  if ((request.method === 'PUT' || request.method === 'DELETE') && grantRoute !== null) {
    json(
      response,
      200,
      account({ functionalGrants: request.method === 'PUT' ? [grantRoute[1]] : [] }),
    );
    return;
  }

  if (request.method === 'DELETE' && /\/sessions\/[^/]+$/u.test(url.pathname)) {
    json(response, 200, { revoked: true });
    return;
  }

  if (request.method === 'DELETE' && /\/sessions$/u.test(url.pathname)) {
    json(response, 200, { revokedSessionCount: 1 });
    return;
  }

  json(response, 404, { error: 'auth.not-found' });
});

const apiServer = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1');
  if (url.pathname === '/__synthetic/append' && request.method === 'POST') {
    if (!authenticated(request)) {
      json(response, 401, { error: 'synthetic.unauthenticated' });
      return;
    }
    messageCounter += 1;
    const message = Object.freeze({
      body: 'Synthetic catch-up message',
      chatId,
      chatSequence: String(messages.length + 1),
      clientMessageId: `fixture:catch-up-${messageCounter}`,
      createdAt: '2026-08-26T00:00:01.000Z',
      id: `00000000-0000-4000-8000-${String(messageCounter).padStart(12, '0')}`,
      senderAccountId: administrator.userId,
    });
    messages.push(message);
    messagesByClientId.set(message.clientMessageId, message);
    json(response, 201, message);
    return;
  }
  if (url.pathname === '/__synthetic/drop' && request.method === 'POST') {
    if (!authenticated(request)) {
      json(response, 401, { error: 'synthetic.unauthenticated' });
      return;
    }
    for (const socket of await socketServer.fetchSockets()) socket.conn.close();
    noContent(response);
    return;
  }
  if (url.pathname === '/__synthetic/revoke' && request.method === 'POST') {
    if (!authenticated(request)) {
      json(response, 401, { error: 'synthetic.unauthenticated' });
      return;
    }
    sessionActive = false;
    for (const socket of await socketServer.fetchSockets()) socket.conn.close();
    noContent(response);
    return;
  }
  if (url.pathname !== '/chats' && !url.pathname.startsWith('/chats/')) {
    await proxyWeb(request, response);
    return;
  }
  if (!authenticated(request)) {
    json(response, 401, { error: 'message-flow.unauthenticated' });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/chats') {
    json(response, 200, {
      contractVersion: 2,
      items: [
        {
          capabilities: { canRead: true, canWrite: true },
          id: chatId,
          kind: 'group',
        },
      ],
    });
    return;
  }
  if (url.pathname === `/chats/${chatId}/messages` && request.method === 'GET') {
    const after = BigInt(url.searchParams.get('afterSequence') ?? '0');
    const beforeValue = url.searchParams.get('beforeSequence');
    const before = beforeValue === null ? null : BigInt(beforeValue);
    const limit = Number.parseInt(url.searchParams.get('limit') ?? '50', 10);
    const visible = messages.filter((message) => {
      const sequence = BigInt(message.chatSequence);
      return before === null ? sequence > after : sequence < before;
    });
    const items = before === null ? visible.slice(0, limit) : visible.slice(-limit);
    json(response, 200, {
      contractVersion: 3,
      hasMore: visible.length > items.length,
      items,
      nextAfterSequence:
        before === null && visible.length > items.length
          ? (items.at(-1)?.chatSequence ?? null)
          : null,
      nextBeforeSequence:
        before !== null && visible.length > items.length ? (items[0]?.chatSequence ?? null) : null,
    });
    return;
  }
  if (url.pathname === `/chats/${chatId}/messages` && request.method === 'POST') {
    const body = await readBody(request);
    const existing = messagesByClientId.get(body?.clientMessageId);
    if (existing !== undefined) {
      json(response, 200, { contractVersion: 2, message: existing, outcome: 'replayed' });
      return;
    }
    messageCounter += 1;
    const message = Object.freeze({
      body: body?.text ?? 'Synthetic message',
      chatId,
      chatSequence: String(messages.length + 1),
      clientMessageId: body?.clientMessageId,
      createdAt: '2026-08-26T00:00:00.000Z',
      id: `00000000-0000-4000-8000-${String(messageCounter).padStart(12, '0')}`,
      senderAccountId: administrator.userId,
    });
    messages.push(message);
    messagesByClientId.set(message.clientMessageId, message);
    json(response, 201, { contractVersion: 2, message, outcome: 'created' });
    socketServer.to(`chat:${chatId}`).emit('realtime.message-created', {
      contractVersion: 2,
      correlationId: 'synthetic-realtime',
      eventId: `00000000-0000-4000-8000-${String(messageCounter + 1_000).padStart(12, '0')}`,
      eventName: 'message.created',
      occurredAt: message.createdAt,
      payload: {
        chatId,
        chatSequence: message.chatSequence,
        messageId: message.id,
        senderAccountId: message.senderAccountId,
      },
    });
    return;
  }
  json(response, 404, { error: 'message-flow.forbidden' });
});

const socketServer = new SocketIoServer(apiServer, {
  path: '/socket.io',
  transports: ['polling', 'websocket'],
});
socketServer.use((socket, next) => {
  if (authenticated({ headers: socket.handshake.headers })) next();
  else next(new Error('unauthenticated'));
});
socketServer.on('connection', (socket) => {
  socket.emit('realtime.ready', { contractVersion: 2, instanceId: 'synthetic-api' });
  socket.on('realtime.subscribe', (value, acknowledge) => {
    const afterSequence = String(value?.afterSequence ?? '0');
    if (value?.chatId !== chatId || !/^\d+$/u.test(afterSequence)) {
      acknowledge({ contractVersion: 2, history: [], joined: false, nextAfterSequence: '0' });
      return;
    }
    void socket.join(`chat:${chatId}`);
    const history = messages.filter(
      (message) => BigInt(message.chatSequence) > BigInt(afterSequence),
    );
    acknowledge({
      contractVersion: 2,
      history,
      joined: true,
      nextAfterSequence: history.at(-1)?.chatSequence ?? afterSequence,
    });
  });
});

authServer.listen(authPort, '127.0.0.1', () => {
  process.stdout.write(`Synthetic A6 auth upstream listening on 127.0.0.1:${authPort}\n`);
});
apiServer.listen(apiPort, '127.0.0.1', () => {
  process.stdout.write(`Synthetic A6 API upstream listening on 127.0.0.1:${apiPort}\n`);
});
