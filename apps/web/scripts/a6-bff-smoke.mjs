/* global Headers, URL, fetch, process */

import assert from 'node:assert/strict';

const baseUrl = new URL(process.argv[2] ?? 'http://127.0.0.1:3400');
assert.ok(
  ['127.0.0.1', '::1', 'localhost'].includes(baseUrl.hostname),
  'The A6 BFF smoke target must be loopback-only',
);

function setCookieValues(response) {
  return response.headers.getSetCookie?.() ?? [response.headers.get('set-cookie')].filter(Boolean);
}

function updateCookies(cookieJar, response) {
  for (const setCookie of setCookieValues(response)) {
    const pair = setCookie.split(';', 1)[0];
    const separator = pair.indexOf('=');
    if (separator < 1) continue;
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (/Max-Age=0/iu.test(setCookie) || value.length === 0) cookieJar.delete(name);
    else cookieJar.set(name, value);
  }
}

function cookieHeader(cookieJar) {
  return [...cookieJar].map(([name, value]) => `${name}=${value}`).join('; ');
}

async function request(cookieJar, path, init = {}) {
  const headers = new Headers(init.headers);
  const cookie = cookieHeader(cookieJar);
  if (cookie.length > 0) headers.set('cookie', cookie);
  const response = await fetch(new URL(path, baseUrl), { ...init, headers, redirect: 'manual' });
  updateCookies(cookieJar, response);
  return response;
}

async function challenge(cookieJar, email) {
  const response = await request(cookieJar, '/bff/auth/challenge', {
    body: JSON.stringify({ email }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { status: 'accepted' });
  assert.ok(cookieJar.has('kovcheg_login_challenge'));
}

async function rejectedIdentity(email) {
  const cookieJar = new Map();
  await challenge(cookieJar, email);
  const verification = await request(cookieJar, '/bff/auth/challenge/verify', {
    body: JSON.stringify({ code: '246810' }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal(verification.status, 401);
  assert.ok(!cookieJar.has('kovcheg_session'));
}

const manifest = await fetch(new URL('/manifest.webmanifest', baseUrl));
assert.equal(manifest.status, 200);
assert.equal((await manifest.json()).display, 'standalone');

const cookieJar = new Map();
await challenge(cookieJar, 'administrator@example.invalid');
const verification = await request(cookieJar, '/bff/auth/challenge/verify', {
  body: JSON.stringify({ code: '246810' }),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
assert.equal(verification.status, 200);
assert.deepEqual(await verification.json(), { authenticated: true });
assert.ok(cookieJar.has('kovcheg_session'));
assert.ok(!cookieJar.has('kovcheg_login_challenge'));

const session = await request(cookieJar, '/bff/session');
assert.equal(session.status, 200);
const principal = await session.json();
assert.equal(principal.contractVersion, 2);
assert.equal(principal.administrativeCapabilities.canManageAccounts, true);

const accountInput = {
  displayName: 'Synthetic Member',
  email: 'member@example.invalid',
};
const created = await request(cookieJar, '/bff/admin/accounts', {
  body: JSON.stringify(accountInput),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
assert.equal(created.status, 201);
const account = await created.json();
assert.equal(account.domainStatus, 'incubator_participant');

const changedDomain = await request(
  cookieJar,
  `/bff/admin/accounts/${account.userId}/domain-status`,
  {
    body: JSON.stringify({ domainStatus: 'disciple', reason: 'synthetic-check', version: 2 }),
    headers: { 'content-type': 'application/json' },
    method: 'PATCH',
  },
);
assert.equal(changedDomain.status, 200);
assert.equal((await changedDomain.json()).domainStatus, 'disciple');

const granted = await request(
  cookieJar,
  `/bff/admin/accounts/${account.userId}/functional-grants/chronicler`,
  {
    body: JSON.stringify({ reason: 'synthetic-check', version: 3 }),
    headers: { 'content-type': 'application/json' },
    method: 'PUT',
  },
);
assert.equal(granted.status, 200);
assert.deepEqual((await granted.json()).functionalGrants, ['chronicler']);

const deactivated = await request(cookieJar, `/bff/admin/accounts/${account.userId}/status`, {
  body: JSON.stringify({ status: 'deactivated' }),
  headers: { 'content-type': 'application/json' },
  method: 'PATCH',
});
assert.equal(deactivated.status, 200);
assert.equal((await deactivated.json()).status, 'deactivated');

const revokedOne = await request(
  cookieJar,
  `/bff/admin/accounts/${account.userId}/sessions/00000000-0000-4000-8000-000000000704`,
  { method: 'DELETE' },
);
assert.equal(revokedOne.status, 200);
assert.equal((await revokedOne.json()).revoked, true);

const revokedAll = await request(cookieJar, `/bff/admin/accounts/${account.userId}/sessions`, {
  method: 'DELETE',
});
assert.equal(revokedAll.status, 200);
assert.equal((await revokedAll.json()).revokedSessionCount, 1);

const chats = await request(cookieJar, '/bff/chats');
assert.equal(chats.status, 200);
const chatList = await chats.json();
assert.equal(chatList.contractVersion, 2);
assert.equal(chatList.items[0].capabilities.canWrite, true);
const chatId = chatList.items[0].id;

const emptyHistory = await request(cookieJar, `/bff/chats/${chatId}/messages?limit=50`);
assert.equal(emptyHistory.status, 200);
assert.deepEqual((await emptyHistory.json()).items, []);

const messageBody = { clientMessageId: 'web:synthetic-smoke-001', text: 'Synthetic text' };
const createdMessage = await request(cookieJar, `/bff/chats/${chatId}/messages`, {
  body: JSON.stringify(messageBody),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
assert.equal(createdMessage.status, 201);
const firstMessage = await createdMessage.json();
assert.equal(firstMessage.outcome, 'created');

const replayedMessage = await request(cookieJar, `/bff/chats/${chatId}/messages`, {
  body: JSON.stringify(messageBody),
  headers: { 'content-type': 'application/json' },
  method: 'POST',
});
assert.equal(replayedMessage.status, 200);
const replayed = await replayedMessage.json();
assert.equal(replayed.outcome, 'replayed');
assert.equal(replayed.message.id, firstMessage.message.id);

const caughtUp = await request(
  cookieJar,
  `/bff/chats/${chatId}/messages?afterSequence=0&limit=100`,
);
assert.equal(caughtUp.status, 200);
assert.equal((await caughtUp.json()).items.length, 1);

const loggedOut = await request(cookieJar, '/bff/session', { method: 'DELETE' });
assert.equal(loggedOut.status, 204);
assert.ok(!cookieJar.has('kovcheg_session'));
assert.equal((await request(cookieJar, '/bff/session')).status, 401);

await rejectedIdentity('unknown@example.invalid');
await rejectedIdentity('deactivated@example.invalid');

process.stdout.write('A6 BFF synthetic smoke passed\n');
