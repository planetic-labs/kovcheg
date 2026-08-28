/* global Buffer, Headers, process, Response, URL */

import { request as httpRequest } from 'node:http';

const [applicationLoopback, issuerLoopback] = process.argv.slice(2);
const applicationOrigin = process.env.KOVCHEG_WEB_OIDC_REDIRECT_URI
  ? new URL(process.env.KOVCHEG_WEB_OIDC_REDIRECT_URI).origin
  : null;
const issuerOrigin = process.env.KOVCHEG_WEB_OIDC_ISSUER ?? null;
const existingSession = process.env.KOVCHEG_SMOKE_SESSION_TOKEN ?? null;
const maximumDiagnosticBodyBytes = 4096;
const maximumSmokeResponseBytes = 1024 * 1024;
const safeErrorCodes = new Set(['a6.oidc-not-configured']);
const uuidExpression =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

if (
  applicationLoopback === undefined ||
  issuerLoopback === undefined ||
  applicationOrigin === null ||
  issuerOrigin === null ||
  existingSession === null
) {
  throw new Error('OIDC dual-host smoke input is incomplete');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function boundedResponseMetadata(response) {
  if (response.body === null) {
    return { bodyBytes: 0, bodyKind: 'empty', errorCode: 'absent' };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let bodyBytes = 0;
  let oversized = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bodyBytes += value.byteLength;
    if (bodyBytes > maximumDiagnosticBodyBytes) {
      oversized = true;
      await reader.cancel();
      break;
    }
    chunks.push(Buffer.from(value));
  }

  if (oversized) {
    return {
      bodyBytes: `>${maximumDiagnosticBodyBytes}`,
      bodyKind: 'oversized',
      errorCode: 'unverified',
    };
  }
  if (bodyBytes === 0) {
    return { bodyBytes, bodyKind: 'empty', errorCode: 'absent' };
  }

  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return { bodyBytes, bodyKind: 'non-json', errorCode: 'unverified' };
  }
  const candidate =
    parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed.code : null;
  return {
    bodyBytes,
    bodyKind: 'json',
    errorCode:
      typeof candidate === 'string' && safeErrorCodes.has(candidate)
        ? candidate
        : candidate === null
          ? 'absent'
          : 'unrecognized',
  };
}

async function requireStatus(response, expectedStatus, stage) {
  if (response.status === expectedStatus) return;
  const metadata = await boundedResponseMetadata(response);
  throw new Error(
    `${stage} response mismatch: expected=${expectedStatus} actual=${response.status} ` +
      `bodyKind=${metadata.bodyKind} bodyBytes=${metadata.bodyBytes} ` +
      `errorCode=${metadata.errorCode}`,
  );
}

function setCookieValues(response) {
  const headers = response.headers;
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const value = headers.get('set-cookie');
  return value === null ? [] : [value];
}

function updateJar(response, jar) {
  for (const header of setCookieValues(response)) {
    const pair = header.split(';', 1)[0];
    const separator = pair.indexOf('=');
    if (separator < 1) continue;
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (/Max-Age=0(?:;|$)/iu.test(header) || value.length === 0) jar.delete(name);
    else jar.set(name, value);
  }
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function loopbackUrl(publicLocation, expectedOrigin, targetOrigin) {
  const location = new URL(publicLocation, expectedOrigin);
  assert(location.origin === expectedOrigin, 'OIDC redirect crossed an unexpected origin');
  const target = new URL(targetOrigin);
  assert(
    target.protocol === 'http:' &&
      target.hostname === '127.0.0.1' &&
      target.username === '' &&
      target.password === '',
    'OIDC smoke target must be an uncredentialed IPv4 loopback HTTP origin',
  );
  target.pathname = location.pathname;
  target.search = location.search;
  return target;
}

function hostPreservingLoopbackRequest(target, publicHost, cookies) {
  return new Promise((resolve, reject) => {
    const headers = { host: publicHost };
    if (cookies.length > 0) headers.cookie = cookies;
    const request = httpRequest(target, { headers, method: 'GET' }, (response) => {
      const chunks = [];
      let bodyBytes = 0;
      response.on('data', (chunk) => {
        bodyBytes += chunk.length;
        if (bodyBytes > maximumSmokeResponseBytes) {
          response.destroy(new Error('OIDC smoke response exceeded its fixed byte limit'));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.once('error', reject);
      response.once('end', () => {
        const status = response.statusCode;
        if (status === undefined || status < 200 || status > 599) {
          reject(new Error('OIDC smoke response status is invalid'));
          return;
        }
        const responseHeaders = new Headers();
        for (let index = 0; index < response.rawHeaders.length; index += 2) {
          const name = response.rawHeaders[index];
          const value = response.rawHeaders[index + 1];
          if (name !== undefined && value !== undefined) responseHeaders.append(name, value);
        }
        resolve(
          new Response(Buffer.concat(chunks), {
            headers: responseHeaders,
            status,
            statusText: response.statusMessage,
          }),
        );
      });
    });
    request.once('error', reject);
    request.end();
  });
}

async function browserRequest(publicLocation, expectedOrigin, targetOrigin, jar) {
  const publicUrl = new URL(publicLocation, expectedOrigin);
  const cookies = cookieHeader(jar);
  const response = await hostPreservingLoopbackRequest(
    loopbackUrl(publicUrl, expectedOrigin, targetOrigin),
    publicUrl.host,
    cookies,
  );
  updateJar(response, jar);
  return response;
}

const applicationCookies = new Map();
const issuerCookies = new Map();

const start = await browserRequest(
  '/bff/auth/oidc/start',
  applicationOrigin,
  applicationLoopback,
  applicationCookies,
);
await requireStatus(start, 303, 'oidc-start');
const authorizationLocation = start.headers.get('location');
assert(authorizationLocation !== null, 'OIDC start omitted its authorization location');
assert(new URL(authorizationLocation).origin === issuerOrigin, 'OIDC start used the wrong issuer');
assert(applicationCookies.has('__Host-kovcheg_oidc'), 'OIDC binding cookie was not host-bound');

const authorization = await browserRequest(
  authorizationLocation,
  issuerOrigin,
  issuerLoopback,
  issuerCookies,
);
await requireStatus(authorization, 303, 'oidc-authorization');
const interactionLocation = authorization.headers.get('location');
assert(interactionLocation !== null, 'OIDC authorization omitted the interaction location');

issuerCookies.set('__Host-kovcheg_session', existingSession);
const interaction = await browserRequest(
  interactionLocation,
  issuerOrigin,
  issuerLoopback,
  issuerCookies,
);
await requireStatus(interaction, 303, 'oidc-interaction');
const resumeLocation = interaction.headers.get('location');
assert(resumeLocation !== null, 'OIDC interaction omitted its resume location');

const resume = await browserRequest(resumeLocation, issuerOrigin, issuerLoopback, issuerCookies);
await requireStatus(resume, 303, 'oidc-resume');
const callbackLocation = resume.headers.get('location');
assert(callbackLocation !== null, 'OIDC provider omitted the application callback');
assert(
  new URL(callbackLocation).origin === applicationOrigin,
  'OIDC provider used the wrong callback',
);

const callback = await browserRequest(
  callbackLocation,
  applicationOrigin,
  applicationLoopback,
  applicationCookies,
);
await requireStatus(callback, 303, 'oidc-callback');
assert(
  callback.headers.get('location') === `${applicationOrigin}/`,
  'OIDC callback redirect drifted',
);
assert(!applicationCookies.has('__Host-kovcheg_oidc'), 'OIDC binding was not cleared');
assert(applicationCookies.has('__Host-kovcheg_session'), 'Application session cookie is missing');

const session = await browserRequest(
  '/bff/session',
  applicationOrigin,
  applicationLoopback,
  applicationCookies,
);
await requireStatus(session, 200, 'application-session');
const principal = await session.json();
assert(
  principal !== null &&
    typeof principal === 'object' &&
    principal.contractVersion === 2 &&
    principal.accountAccess === 'member' &&
    principal.accountStatus === 'active' &&
    principal.sessionStatus === 'active' &&
    typeof principal.userId === 'string' &&
    uuidExpression.test(principal.userId) &&
    typeof principal.sessionId === 'string' &&
    uuidExpression.test(principal.sessionId),
  'OIDC-created application session returned an invalid principal',
);

const replay = await browserRequest(
  callbackLocation,
  applicationOrigin,
  applicationLoopback,
  new Map(applicationCookies),
);
await requireStatus(replay, 503, 'oidc-replay');

process.stdout.write('Dual-host OIDC session bridge passed.\n');
