/* global fetch, Headers, process, URL */

const [applicationLoopback, issuerLoopback] = process.argv.slice(2);
const applicationOrigin = process.env.KOVCHEG_WEB_OIDC_REDIRECT_URI
  ? new URL(process.env.KOVCHEG_WEB_OIDC_REDIRECT_URI).origin
  : null;
const issuerOrigin = process.env.KOVCHEG_WEB_OIDC_ISSUER ?? null;
const existingSession = process.env.KOVCHEG_SMOKE_SESSION_TOKEN ?? null;

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
  target.pathname = location.pathname;
  target.search = location.search;
  return target;
}

async function browserRequest(publicLocation, expectedOrigin, targetOrigin, jar) {
  const publicUrl = new URL(publicLocation, expectedOrigin);
  const headers = new Headers({
    host: publicUrl.host,
    'x-forwarded-host': publicUrl.host,
    'x-forwarded-proto': 'https',
  });
  const cookies = cookieHeader(jar);
  if (cookies.length > 0) headers.set('cookie', cookies);
  const response = await fetch(loopbackUrl(publicUrl, expectedOrigin, targetOrigin), {
    headers,
    redirect: 'manual',
  });
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
assert(start.status === 303, 'OIDC start did not redirect');
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
assert(authorization.status === 303, 'OIDC authorization did not create an interaction');
const interactionLocation = authorization.headers.get('location');
assert(interactionLocation !== null, 'OIDC authorization omitted the interaction location');

issuerCookies.set('__Host-kovcheg_session', existingSession);
const interaction = await browserRequest(
  interactionLocation,
  issuerOrigin,
  issuerLoopback,
  issuerCookies,
);
assert(interaction.status === 303, 'OIDC interaction rejected an existing active account');
const resumeLocation = interaction.headers.get('location');
assert(resumeLocation !== null, 'OIDC interaction omitted its resume location');

const resume = await browserRequest(resumeLocation, issuerOrigin, issuerLoopback, issuerCookies);
assert(resume.status === 303, 'OIDC provider did not issue an authorization code');
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
assert(callback.status === 303, 'OIDC callback did not create an application session');
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
assert(session.status === 200, 'OIDC-created application session is not active');
const principal = await session.json();
assert(
  principal !== null &&
    typeof principal === 'object' &&
    principal.sessionActive === true &&
    typeof principal.accountId === 'string',
  'OIDC-created application session returned an invalid principal',
);

const replay = await browserRequest(
  callbackLocation,
  applicationOrigin,
  applicationLoopback,
  new Map(applicationCookies),
);
assert(replay.status === 503, 'OIDC callback replay did not fail closed');

process.stdout.write('Dual-host OIDC session bridge passed.\n');
