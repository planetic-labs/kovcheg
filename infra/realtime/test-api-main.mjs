/* global process */

import { loadServiceConfig } from '@kovcheg/config';
import { createSyntheticIdentityStub } from '@kovcheg/contracts/testing';

import { createApiApplication } from './dist/application.js';
import { loadRealtimeApiRuntimeOptions } from './dist/realtime/realtime.config.js';
import { ApplicationSessionError } from './dist/session/application-session.js';

const messageAuditSessions = new Map([
  ['00000000-0000-4000-8000-000000009001', '00000000-0000-4000-8000-000000009291'],
]);

function testSessionAuthenticator() {
  if (process.env.NODE_ENV !== 'test' || process.env.KOVCHEG_IDENTITY_STUB_ENABLED !== 'true') {
    throw new Error('The isolated test session adapter is unavailable');
  }
  const identities = createSyntheticIdentityStub({ NODE_ENV: 'test' });
  const authenticate = async (cookieHeader) => {
    const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
    const userId = match?.[1];
    const sessionId = userId === undefined ? undefined : messageAuditSessions.get(userId);
    if (userId !== undefined && sessionId !== undefined) {
      return Object.freeze({ sessionId, userId });
    }
    const identity = userId === undefined ? null : await identities.findById(userId);
    if (identity === null || identity.status !== 'active') {
      throw new ApplicationSessionError('unauthenticated');
    }
    return Object.freeze({ sessionId: userId, userId });
  };
  return Object.freeze({
    authenticate,
    isReady: () => Promise.resolve(true),
    validate: authenticate,
  });
}

const config = loadServiceConfig('api');
const realtime = loadRealtimeApiRuntimeOptions();
const app = await createApiApplication(config, {
  instanceId: realtime.instanceId,
  redisUrl: realtime.redisUrl,
  relayToken: realtime.relayToken,
  sessionAuthenticator: testSessionAuthenticator(),
});
app.enableShutdownHooks();
await app.listen(config.port, config.host);
