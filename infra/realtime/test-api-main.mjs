/* global process */

import { loadServiceConfig } from '@kovcheg/config';
import { createSyntheticIdentityStub } from '@kovcheg/contracts/testing';

import { createApiApplication } from './dist/application.js';
import { loadRealtimeApiRuntimeOptions } from './dist/realtime/realtime.config.js';
import { ApplicationSessionError } from './dist/session/application-session.js';

function testSessionAuthenticator() {
  if (process.env.NODE_ENV !== 'test' || process.env.KOVCHEG_IDENTITY_STUB_ENABLED !== 'true') {
    throw new Error('The isolated test session adapter is unavailable');
  }
  const identities = createSyntheticIdentityStub({ NODE_ENV: 'test' });
  return Object.freeze({
    async authenticate(cookieHeader) {
      const match = /(?:^|;\s*)kovcheg_session=([0-9a-f-]{36})(?:;|$)/iu.exec(cookieHeader ?? '');
      const userId = match?.[1];
      const identity = userId === undefined ? null : await identities.findById(userId);
      if (identity === null || identity.status !== 'active') {
        throw new ApplicationSessionError('unauthenticated');
      }
      return Object.freeze({ sessionId: userId, userId });
    },
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
