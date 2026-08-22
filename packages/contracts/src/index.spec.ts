import { describe, expect, it } from 'vitest';

import {
  coreModuleNames,
  correlationIdHeaderName,
  correlationIdMiddleware,
  createCorrelationId,
  createOperationalEvent,
  createServiceHealth,
  denyAllAuthorizationEvaluator,
  errorCodes,
  foundationContractVersion,
  machineErrorJsonSchema,
  parseCorrelationId,
  serviceHealthJsonSchema,
  unknownBuildMetadata,
} from './index.js';
import type { AuthorizationRequest, CorrelationRequest } from './index.js';

describe('foundation contracts', () => {
  it('exports an explicit contract version', () => {
    expect(foundationContractVersion).toBe(1);
  });

  it('creates a typed readiness response', () => {
    expect(createServiceHealth('api', 'ready')).toEqual({
      build: {
        commitSha: null,
        contractVersion: 1,
        imageDigest: null,
        migrationVersion: null,
      },
      checks: [],
      contractVersion: 1,
      service: 'api',
      state: 'ready',
      status: 'ok',
    });
  });

  it('supports degraded and unavailable health without dependency checks', () => {
    expect(
      createServiceHealth('worker', 'ready', {
        checks: [{ name: 'future-dependency', status: 'unavailable' }],
        status: 'degraded',
      }),
    ).toMatchObject({
      checks: [{ name: 'future-dependency', status: 'unavailable' }],
      status: 'degraded',
    });
    expect(serviceHealthJsonSchema.properties.status.enum).toEqual([
      'ok',
      'degraded',
      'unavailable',
    ]);
  });

  it('accepts safe correlation IDs and replaces invalid values', () => {
    const generated = createCorrelationId();
    expect(parseCorrelationId(generated)).toBe(generated);
    expect(parseCorrelationId('request-123')).toBe('request-123');
    expect(parseCorrelationId('unsafe value')).toBeNull();

    const headers = new Map<string, string>();
    let nextCalled = false;
    const request: CorrelationRequest = {
      headers: { [correlationIdHeaderName]: 'unsafe value' },
    };
    correlationIdMiddleware(
      request,
      {
        setHeader(name, value) {
          headers.set(name, value);
        },
      },
      () => {
        nextCalled = true;
      },
    );

    expect(parseCorrelationId(headers.get(correlationIdHeaderName))).not.toBeNull();
    expect(request.correlationId).toBe(headers.get(correlationIdHeaderName));
    expect(nextCalled).toBe(true);
  });

  it('publishes a stable machine-error code set', () => {
    expect(errorCodes).toEqual([
      'foundation.invalid-request',
      'foundation.not-found',
      'foundation.conflict',
      'foundation.unavailable',
      'foundation.internal-error',
      'message-flow.invalid-request',
      'message-flow.identity-unavailable',
      'message-flow.unauthenticated',
      'message-flow.forbidden',
      'message-flow.idempotency-key-reused',
      'message-flow.unavailable',
      'message-flow.internal-error',
    ]);
    expect(machineErrorJsonSchema.properties.code.enum).toEqual(errorCodes);
  });

  it('creates versioned operational events without arbitrary payload data', () => {
    const event = createOperationalEvent({
      correlationId: createCorrelationId(),
      name: 'service.started',
      occurredAt: '2026-01-01T00:00:00.000Z',
      outcome: 'success',
      service: 'api',
    });

    expect(event).toEqual({
      build: unknownBuildMetadata,
      contractVersion: 1,
      correlationId: event.correlationId,
      name: 'service.started',
      occurredAt: '2026-01-01T00:00:00.000Z',
      outcome: 'success',
      service: 'api',
    });
  });

  it('denies authorization by default', async () => {
    const request: AuthorizationRequest = {
      action: 'foundation.probe',
      identity: null,
      resource: { module: 'authorization', resourceId: null },
      session: null,
    };

    await expect(denyAllAuthorizationEvaluator.authorize(request)).resolves.toEqual({
      allowed: false,
      reason: 'not-implemented',
    });
  });

  it('keeps the core module boundary explicit', () => {
    expect(coreModuleNames).toEqual([
      'identity',
      'session',
      'authorization',
      'users',
      'chats',
      'messages',
      'realtime',
      'notifications',
    ]);
  });
});
