import { afterEach, describe, expect, it } from 'vitest';

import { loadServiceConfig } from '@kovcheg/config';
import {
  correlationIdHeaderName,
  identityStubHeaderName,
  parseCorrelationId,
} from '@kovcheg/contracts';
import { createSyntheticIdentityStub, syntheticUserIds } from '@kovcheg/contracts/testing';

import { createApiApplication } from './application.js';

const openApplications: Awaited<ReturnType<typeof createApiApplication>>[] = [];

afterEach(async () => {
  await Promise.all(openApplications.splice(0).map(async (app) => app.close()));
});

describe('API HTTP foundation', () => {
  it('serves liveness, readiness, and a local OpenAPI document', async () => {
    const app = await createApiApplication(undefined, {
      repository: {
        isReady: () => Promise.resolve(true),
        subscribe: () => Promise.resolve({ history: Object.freeze([]) }),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const [liveResponse, readyResponse, openApiResponse] = await Promise.all([
      fetch(`${baseUrl}/health/live`, {
        headers: { [correlationIdHeaderName]: 'api-test-001' },
      }),
      fetch(`${baseUrl}/health/ready`),
      fetch(`${baseUrl}/openapi.json`),
    ]);

    expect(liveResponse.status).toBe(200);
    expect(liveResponse.headers.get(correlationIdHeaderName)).toBe('api-test-001');
    await expect(liveResponse.json()).resolves.toMatchObject({
      service: 'api',
      state: 'live',
      status: 'ok',
    });
    expect(readyResponse.status).toBe(200);
    expect(parseCorrelationId(readyResponse.headers.get(correlationIdHeaderName))).not.toBeNull();
    await expect(readyResponse.json()).resolves.toMatchObject({
      service: 'api',
      state: 'ready',
      status: 'ok',
    });
    expect(openApiResponse.status).toBe(200);
    const openApiDocument = (await openApiResponse.json()) as Record<string, unknown>;
    expect(openApiDocument).toMatchObject({
      info: { title: 'Kovcheg API' },
      openapi: expect.stringMatching(/^3\./),
      paths: {
        '/chats/{chatId}/messages': {
          get: {
            parameters: expect.arrayContaining([
              expect.objectContaining({ in: 'header', name: identityStubHeaderName }),
              expect.objectContaining({ in: 'query', name: 'afterSequence' }),
              expect.objectContaining({ in: 'query', name: 'limit' }),
            ]),
            responses: { 200: expect.any(Object), 403: expect.any(Object) },
          },
          post: {
            parameters: expect.arrayContaining([
              expect.objectContaining({ in: 'header', name: identityStubHeaderName }),
            ]),
            requestBody: expect.any(Object),
            responses: {
              200: expect.any(Object),
              201: expect.any(Object),
              409: expect.any(Object),
            },
          },
        },
        '/health/live': expect.any(Object),
        '/health/ready': expect.any(Object),
      },
    });
  });

  it('returns correlation-bound machine errors at the identity and database boundaries', async () => {
    const identityStub = createSyntheticIdentityStub({ NODE_ENV: 'test' });
    const app = await createApiApplication(undefined, {
      identityProvider: {
        available: true,
        findById: (userId) => identityStub.findById(userId),
      },
    });
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();
    const chatId = '00000000-0000-4000-8000-000000004001';
    const requestBody = JSON.stringify({
      clientMessageId: 'http-message-001',
      text: 'Synthetic HTTP message',
    });

    const unauthenticatedResponse = await fetch(`${baseUrl}/chats/${chatId}/messages`, {
      body: requestBody,
      headers: {
        'content-type': 'application/json',
        [correlationIdHeaderName]: 'http-message-unauthenticated',
      },
      method: 'POST',
    });
    expect(unauthenticatedResponse.status).toBe(401);
    await expect(unauthenticatedResponse.json()).resolves.toMatchObject({
      code: 'message-flow.unauthenticated',
      correlationId: 'http-message-unauthenticated',
      httpStatus: 401,
    });

    const deactivatedResponse = await fetch(`${baseUrl}/chats/${chatId}/messages`, {
      headers: {
        [correlationIdHeaderName]: 'http-history-deactivated',
        [identityStubHeaderName]: syntheticUserIds.deactivated,
      },
    });
    expect(deactivatedResponse.status).toBe(403);
    await expect(deactivatedResponse.json()).resolves.toMatchObject({
      code: 'message-flow.forbidden',
      correlationId: 'http-history-deactivated',
      httpStatus: 403,
    });

    const unavailableResponse = await fetch(`${baseUrl}/chats/${chatId}/messages`, {
      body: requestBody,
      headers: {
        'content-type': 'application/json',
        [correlationIdHeaderName]: 'http-message-unavailable',
        [identityStubHeaderName]: syntheticUserIds.activePrimary,
      },
      method: 'POST',
    });
    expect(unavailableResponse.status).toBe(503);
    await expect(unavailableResponse.json()).resolves.toMatchObject({
      code: 'message-flow.unavailable',
      correlationId: 'http-message-unavailable',
      httpStatus: 503,
    });
  });

  it('keeps OpenAPI JSON but disables Swagger UI in production', async () => {
    const app = await createApiApplication(
      loadServiceConfig('api', { LOG_LEVEL: 'error', NODE_ENV: 'production' }),
    );
    openApplications.push(app);
    await app.listen(0, '127.0.0.1');
    const baseUrl = await app.getUrl();

    const [openApiResponse, swaggerResponse] = await Promise.all([
      fetch(`${baseUrl}/openapi.json`),
      fetch(`${baseUrl}/docs`),
    ]);

    expect(openApiResponse.status).toBe(200);
    expect(swaggerResponse.status).toBe(404);
  });
});
