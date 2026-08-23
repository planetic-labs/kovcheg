import type { QueryResultRow } from 'pg';
import { describe, expect, it } from 'vitest';

import { AuthRepositoryConflictError } from './contracts.js';
import {
  createPostgresOidcStorageAdapter,
  PostgresAuthRepository,
  PostgresOidcClientRepository,
} from './postgres.js';
import type { AuthPostgresClient } from './postgres.js';

class QueryFixture implements AuthPostgresClient {
  readonly calls: { readonly text: string; readonly values: readonly unknown[] }[] = [];

  constructor(
    private readonly results: (readonly QueryResultRow[] | { readonly error: unknown })[],
  ) {}

  query<Row extends QueryResultRow>(
    text: string,
    values: readonly unknown[] = [],
  ): Promise<{ readonly rows: Row[] }> {
    this.calls.push({ text, values });
    const result = this.results.shift();
    if (result === undefined) {
      return Promise.reject(new Error('Missing synthetic query result'));
    }
    if ('error' in result) {
      return Promise.reject(result.error);
    }
    return Promise.resolve({ rows: [...result] as Row[] });
  }
}

describe('A2 PostgreSQL auth repository', () => {
  it('maps the PostgreSQL custom enum array returned by session functions', async () => {
    const client = new QueryFixture([
      [
        {
          account_id: '00000000-0000-4000-8000-000000000050',
          auth_roles: '{administrator}',
          session_id: '00000000-0000-4000-8000-000000000054',
        },
      ],
    ]);
    const repository = new PostgresAuthRepository(client);
    await expect(repository.authenticateSession('v'.repeat(43), Date.now())).resolves.toEqual({
      roles: ['administrator'],
      sessionId: '00000000-0000-4000-8000-000000000054',
      userId: '00000000-0000-4000-8000-000000000050',
    });
  });

  it('maps durable neutral and active-account challenge outcomes without direct table access', async () => {
    const client = new QueryFixture([
      [{ account_id: null, challenge_id: null, outcome: 'neutral', recipient: null }],
      [
        {
          account_id: '00000000-0000-4000-8000-000000000051',
          challenge_id: '00000000-0000-4000-8000-000000000052',
          outcome: 'issued',
          recipient: 'synthetic-account@example.invalid',
        },
      ],
    ]);
    const repository = new PostgresAuthRepository(client);
    const base = {
      challenge: {
        challengeId: '00000000-0000-4000-8000-000000000052' as const,
        codeVerifier: 'v'.repeat(43),
        expiresAt: 20_000,
        issuedAt: 10_000,
        maxAttempts: 5,
      },
      email: 'synthetic-account@example.invalid',
      resendCooldownMs: 60_000,
    };

    await expect(repository.issueChallengeForActiveAccount(base)).resolves.toEqual({
      kind: 'neutral',
    });
    await expect(repository.issueChallengeForActiveAccount(base)).resolves.toMatchObject({
      accountId: '00000000-0000-4000-8000-000000000051',
      kind: 'issued',
      recipient: 'synthetic-account@example.invalid',
    });
    expect(client.calls).toHaveLength(2);
    expect(client.calls.every((call) => call.text.includes('issue_auth_challenge'))).toBe(true);
    expect(client.calls.every((call) => !/\b(?:INSERT|UPDATE|DELETE)\b/i.test(call.text))).toBe(
      true,
    );
  });

  it('maps uniqueness failures to the repository conflict contract', async () => {
    const client = new QueryFixture([{ error: { code: '23505' } }]);
    const repository = new PostgresAuthRepository(client);
    await expect(
      repository.createAccount({
        displayName: 'Synthetic Duplicate',
        email: 'synthetic-duplicate@example.invalid',
        userId: '00000000-0000-4000-8000-000000000053',
      }),
    ).rejects.toBeInstanceOf(AuthRepositoryConflictError);
  });
});

describe('A2 PostgreSQL OIDC persistence', () => {
  it('loads redirect URIs and protocol policy from the registered DB client', async () => {
    const client = new QueryFixture([
      [
        {
          allowed_scope: 'openid',
          client_id: 'synthetic-client',
          grant_type: 'authorization_code',
          pkce_required: true,
          redirect_uris: ['http://127.0.0.1/callback', 'https://synthetic-client.invalid/callback'],
          token_endpoint_auth_method: 'none',
        },
      ],
    ]);
    const repository = new PostgresOidcClientRepository(client, [
      {
        clientId: 'synthetic-client',
        redirectUris: ['https://ignored-config.invalid/callback'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'none',
      },
    ]);

    await expect(repository.listRegisteredClients()).resolves.toEqual([
      {
        clientId: 'synthetic-client',
        redirectUris: ['http://127.0.0.1/callback', 'https://synthetic-client.invalid/callback'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'none',
      },
    ]);
  });

  it('preserves durable consume state and rejects a second atomic consumption', async () => {
    const consumedAt = new Date('2030-01-01T00:00:03.000Z');
    const client = new QueryFixture([
      [],
      [{ consumed_at: null, payload: { grantId: 'synthetic-grant' } }],
      [{ result: true }],
      [{ result: false }],
      [{ consumed_at: consumedAt, payload: { grantId: 'synthetic-grant' } }],
    ]);
    const adapter = createPostgresOidcStorageAdapter(client, () => Date.parse('2030-01-01Z'))(
      'AuthorizationCode',
    );

    await adapter.upsert('synthetic-artifact', { grantId: 'synthetic-grant' }, 60);
    await expect(adapter.find('synthetic-artifact')).resolves.toEqual({
      grantId: 'synthetic-grant',
    });
    await expect(adapter.consume('synthetic-artifact')).resolves.toBeUndefined();
    await expect(adapter.consume('synthetic-artifact')).rejects.toMatchObject({
      code: 'auth.unavailable',
    });
    await expect(adapter.find('synthetic-artifact')).resolves.toEqual({
      consumed: Math.floor(consumedAt.getTime() / 1000),
      grantId: 'synthetic-grant',
    });
  });
});
