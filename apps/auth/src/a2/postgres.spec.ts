import type { CorrelationId } from '@kovcheg/contracts';
import type { QueryResultRow } from 'pg';
import { describe, expect, it } from 'vitest';

import {
  AuthRepositoryAuthorizationError,
  AuthRepositoryConflictError,
  AuthRepositoryNotFoundError,
} from './contracts.js';
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
  const principal = Object.freeze({
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
    domainStatus: 'incubator_participant',
    functionalGrants: ['platform_administrator'],
    isServerOwner: true,
    materialCapabilities: [],
    sensitiveCapabilities: Object.freeze({ canPerformSensitiveActions: false }),
    sessionId: '00000000-0000-4000-8000-000000000054',
    sessionStatus: 'active',
    userId: '00000000-0000-4000-8000-000000000050',
  });

  it('maps the versioned PostgreSQL authorization principal', async () => {
    const client = new QueryFixture([[{ principal }]]);
    const repository = new PostgresAuthRepository(client);
    await expect(repository.authenticateSession('v'.repeat(43), Date.now())).resolves.toEqual(
      principal,
    );
  });

  it('uses the non-touch database function for background session validation', async () => {
    const client = new QueryFixture([[{ principal }]]);
    const repository = new PostgresAuthRepository(client);

    await expect(repository.validateSession('v'.repeat(43), Date.now())).resolves.toMatchObject({
      sessionId: '00000000-0000-4000-8000-000000000054',
      userId: '00000000-0000-4000-8000-000000000050',
    });
    expect(client.calls[0]?.text).toContain('read_current_principal_authorization');
    expect(client.calls[0]?.values[2]).toBeUndefined();
    expect(client.calls[0]?.values).toHaveLength(2);
  });

  it('maps durable neutral and active-account challenge outcomes without direct table access', async () => {
    const client = new QueryFixture([
      [{ challenge_id: null, outcome: 'neutral', recipient: null }],
      [
        {
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
      correlationId: 'postgres-email-challenge' as CorrelationId,
      email: 'synthetic-account@example.invalid',
      resendCooldownMs: 60_000,
    };

    await expect(repository.issueEmailChallenge(base)).resolves.toEqual({
      kind: 'neutral',
    });
    await expect(repository.issueEmailChallenge(base)).resolves.toMatchObject({
      kind: 'issued',
      recipient: 'synthetic-account@example.invalid',
    });
    expect(client.calls).toHaveLength(2);
    expect(client.calls.every((call) => call.text.includes('issue_auth_email_challenge'))).toBe(
      true,
    );
    expect(client.calls.every((call) => call.values.at(-1) === base.correlationId)).toBe(true);
    expect(client.calls.every((call) => !/\b(?:INSERT|UPDATE|DELETE)\b/i.test(call.text))).toBe(
      true,
    );
  });

  it('consumes an email challenge into an application session through the protected function', async () => {
    const client = new QueryFixture([[{ outcome: 'authenticated', principal }]]);
    const repository = new PostgresAuthRepository(client);
    await expect(
      repository.consumeChallengeAndCreateSession({
        candidateCodeVerifier: 'c'.repeat(43),
        challengeId: '00000000-0000-4000-8000-000000000052',
        now: Date.parse('2030-01-01T00:00:00Z'),
        session: {
          absoluteExpiresAt: Date.parse('2030-01-31T00:00:00Z'),
          idleLifetimeMs: 7 * 24 * 60 * 60_000,
          issuedAt: Date.parse('2030-01-01T00:00:00Z'),
          sessionId: '00000000-0000-4000-8000-000000000054',
          tokenVerifier: 's'.repeat(43),
        },
      }),
    ).resolves.toMatchObject({ kind: 'authenticated' });
    expect(client.calls[0]?.text).toContain('consume_challenge_and_read_principal');
    expect(client.calls[0]?.text).not.toMatch(/auth_personal_gate/iu);
    expect(client.calls[0]?.text).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/iu);
  });

  it('keeps the security-reset response on the active auth surface only', async () => {
    const client = new QueryFixture([
      [
        {
          result: {
            invalidatedChallengeCount: 1,
            revokedApplicationSessionCount: 2,
            revokedFamilyCount: 1,
            revokedGateSessionCount: 3,
            revokedPasskeyCount: 4,
          },
        },
      ],
    ]);
    const repository = new PostgresAuthRepository(client);
    const common = {
      accountId: '00000000-0000-4000-8000-000000000050' as const,
      actorSessionVerifier: 'a'.repeat(43),
      correlationId: 'postgres-security-reset' as CorrelationId,
      now: Date.parse('2030-01-01T00:00:00Z'),
    };
    await expect(repository.adminSecurityResetAuthAccess(common)).resolves.toEqual({
      invalidatedChallengeCount: 1,
      revokedApplicationSessionCount: 2,
      revokedPasskeyCount: 4,
    });
    expect(client.calls[0]?.text).toContain('admin_security_reset_auth_access');
    expect(client.calls[0]?.text).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/iu);
  });

  it('consumes only the three protected passkey functions without direct DML', async () => {
    const credentialId = Uint8Array.from(Buffer.from('synthetic-postgres-passkey'));
    const accountId = '00000000-0000-4000-8000-000000000050' as const;
    const passkeyId = '00000000-0000-4000-8000-000000000057' as const;
    const sessionId = '00000000-0000-4000-8000-000000000058' as const;
    const client = new QueryFixture([
      [
        {
          aaguid: '00000000-0000-0000-0000-000000000000',
          account_id: accountId,
          attestation_format: 'none',
          last_backup_eligible: true,
          last_backup_state: true,
          passkey_id: passkeyId,
          public_key: Buffer.from([1, 2, 3, 4]),
          registered_backup_eligible: true,
          registered_backup_state: true,
          sign_count: '10',
          transports: ['hybrid'],
        },
      ],
      [{ account_id: accountId, passkey_id: passkeyId }],
      [
        {
          account_id: accountId,
          outcome: 'authenticated',
          reused: false,
          session_id: sessionId,
          sign_count_status: 'regressed',
        },
      ],
    ]);
    const repository = new PostgresAuthRepository(client);
    await expect(repository.readPasskeyByCredentialId(credentialId, 10_000)).resolves.toMatchObject(
      {
        accountId,
        passkeyId,
        signCount: 10,
        transports: ['hybrid'],
      },
    );
    await expect(
      repository.registerPasskey({
        actorSessionVerifier: 'a'.repeat(43),
        aaguid: '00000000-0000-0000-0000-000000000000',
        attestationFormat: 'none',
        backupEligible: true,
        backupState: true,
        correlationId: 'postgres-passkey-registration' as CorrelationId,
        credentialId,
        now: 10_000,
        passkeyId,
        publicKey: Uint8Array.from([1, 2, 3, 4]),
        signCount: 10,
        transports: ['hybrid'],
        userVerified: true,
      }),
    ).resolves.toEqual({ accountId, passkeyId });
    await expect(
      repository.completePasskeyLogin({
        assertionId: '00000000-0000-4000-8000-000000000059',
        correlationId: 'postgres-passkey-login' as CorrelationId,
        credentialId,
        expectedSignCount: 10,
        now: 20_000,
        observedBackupEligible: true,
        observedBackupState: true,
        observedSignCount: 5,
        session: {
          absoluteExpiresAt: 40_000,
          idleLifetimeMs: 10_000,
          issuedAt: 20_000,
          sessionId,
          tokenVerifier: 's'.repeat(43),
        },
        userVerified: true,
      }),
    ).resolves.toEqual({
      accountId,
      reused: false,
      sessionId,
      signCountStatus: 'regressed',
    });
    expect(client.calls.map((call) => call.text)).toEqual([
      expect.stringContaining('read_auth_passkey_by_credential_id'),
      expect.stringContaining('register_auth_passkey'),
      expect.stringContaining('complete_auth_passkey_login'),
    ]);
    expect(client.calls.every((call) => !/\b(?:INSERT|UPDATE|DELETE)\b/iu.test(call.text))).toBe(
      true,
    );
    expect(client.calls[1]?.values.at(-1)).toBe('postgres-passkey-registration');
    expect(client.calls[2]?.values.at(-1)).toBe('postgres-passkey-login');
  });

  it('maps uniqueness failures to the repository conflict contract', async () => {
    const client = new QueryFixture([{ error: { code: '23505' } }]);
    const repository = new PostgresAuthRepository(client);
    await expect(
      repository.createAccountAsAdministrator({
        actorSessionVerifier: 'v'.repeat(43),
        correlationId: 'postgres-admin-conflict' as CorrelationId,
        displayName: 'Synthetic Duplicate',
        email: 'synthetic-duplicate@example.invalid',
        now: Date.now(),
        userId: '00000000-0000-4000-8000-000000000053',
      }),
    ).rejects.toBeInstanceOf(AuthRepositoryConflictError);
  });

  it('uses only actor-verified protected wrappers for every administrative mutation', async () => {
    const account = {
      account_access: 'member',
      account_id: '00000000-0000-4000-8000-000000000053',
      account_status: 'active',
      display_name: 'Synthetic Account',
      domain_status: 'incubator_participant',
      email: 'synthetic-account@example.invalid',
      functional_grants: '{}',
    };
    const client = new QueryFixture([
      [account],
      [account],
      [account],
      [{ result: true }],
      [{ result: 3 }],
    ]);
    const repository = new PostgresAuthRepository(client);
    const administrative = {
      actorSessionVerifier: 'a'.repeat(43),
      correlationId: 'postgres-admin-operation' as CorrelationId,
      now: Date.parse('2030-01-01T00:00:00Z'),
      userId: '00000000-0000-4000-8000-000000000053' as const,
    };

    await repository.createAccountAsAdministrator({
      ...administrative,
      displayName: account.display_name,
      email: account.email,
    });
    await repository.updateAccountAsAdministrator({
      ...administrative,
      displayName: account.display_name,
      email: account.email,
    });
    await repository.setAccountStatusAsAdministrator({
      ...administrative,
      status: 'active',
    });
    await expect(
      repository.revokeSessionAsAdministrator({
        ...administrative,
        sessionId: '00000000-0000-4000-8000-000000000054',
      }),
    ).resolves.toBe(true);
    await expect(repository.revokeAllSessionsAsAdministrator(administrative)).resolves.toBe(3);

    expect(client.calls.map((call) => call.text)).toEqual(
      expect.arrayContaining([
        expect.stringContaining('kovcheg.admin_create_role_capable_account'),
        expect.stringContaining('kovcheg.admin_update_role_capable_account'),
        expect.stringContaining('kovcheg.admin_set_role_capable_account_status'),
        expect.stringContaining('kovcheg.admin_revoke_auth_session'),
        expect.stringContaining('kovcheg.admin_revoke_all_auth_sessions'),
      ]),
    );
    expect(
      client.calls.every((call) => call.values[0] === administrative.actorSessionVerifier),
    ).toBe(true);
    expect(
      client.calls.every(
        (call) =>
          !/\b(?:INSERT|UPDATE|DELETE)\b/i.test(call.text) &&
          !/FROM kovcheg\.create_auth_account\(/.test(call.text) &&
          !/FROM kovcheg\.set_auth_account_status_and_revoke\(/.test(call.text) &&
          !/kovcheg\.revoke_auth_session_by_id\(/.test(call.text),
      ),
    ).toBe(true);
  });

  it('maps protected-wrapper authorization and missing-target failures without details', async () => {
    const client = new QueryFixture([
      { error: { code: '42501', detail: 'must not escape' } },
      { error: { code: 'P0002', detail: 'must not escape' } },
    ]);
    const repository = new PostgresAuthRepository(client);
    const administrative = {
      actorSessionVerifier: 'a'.repeat(43),
      correlationId: 'postgres-admin-failure' as CorrelationId,
      displayName: 'Synthetic Account',
      email: 'synthetic-account@example.invalid',
      now: Date.parse('2030-01-01T00:00:00Z'),
      userId: '00000000-0000-4000-8000-000000000053' as const,
    };

    await expect(repository.createAccountAsAdministrator(administrative)).rejects.toEqual(
      new AuthRepositoryAuthorizationError(),
    );
    await expect(repository.updateAccountAsAdministrator(administrative)).rejects.toEqual(
      new AuthRepositoryNotFoundError(),
    );
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
