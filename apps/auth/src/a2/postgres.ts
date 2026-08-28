import { readFileSync } from 'node:fs';

import { functionalGrants, parseCurrentPrincipalAuthorization } from '@kovcheg/contracts';
import type { FunctionalGrant, SessionId, UserId, Uuid } from '@kovcheg/contracts';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';
import type { PoolConfig, QueryResultRow } from 'pg';
import { Pool } from 'pg';

import {
  AuthError,
  AuthRepositoryAuthorizationError,
  AuthRepositoryConflictError,
  AuthRepositoryNotFoundError,
} from './contracts.js';
import type {
  AccountRecord,
  AccountStatus,
  AuthPasskeyCredential,
  AuthPasskeySignCountStatus,
  AuthPasskeyTransport,
  AuthSecurityResetResult,
  SessionPrincipal,
} from './contracts.js';
import type { OidcClientRepository, RegisteredOidcClient } from './oidc.js';
import type {
  AuthRepository,
  BootstrapAdministratorResult,
  ConsumeChallengeResult,
  IssueChallengeResult,
} from './ports.js';

interface AuthPostgresQueryClient {
  query<Row extends QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<{ readonly rows: Row[] }>;
}

export interface AuthPostgresClient extends AuthPostgresQueryClient {
  connect?(): Promise<AuthPostgresQueryClient & { release(): void }>;
}

export interface AuthPostgresEnvironment {
  readonly PGDATABASE?: string | undefined;
  readonly PGHOST?: string | undefined;
  readonly PGPASSWORD_FILE?: string | undefined;
  readonly PGPORT?: string | undefined;
  readonly PGUSER?: string | undefined;
}

interface AccountRow extends QueryResultRow {
  readonly account_access: string;
  readonly account_id: string;
  readonly account_status: string;
  readonly created?: boolean | undefined;
  readonly display_name: string;
  readonly domain_status: string;
  readonly email: string;
  readonly functional_grants: unknown;
}

interface ChallengeRow extends QueryResultRow {
  readonly challenge_id: string | null;
  readonly outcome: string;
  readonly recipient: string | null;
}

interface PasskeyRow extends QueryResultRow {
  readonly aaguid: string;
  readonly account_id: string;
  readonly attestation_format: string;
  readonly last_backup_eligible: boolean;
  readonly last_backup_state: boolean;
  readonly passkey_id: string;
  readonly public_key: Uint8Array;
  readonly registered_backup_eligible: boolean;
  readonly registered_backup_state: boolean;
  readonly sign_count: number | string;
  readonly transports: unknown;
}

interface PasskeyRegistrationRow extends QueryResultRow {
  readonly account_id: string;
  readonly passkey_id: string;
}

interface PasskeyLoginRow extends QueryResultRow {
  readonly account_id: string;
  readonly outcome: string;
  readonly reused: boolean;
  readonly session_id: string;
  readonly sign_count_status: string;
}

interface JsonResultRow extends QueryResultRow {
  readonly result: unknown;
}

interface SessionRow extends QueryResultRow {
  readonly outcome?: string | undefined;
  readonly principal: unknown;
}

interface BooleanRow extends QueryResultRow {
  readonly result: boolean;
}

interface CountRow extends QueryResultRow {
  readonly result: number;
}

interface OidcClientRow extends QueryResultRow {
  readonly allowed_scope: string;
  readonly client_id: string;
  readonly grant_type: string;
  readonly pkce_required: boolean;
  readonly redirect_uris: unknown;
  readonly token_endpoint_auth_method: string;
}

interface OidcArtifactRow extends QueryResultRow {
  readonly artifact_id?: string | undefined;
  readonly consumed_at: Date | string | null;
  readonly model?: string | undefined;
  readonly payload: unknown;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const genericUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const oidcModelPattern = /^[A-Za-z][A-Za-z0-9]{1,63}$/;

function unavailable(): AuthError {
  return new AuthError('auth.unavailable', 'Durable authentication storage is unavailable');
}

function mapPostgresError(error: unknown): Error {
  if (error instanceof AuthError || error instanceof AuthRepositoryConflictError) {
    return error;
  }
  const postgresError = error as { readonly code?: string };
  if (postgresError.code === '42501') {
    return new AuthRepositoryAuthorizationError();
  }
  if (postgresError.code === '23505') {
    return new AuthRepositoryConflictError();
  }
  if (postgresError.code === '40001') {
    return new AuthRepositoryConflictError();
  }
  if (postgresError.code === 'P0002') {
    return new AuthRepositoryNotFoundError();
  }
  return unavailable();
}

async function query<Row extends QueryResultRow>(
  client: AuthPostgresQueryClient,
  text: string,
  values: readonly unknown[] = [],
): Promise<Row[]> {
  try {
    return (await client.query<Row>(text, values)).rows;
  } catch (error) {
    throw mapPostgresError(error);
  }
}

function accountStatus(value: string): AccountStatus {
  if (value !== 'active' && value !== 'deactivated') {
    throw unavailable();
  }
  return value;
}

function identifier<T extends string>(value: string | null): T {
  if (value === null || !uuidPattern.test(value)) {
    throw unavailable();
  }
  return value as T;
}

function genericUuid(value: string | null): Uuid {
  if (value === null || !genericUuidPattern.test(value)) throw unavailable();
  return value as Uuid;
}

function countField(value: unknown, name: string): number {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw unavailable();
  const field = (value as Record<string, unknown>)[name];
  if (!Number.isSafeInteger(field) || (field as number) < 0) throw unavailable();
  return field as number;
}

function boundedInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  const parsed = typeof value === 'string' && /^\d+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || (parsed as number) < 0 || (parsed as number) > maximum) {
    throw unavailable();
  }
  return parsed as number;
}

function passkeyTransports(value: unknown): readonly AuthPasskeyTransport[] {
  const parsed =
    typeof value === 'string' && /^\{(?:[a-z-]+(?:,[a-z-]+)*)?\}$/u.test(value)
      ? value.slice(1, -1).split(',')
      : value;
  if (!Array.isArray(parsed)) throw unavailable();
  if (parsed.length === 1 && parsed[0] === '') return Object.freeze([]);
  if (
    parsed.some(
      (transport) =>
        transport !== 'ble' &&
        transport !== 'hybrid' &&
        transport !== 'internal' &&
        transport !== 'nfc' &&
        transport !== 'smart-card' &&
        transport !== 'usb',
    )
  ) {
    throw unavailable();
  }
  return Object.freeze([...parsed] as AuthPasskeyTransport[]);
}

function passkeySignCountStatus(value: string): AuthPasskeySignCountStatus {
  if (
    value !== 'advanced' &&
    value !== 'not_advanced' &&
    value !== 'not_supported' &&
    value !== 'regressed'
  ) {
    throw unavailable();
  }
  return value;
}

function bytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > maximum) {
    throw unavailable();
  }
  return Uint8Array.from(value);
}

function grants(value: unknown): readonly FunctionalGrant[] {
  const parsed =
    typeof value === 'string' &&
    /^\{(?:(?:warrior|platform_administrator|chronicler|editor|technical_administrator)(?:,(?:warrior|platform_administrator|chronicler|editor|technical_administrator))*)?\}$/.test(
      value,
    )
      ? value.slice(1, -1).split(',')
      : value;
  if (!Array.isArray(parsed) || parsed.some((grant) => typeof grant !== 'string')) {
    throw unavailable();
  }
  if (parsed.length === 1 && parsed[0] === '') return Object.freeze([]);
  if (parsed.some((grant) => !functionalGrants.includes(grant as FunctionalGrant))) {
    throw unavailable();
  }
  return Object.freeze(parsed as FunctionalGrant[]);
}

function mapAccount(row: AccountRow | undefined): AccountRecord | null {
  if (row === undefined) {
    return null;
  }
  if (
    row.account_access !== 'member' ||
    typeof row.email !== 'string' ||
    typeof row.display_name !== 'string' ||
    (row.domain_status !== 'incubator_participant' && row.domain_status !== 'disciple')
  ) {
    throw unavailable();
  }
  return Object.freeze({
    accountAccess: 'member',
    displayName: row.display_name,
    domainStatus: row.domain_status,
    email: row.email,
    functionalGrants: grants(row.functional_grants),
    status: accountStatus(row.account_status),
    userId: identifier<UserId>(row.account_id),
  });
}

export class PostgresAuthRepository implements AuthRepository {
  readonly productionSafe = true;

  constructor(private readonly client: AuthPostgresClient) {}

  async adminSecurityResetAuthAccess(
    input: Parameters<AuthRepository['adminSecurityResetAuthAccess']>[0],
  ): Promise<AuthSecurityResetResult> {
    const rows = await query<JsonResultRow>(
      this.client,
      'SELECT kovcheg.admin_security_reset_auth_access($1, $2, $3, $4) AS result',
      [input.actorSessionVerifier, input.accountId, new Date(input.now), input.correlationId],
    );
    const result = rows[0]?.result;
    return Object.freeze({
      invalidatedChallengeCount: countField(result, 'invalidatedChallengeCount'),
      revokedApplicationSessionCount: countField(result, 'revokedApplicationSessionCount'),
      revokedPasskeyCount: countField(result, 'revokedPasskeyCount'),
    });
  }

  async authenticateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null> {
    const rows = await query<SessionRow>(
      this.client,
      `SELECT kovcheg.read_current_principal_authorization($1, $2, true) AS principal`,
      [tokenVerifier, new Date(now)],
    );
    if (rows[0]?.principal === null) return null;
    return parseCurrentPrincipalAuthorization(rows[0]?.principal) ?? null;
  }

  async validateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null> {
    const rows = await query<SessionRow>(
      this.client,
      `SELECT kovcheg.read_current_principal_authorization($1, $2, false) AS principal`,
      [tokenVerifier, new Date(now)],
    );
    if (rows[0]?.principal === null) return null;
    return parseCurrentPrincipalAuthorization(rows[0]?.principal) ?? null;
  }

  async bootstrapAdministrator(
    input: Parameters<AuthRepository['bootstrapAdministrator']>[0],
  ): Promise<BootstrapAdministratorResult> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants, created
       FROM kovcheg.bootstrap_role_capable_administrator($1, $2, $3, $4)`,
      [input.bootstrapId, input.userId, input.email, input.displayName],
    );
    const row = rows[0];
    const account = mapAccount(row);
    if (account === null || typeof row?.created !== 'boolean') {
      throw unavailable();
    }
    return Object.freeze({ account, created: row.created });
  }

  async completePasskeyLogin(
    input: Parameters<AuthRepository['completePasskeyLogin']>[0],
  ): ReturnType<AuthRepository['completePasskeyLogin']> {
    const rows = await query<PasskeyLoginRow>(
      this.client,
      `SELECT outcome, account_id, session_id, sign_count_status, reused
       FROM kovcheg.complete_auth_passkey_login(
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
       )`,
      [
        Buffer.from(input.credentialId),
        input.expectedSignCount,
        input.observedSignCount,
        input.observedBackupEligible,
        input.observedBackupState,
        input.userVerified,
        input.assertionId,
        input.session.sessionId,
        input.session.tokenVerifier,
        input.session.idleLifetimeMs,
        new Date(input.session.absoluteExpiresAt),
        new Date(input.now),
        input.correlationId,
      ],
    );
    const row = rows[0];
    if (row === undefined) return null;
    if (row.outcome !== 'authenticated' || typeof row.reused !== 'boolean') throw unavailable();
    return Object.freeze({
      accountId: identifier<UserId>(row.account_id),
      reused: row.reused,
      sessionId: identifier<SessionId>(row.session_id),
      signCountStatus: passkeySignCountStatus(row.sign_count_status),
    });
  }

  async consumeChallengeAndCreateSession(
    input: Parameters<AuthRepository['consumeChallengeAndCreateSession']>[0],
  ): Promise<ConsumeChallengeResult> {
    const rows = await query<SessionRow>(
      this.client,
      `SELECT outcome, principal
       FROM kovcheg.consume_challenge_and_read_principal(
         $1, $2, $3, $4, $5, $6, $7, $8
       )`,
      [
        input.challengeId,
        input.candidateCodeVerifier,
        new Date(input.now),
        input.session.sessionId,
        input.session.tokenVerifier,
        new Date(input.session.issuedAt),
        input.session.idleLifetimeMs,
        new Date(input.session.absoluteExpiresAt),
      ],
    );
    const row = rows[0];
    if (row?.outcome === 'invalid') {
      return Object.freeze({ kind: 'invalid' });
    }
    if (row?.outcome !== 'authenticated') {
      throw unavailable();
    }
    const principal = parseCurrentPrincipalAuthorization(row.principal);
    if (principal === null) throw unavailable();
    return Object.freeze({ kind: 'authenticated', principal });
  }

  async createOidcSession(
    input: Parameters<AuthRepository['createOidcSession']>[0],
  ): Promise<boolean> {
    const rows = await query<SessionRow>(
      this.client,
      `SELECT outcome
       FROM kovcheg.create_oidc_application_session(
         $1, $2, $3, $4, $5, $6, $7, $8
       )`,
      [
        input.accountId,
        input.sourceTokenVerifier,
        input.session.sessionId,
        input.session.tokenVerifier,
        new Date(input.session.issuedAt),
        input.session.idleLifetimeMs,
        new Date(input.session.absoluteExpiresAt),
        input.correlationId,
      ],
    );
    const outcome = rows[0]?.outcome;
    if (outcome !== 'authenticated' && outcome !== 'invalid') throw unavailable();
    return outcome === 'authenticated';
  }

  async createAccountAsAdministrator(
    input: Parameters<AuthRepository['createAccountAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    const rows = await query<AccountRow>(
      this.client,
      `WITH session_activity AS MATERIALIZED (
         SELECT count(*) AS authenticated_session_count
         FROM kovcheg.authenticate_auth_session($1, $5)
       )
       SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM session_activity
       CROSS JOIN LATERAL kovcheg.admin_create_role_capable_account($1, $2, $3, $4, $5, $6)`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.email,
        input.displayName,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const account = mapAccount(rows[0]);
    if (account === null) {
      throw unavailable();
    }
    return account;
  }

  async findAccountById(userId: UserId): Promise<AccountRecord | null> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM kovcheg.read_role_capable_account($1)`,
      [userId],
    );
    return mapAccount(rows[0]);
  }

  async grantFunctionalGrantAsAdministrator(
    input: Parameters<AuthRepository['grantFunctionalGrantAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.authorizationMutation('kovcheg.admin_grant_functional_grant', input);
  }

  async invalidateChallenge(challengeId: Uuid, now: number): Promise<void> {
    await query(this.client, 'SELECT kovcheg.invalidate_auth_challenge($1, $2)', [
      challengeId,
      new Date(now),
    ]);
  }

  async isReady(): Promise<boolean> {
    try {
      await this.client.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async issueEmailChallenge(
    input: Parameters<AuthRepository['issueEmailChallenge']>[0],
  ): Promise<IssueChallengeResult> {
    const rows = await query<ChallengeRow>(
      this.client,
      `SELECT outcome, challenge_id, recipient
       FROM kovcheg.issue_auth_email_challenge(
         $1, $2, $3, $4, $5, $6, $7::bigint * interval '1 millisecond', $8
       )`,
      [
        input.email,
        input.challenge.challengeId,
        input.challenge.codeVerifier,
        new Date(input.challenge.issuedAt),
        new Date(input.challenge.expiresAt),
        input.challenge.maxAttempts,
        input.resendCooldownMs,
        input.correlationId,
      ],
    );
    const row = rows[0];
    if (row?.outcome === 'neutral') {
      return Object.freeze({ kind: 'neutral' });
    }
    if (row?.outcome !== 'issued' || row.recipient === null) {
      throw unavailable();
    }
    return Object.freeze({
      challengeId: identifier<Uuid>(row.challenge_id),
      kind: 'issued',
      recipient: row.recipient,
    });
  }

  async readPasskeyByCredentialId(
    credentialId: Uint8Array,
    now: number,
  ): Promise<AuthPasskeyCredential | null> {
    const rows = await query<PasskeyRow>(
      this.client,
      `SELECT passkey_id, account_id, public_key, sign_count, transports, aaguid,
              attestation_format, registered_backup_eligible, registered_backup_state,
              last_backup_eligible, last_backup_state
       FROM kovcheg.read_auth_passkey_by_credential_id($1, $2)`,
      [Buffer.from(credentialId), new Date(now)],
    );
    const row = rows[0];
    if (row === undefined) return null;
    if (
      typeof row.attestation_format !== 'string' ||
      typeof row.registered_backup_eligible !== 'boolean' ||
      typeof row.registered_backup_state !== 'boolean' ||
      typeof row.last_backup_eligible !== 'boolean' ||
      typeof row.last_backup_state !== 'boolean'
    ) {
      throw unavailable();
    }
    return Object.freeze({
      aaguid: genericUuid(row.aaguid),
      accountId: identifier<UserId>(row.account_id),
      attestationFormat: row.attestation_format,
      credentialId: Uint8Array.from(credentialId),
      lastBackupEligible: row.last_backup_eligible,
      lastBackupState: row.last_backup_state,
      passkeyId: identifier<Uuid>(row.passkey_id),
      publicKey: bytes(row.public_key, 8192),
      registeredBackupEligible: row.registered_backup_eligible,
      registeredBackupState: row.registered_backup_state,
      signCount: boundedInteger(row.sign_count, 4_294_967_295),
      transports: passkeyTransports(row.transports),
    });
  }

  async registerPasskey(
    input: Parameters<AuthRepository['registerPasskey']>[0],
  ): ReturnType<AuthRepository['registerPasskey']> {
    const rows = await query<PasskeyRegistrationRow>(
      this.client,
      `SELECT passkey_id, account_id
       FROM kovcheg.register_auth_passkey(
         $1, $2, $3, $4, $5, $6::kovcheg.auth_passkey_transport[], $7, $8,
         $9, $10, $11, $12, $13
       )`,
      [
        input.actorSessionVerifier,
        input.passkeyId,
        Buffer.from(input.credentialId),
        Buffer.from(input.publicKey),
        input.signCount,
        [...input.transports],
        input.aaguid,
        input.attestationFormat,
        input.backupEligible,
        input.backupState,
        input.userVerified,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const row = rows[0];
    if (row === undefined) throw unavailable();
    return Object.freeze({
      accountId: identifier<UserId>(row.account_id),
      passkeyId: identifier<Uuid>(row.passkey_id),
    });
  }

  async revokeAllSessionsAsAdministrator(
    input: Parameters<AuthRepository['revokeAllSessionsAsAdministrator']>[0],
  ): Promise<number> {
    const rows = await query<CountRow>(
      this.client,
      `WITH session_activity AS MATERIALIZED (
         SELECT count(*) AS authenticated_session_count
         FROM kovcheg.authenticate_auth_session($1, $3)
       )
       SELECT kovcheg.admin_revoke_all_auth_sessions($1, $2, $3, $4) AS result
       FROM session_activity`,
      [input.actorSessionVerifier, input.userId, new Date(input.now), input.correlationId],
    );
    if (!Number.isSafeInteger(rows[0]?.result) || (rows[0]?.result ?? -1) < 0) {
      throw unavailable();
    }
    return rows[0]?.result ?? 0;
  }

  async revokeFunctionalGrantAsAdministrator(
    input: Parameters<AuthRepository['revokeFunctionalGrantAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.authorizationMutation('kovcheg.admin_revoke_functional_grant', input);
  }

  async revokeSessionAsAdministrator(
    input: Parameters<AuthRepository['revokeSessionAsAdministrator']>[0],
  ): Promise<boolean> {
    const rows = await query<BooleanRow>(
      this.client,
      `WITH session_activity AS MATERIALIZED (
         SELECT count(*) AS authenticated_session_count
         FROM kovcheg.authenticate_auth_session($1, $4)
       )
       SELECT kovcheg.admin_revoke_auth_session($1, $2, $3, $4, $5) AS result
       FROM session_activity`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.sessionId,
        new Date(input.now),
        input.correlationId,
      ],
    );
    if (typeof rows[0]?.result !== 'boolean') {
      throw unavailable();
    }
    return rows[0].result;
  }

  async revokeSessionByVerifier(tokenVerifier: string, now: number): Promise<boolean> {
    return this.booleanFunction('kovcheg.revoke_auth_session_by_verifier', tokenVerifier, now);
  }

  async setAccountStatusAsAdministrator(
    input: Parameters<AuthRepository['setAccountStatusAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM kovcheg.admin_set_role_capable_account_status($1, $2, $3, $4, $5)`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.status,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const account = mapAccount(rows[0]);
    if (account === null) {
      throw unavailable();
    }
    return account;
  }

  async setDomainStatusAsAdministrator(
    input: Parameters<AuthRepository['setDomainStatusAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM kovcheg.admin_set_domain_status($1, $2, $3, $4, $5, $6, $7)`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.domainStatus,
        input.reason,
        input.version,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const account = mapAccount(rows[0]);
    if (account === null) throw unavailable();
    return account;
  }

  async updateAccountAsAdministrator(
    input: Parameters<AuthRepository['updateAccountAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM kovcheg.admin_update_role_capable_account($1, $2, $3, $4, $5, $6)`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.email,
        input.displayName,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const account = mapAccount(rows[0]);
    if (account === null) {
      throw unavailable();
    }
    return account;
  }

  private async authorizationMutation(
    name: 'kovcheg.admin_grant_functional_grant' | 'kovcheg.admin_revoke_functional_grant',
    input:
      | Parameters<AuthRepository['grantFunctionalGrantAsAdministrator']>[0]
      | Parameters<AuthRepository['revokeFunctionalGrantAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    const rows = await query<AccountRow>(
      this.client,
      `SELECT account_id, email, display_name, account_access, account_status,
              domain_status, functional_grants
       FROM ${name}($1, $2, $3, $4, $5, $6, $7)`,
      [
        input.actorSessionVerifier,
        input.userId,
        input.grant,
        input.reason,
        input.version,
        new Date(input.now),
        input.correlationId,
      ],
    );
    const account = mapAccount(rows[0]);
    if (account === null) throw unavailable();
    return account;
  }

  private async booleanFunction(
    name: string,
    identifierValue: string,
    now: number,
  ): Promise<boolean> {
    const rows = await query<BooleanRow>(this.client, `SELECT ${name}($1, $2) AS result`, [
      identifierValue,
      new Date(now),
    ]);
    if (typeof rows[0]?.result !== 'boolean') {
      throw unavailable();
    }
    return rows[0].result;
  }
}

export class PostgresOidcClientRepository implements OidcClientRepository {
  readonly productionSafe = true;

  constructor(
    private readonly client: AuthPostgresClient,
    private readonly configuredClients: readonly RegisteredOidcClient[],
  ) {}

  async listRegisteredClients(): Promise<readonly RegisteredOidcClient[]> {
    const clients = await Promise.all(
      this.configuredClients.map(async (configured): Promise<RegisteredOidcClient> => {
        const rows = await query<OidcClientRow>(
          this.client,
          `SELECT client_id, redirect_uris, allowed_scope, grant_type, pkce_required,
                  token_endpoint_auth_method
           FROM kovcheg.find_registered_oidc_client($1)`,
          [configured.clientId],
        );
        const row = rows[0];
        if (
          row === undefined ||
          row.client_id !== configured.clientId ||
          row.allowed_scope !== 'openid' ||
          row.grant_type !== 'authorization_code' ||
          row.pkce_required !== true ||
          row.token_endpoint_auth_method !== configured.tokenEndpointAuthMethod ||
          !Array.isArray(row.redirect_uris) ||
          row.redirect_uris.length < 1 ||
          row.redirect_uris.some((value) => typeof value !== 'string')
        ) {
          throw unavailable();
        }
        const base = {
          clientId: row.client_id,
          redirectUris: Object.freeze([...row.redirect_uris] as string[]),
          scopes: Object.freeze(['openid']),
        };
        return configured.tokenEndpointAuthMethod === 'client_secret_basic'
          ? Object.freeze({
              ...base,
              clientSecret: configured.clientSecret,
              tokenEndpointAuthMethod: 'client_secret_basic' as const,
            })
          : Object.freeze({ ...base, tokenEndpointAuthMethod: 'none' as const });
      }),
    );
    return Object.freeze(clients);
  }
}

function payloadObject(value: unknown): AdapterPayload {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw unavailable();
  }
  return value as AdapterPayload;
}

function consumedEpoch(value: Date | string | null): number | undefined {
  if (value === null) {
    return undefined;
  }
  const milliseconds = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw unavailable();
  }
  return Math.floor(milliseconds / 1000);
}

function textMetadata(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

class PostgresOidcProviderAdapter implements Adapter {
  constructor(
    private readonly model: string,
    private readonly client: AuthPostgresClient,
    private readonly now: () => number,
  ) {
    if (!oidcModelPattern.test(model)) {
      throw unavailable();
    }
  }

  async consume(id: string): Promise<void> {
    const rows = await query<BooleanRow>(
      this.client,
      'SELECT kovcheg.consume_oidc_provider_artifact($1, $2, $3) AS result',
      [this.model, id, new Date(this.now())],
    );
    if (rows[0]?.result !== true) {
      throw unavailable();
    }
  }

  async destroy(id: string): Promise<void> {
    await query<BooleanRow>(
      this.client,
      'SELECT kovcheg.destroy_oidc_provider_artifact($1, $2) AS result',
      [this.model, id],
    );
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const rows = await query<OidcArtifactRow>(
      this.client,
      `SELECT payload, consumed_at
       FROM kovcheg.find_oidc_provider_artifact($1, $2, $3)`,
      [this.model, id, new Date(this.now())],
    );
    return this.mapArtifact(rows[0]);
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.findBySecondaryKey('uid', uid);
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.findBySecondaryKey('user_code', userCode);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const rows = await query<CountRow>(
      this.client,
      'SELECT kovcheg.revoke_oidc_provider_artifacts_by_grant_id($1) AS result',
      [grantId],
    );
    if (typeof rows[0]?.result !== 'number') {
      throw unavailable();
    }
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    if (!Number.isSafeInteger(expiresIn) || (expiresIn ?? 0) <= 0) {
      throw unavailable();
    }
    let durablePayload: AdapterPayload;
    try {
      durablePayload = payloadObject(JSON.parse(JSON.stringify(payload)) as unknown);
    } catch {
      throw unavailable();
    }
    await query(
      this.client,
      `SELECT kovcheg.upsert_oidc_provider_artifact(
         $1, $2, $3::jsonb, $4, $5, $6, $7
       )`,
      [
        this.model,
        id,
        JSON.stringify(durablePayload),
        new Date(this.now() + (expiresIn ?? 0) * 1000),
        textMetadata(payload.grantId),
        textMetadata(payload.userCode),
        textMetadata(payload.uid),
      ],
    );
  }

  private async findBySecondaryKey(
    kind: 'uid' | 'user_code',
    value: string,
  ): Promise<AdapterPayload | undefined> {
    const functionName =
      kind === 'uid'
        ? 'kovcheg.find_oidc_provider_artifact_by_uid'
        : 'kovcheg.find_oidc_provider_artifact_by_user_code';
    const rows = await query<OidcArtifactRow>(
      this.client,
      `SELECT model, artifact_id, payload, consumed_at FROM ${functionName}($1, $2)`,
      [value, new Date(this.now())],
    );
    const row = rows[0];
    return row?.model === this.model ? this.mapArtifact(row) : undefined;
  }

  private mapArtifact(row: OidcArtifactRow | undefined): AdapterPayload | undefined {
    if (row === undefined) {
      return undefined;
    }
    const payload = payloadObject(row.payload);
    const consumed = consumedEpoch(row.consumed_at);
    return Object.freeze(consumed === undefined ? { ...payload } : { ...payload, consumed });
  }
}

export function createPostgresOidcStorageAdapter(
  client: AuthPostgresClient,
  now: () => number = Date.now,
): AdapterFactory {
  return (model) => new PostgresOidcProviderAdapter(model, client, now);
}

function required(
  environment: AuthPostgresEnvironment,
  key: keyof AuthPostgresEnvironment,
): string {
  const value = environment[key]?.trim();
  if (value === undefined || value.length === 0) {
    throw unavailable();
  }
  return value;
}

export function createAuthPostgresPool(environment: AuthPostgresEnvironment = process.env): Pool {
  const user = required(environment, 'PGUSER');
  if (user !== 'kovcheg_auth_app') {
    throw unavailable();
  }
  const portValue = environment.PGPORT?.trim() || '5432';
  if (!/^\d+$/.test(portValue)) {
    throw unavailable();
  }
  const port = Number.parseInt(portValue, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw unavailable();
  }
  let password: string;
  try {
    password = readFileSync(required(environment, 'PGPASSWORD_FILE'), 'utf8').replace(
      /[\r\n]+$/u,
      '',
    );
  } catch {
    throw unavailable();
  }
  if (password.length === 0) {
    throw unavailable();
  }
  const config: PoolConfig = {
    application_name: 'kovcheg-auth',
    database: required(environment, 'PGDATABASE'),
    host: required(environment, 'PGHOST'),
    max: 10,
    password,
    port,
    user,
  };
  return new Pool(config);
}
