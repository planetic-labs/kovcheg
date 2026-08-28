import { timingSafeEqual } from 'node:crypto';

import { principalAuthorizationContractVersion } from '@kovcheg/contracts';
import type { DomainStatus, FunctionalGrant, UserId, Uuid } from '@kovcheg/contracts';

import {
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
  BootstrapAdministratorInput,
  ChallengeRecordInput,
  EmailChallengeMessage,
  AuthSecurityResetResult,
  RateLimitRule,
  SessionPrincipal,
  SessionRecordInput,
} from './contracts.js';
import type {
  AuthRepository,
  BootstrapAdministratorResult,
  Clock,
  ConsumeChallengeResult,
  EmailChallengeDelivery,
  IssueChallengeResult,
  RateLimitDecision,
  RateLimiter,
} from './ports.js';

interface StoredAccount {
  displayName: string;
  domainStatus: DomainStatus;
  email: string;
  functionalGrants: FunctionalGrant[];
  isServerOwner: boolean;
  status: AccountStatus;
  userId: UserId;
}

interface StoredChallenge extends ChallengeRecordInput {
  accountId: UserId;
  attempts: number;
  invalidatedAt: number | null;
  usedAt: number | null;
}

interface StoredSession extends SessionRecordInput {
  accountId: UserId;
  idleExpiresAt: number;
  lastSeenAt: number;
  revokedAt: number | null;
  sourceOidcTokenVerifier?: string | undefined;
}

interface StoredPasskey {
  aaguid: Uuid;
  accountId: UserId;
  attestationFormat: string;
  credentialId: Uint8Array;
  createdAt: number;
  lastBackupEligible: boolean;
  lastBackupState: boolean;
  lastUsedAt: number | null;
  passkeyId: Uuid;
  publicKey: Uint8Array;
  registeredBackupEligible: boolean;
  registeredBackupState: boolean;
  revokedAt: number | null;
  signCount: number;
  transports: readonly AuthPasskeyTransport[];
}

function cloneAccount(account: StoredAccount): AccountRecord {
  return Object.freeze({
    accountAccess: 'member',
    displayName: account.displayName,
    domainStatus: account.domainStatus,
    email: account.email,
    functionalGrants: Object.freeze([...account.functionalGrants]),
    status: account.status,
    userId: account.userId,
  });
}

function sessionPrincipal(account: StoredAccount, session: StoredSession): SessionPrincipal {
  const isAdministrator = account.functionalGrants.includes('platform_administrator');
  const isTechnicalAdministrator = account.functionalGrants.includes('technical_administrator');
  return Object.freeze({
    accountAccess: 'member',
    accountStatus: 'active',
    administrativeCapabilities: Object.freeze({
      canManageAccounts: isAdministrator,
      canManageDomainStatus: isAdministrator,
      canManageFunctionalGrants: isAdministrator,
      canManagePlatformAdministrators: account.isServerOwner,
    }),
    contractVersion: principalAuthorizationContractVersion,
    diagnosticCapabilities: Object.freeze({
      canReadBuildAndMigrationVersions: isTechnicalAdministrator,
      canReadHealthAndReadiness: isTechnicalAdministrator,
      canReadQueueAndTechnicalState: isTechnicalAdministrator,
      canReadSanitizedDiagnostics: isTechnicalAdministrator,
    }),
    domainStatus: account.domainStatus,
    functionalGrants: Object.freeze([...account.functionalGrants]),
    isServerOwner: account.isServerOwner,
    materialCapabilities: Object.freeze([]),
    sensitiveCapabilities: Object.freeze({ canPerformSensitiveActions: false }),
    sessionId: session.sessionId,
    sessionStatus: 'active',
    userId: account.userId,
  });
}

function safeVerifierEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

class ExclusiveQueue {
  private tail: Promise<void> = Promise.resolve();

  run<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = this.tail.then(operation, operation);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

export class LocalAuthRepository implements AuthRepository {
  private readonly accountsByEmail = new Map<string, StoredAccount>();
  private readonly accountsById = new Map<UserId, StoredAccount>();
  private readonly bootstrapAccounts = new Map<string, UserId>();
  private readonly challenges = new Map<Uuid, StoredChallenge>();
  private readonly latestChallengeAt = new Map<UserId, number>();
  private readonly passkeysByCredentialId = new Map<string, StoredPasskey>();
  private readonly passkeysById = new Map<Uuid, StoredPasskey>();
  private readonly queue = new ExclusiveQueue();
  private readonly sessionsByVerifier = new Map<string, StoredSession>();

  constructor(environment: Readonly<{ NODE_ENV?: string | undefined }> = process.env) {
    if (environment.NODE_ENV === 'production') {
      throw new Error('Local auth repository is unavailable in production');
    }
  }

  adminSecurityResetAuthAccess(
    input: Parameters<AuthRepository['adminSecurityResetAuthAccess']>[0],
  ): Promise<AuthSecurityResetResult> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      this.requireAccount(input.accountId);
      let invalidatedChallengeCount = 0;
      for (const challenge of this.challenges.values()) {
        if (
          challenge.accountId === input.accountId &&
          challenge.invalidatedAt === null &&
          challenge.usedAt === null
        ) {
          challenge.invalidatedAt = input.now;
          invalidatedChallengeCount += 1;
        }
      }
      let revokedApplicationSessionCount = 0;
      for (const session of this.sessionsByVerifier.values()) {
        if (session.accountId === input.accountId && session.revokedAt === null) {
          session.revokedAt = input.now;
          revokedApplicationSessionCount += 1;
        }
      }
      let revokedPasskeyCount = 0;
      for (const passkey of this.passkeysById.values()) {
        if (passkey.accountId === input.accountId && passkey.revokedAt === null) {
          passkey.revokedAt = input.now;
          revokedPasskeyCount += 1;
        }
      }
      return {
        invalidatedChallengeCount,
        revokedApplicationSessionCount,
        revokedPasskeyCount,
      };
    });
  }

  authenticateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null> {
    return this.queue.run(() => {
      const session = this.sessionsByVerifier.get(tokenVerifier);
      if (session === undefined || session.revokedAt !== null) {
        return null;
      }
      const account = this.accountsById.get(session.accountId);
      if (
        account === undefined ||
        account.status !== 'active' ||
        now >= session.absoluteExpiresAt ||
        now >= session.idleExpiresAt
      ) {
        session.revokedAt = now;
        return null;
      }

      session.lastSeenAt = now;
      session.idleExpiresAt = Math.min(session.absoluteExpiresAt, now + session.idleLifetimeMs);
      return sessionPrincipal(account, session);
    });
  }

  validateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null> {
    return this.queue.run(() => {
      const session = this.sessionsByVerifier.get(tokenVerifier);
      if (session === undefined || session.revokedAt !== null) return null;
      const account = this.accountsById.get(session.accountId);
      if (
        account === undefined ||
        account.status !== 'active' ||
        now < session.issuedAt ||
        now >= session.absoluteExpiresAt ||
        now >= session.idleExpiresAt
      ) {
        return null;
      }
      return sessionPrincipal(account, session);
    });
  }

  bootstrapAdministrator(
    input: BootstrapAdministratorInput,
  ): Promise<BootstrapAdministratorResult> {
    return this.queue.run(() => {
      const bootstrappedUserId = this.bootstrapAccounts.get(input.bootstrapId);
      if (bootstrappedUserId !== undefined) {
        const account = this.accountsById.get(bootstrappedUserId);
        if (
          account === undefined ||
          account.userId !== input.userId ||
          account.email !== input.email
        ) {
          throw new AuthRepositoryConflictError();
        }
        return { account: cloneAccount(account), created: false };
      }
      if (this.accountsById.has(input.userId) || this.accountsByEmail.has(input.email)) {
        throw new AuthRepositoryConflictError();
      }
      if (this.accountsById.size > 0 && this.bootstrapAccounts.size > 0) {
        throw new AuthRepositoryConflictError();
      }

      const account: StoredAccount = {
        displayName: input.displayName,
        domainStatus: 'incubator_participant',
        email: input.email,
        functionalGrants: ['platform_administrator'],
        isServerOwner: true,
        status: 'active',
        userId: input.userId,
      };
      this.accountsById.set(account.userId, account);
      this.accountsByEmail.set(account.email, account);
      this.bootstrapAccounts.set(input.bootstrapId, account.userId);
      return { account: cloneAccount(account), created: true };
    });
  }

  completePasskeyLogin(
    input: Parameters<AuthRepository['completePasskeyLogin']>[0],
  ): ReturnType<AuthRepository['completePasskeyLogin']> {
    return this.queue.run(() => {
      const passkey = this.passkeysByCredentialId.get(
        Buffer.from(input.credentialId).toString('base64url'),
      );
      const account = passkey === undefined ? undefined : this.accountsById.get(passkey.accountId);
      if (
        passkey === undefined ||
        passkey.revokedAt !== null ||
        account?.status !== 'active' ||
        !input.userVerified
      ) {
        return null;
      }
      if (passkey.signCount !== input.expectedSignCount) {
        throw new AuthRepositoryConflictError();
      }
      if (
        this.sessionsByVerifier.has(input.session.tokenVerifier) ||
        [...this.sessionsByVerifier.values()].some(
          (session) => session.sessionId === input.session.sessionId,
        )
      ) {
        throw new AuthRepositoryConflictError();
      }
      const signCountStatus: AuthPasskeySignCountStatus =
        passkey.signCount === 0 && input.observedSignCount === 0
          ? 'not_supported'
          : input.observedSignCount > passkey.signCount
            ? 'advanced'
            : input.observedSignCount === passkey.signCount
              ? 'not_advanced'
              : 'regressed';
      passkey.signCount = Math.max(passkey.signCount, input.observedSignCount);
      passkey.lastBackupEligible = input.observedBackupEligible;
      passkey.lastBackupState = input.observedBackupState;
      passkey.lastUsedAt = input.now;
      const session: StoredSession = {
        ...input.session,
        accountId: passkey.accountId,
        idleExpiresAt: Math.min(
          input.session.absoluteExpiresAt,
          input.now + input.session.idleLifetimeMs,
        ),
        lastSeenAt: input.now,
        revokedAt: null,
      };
      this.sessionsByVerifier.set(session.tokenVerifier, session);
      return {
        accountId: passkey.accountId,
        reused: false,
        sessionId: session.sessionId,
        signCountStatus,
      };
    });
  }

  consumeChallengeAndCreateSession(input: {
    readonly candidateCodeVerifier: string;
    readonly challengeId: Uuid;
    readonly now: number;
    readonly session: SessionRecordInput;
  }): Promise<ConsumeChallengeResult> {
    return this.queue.run(() => {
      const challenge = this.challenges.get(input.challengeId);
      if (
        challenge === undefined ||
        challenge.invalidatedAt !== null ||
        challenge.usedAt !== null ||
        input.now >= challenge.expiresAt ||
        challenge.attempts >= challenge.maxAttempts
      ) {
        return { kind: 'invalid' };
      }

      if (!safeVerifierEqual(challenge.codeVerifier, input.candidateCodeVerifier)) {
        challenge.attempts += 1;
        return { kind: 'invalid' };
      }

      const account = this.accountsById.get(challenge.accountId);
      if (account === undefined || account.status !== 'active') {
        challenge.invalidatedAt = input.now;
        return { kind: 'invalid' };
      }
      if (this.sessionsByVerifier.has(input.session.tokenVerifier)) {
        throw new AuthRepositoryConflictError();
      }

      challenge.usedAt = input.now;
      const session: StoredSession = {
        ...input.session,
        accountId: account.userId,
        idleExpiresAt: Math.min(
          input.session.absoluteExpiresAt,
          input.session.issuedAt + input.session.idleLifetimeMs,
        ),
        lastSeenAt: input.session.issuedAt,
        revokedAt: null,
      };
      this.sessionsByVerifier.set(session.tokenVerifier, session);
      return {
        kind: 'authenticated',
        principal: sessionPrincipal(account, session),
      };
    });
  }

  createOidcSession(input: Parameters<AuthRepository['createOidcSession']>[0]): Promise<boolean> {
    return this.queue.run(() => {
      const account = this.accountsById.get(input.accountId);
      if (
        account === undefined ||
        account.status !== 'active' ||
        [...this.sessionsByVerifier.values()].some(
          (session) => session.sourceOidcTokenVerifier === input.sourceTokenVerifier,
        )
      ) {
        return false;
      }
      if (
        this.sessionsByVerifier.has(input.session.tokenVerifier) ||
        [...this.sessionsByVerifier.values()].some(
          (session) => session.sessionId === input.session.sessionId,
        )
      ) {
        throw new AuthRepositoryConflictError();
      }
      const session: StoredSession = {
        ...input.session,
        accountId: account.userId,
        idleExpiresAt: Math.min(
          input.session.absoluteExpiresAt,
          input.session.issuedAt + input.session.idleLifetimeMs,
        ),
        lastSeenAt: input.session.issuedAt,
        revokedAt: null,
        sourceOidcTokenVerifier: input.sourceTokenVerifier,
      };
      this.sessionsByVerifier.set(session.tokenVerifier, session);
      return true;
    });
  }

  createAccountAsAdministrator(
    input: Parameters<AuthRepository['createAccountAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      if (this.accountsById.has(input.userId) || this.accountsByEmail.has(input.email)) {
        throw new AuthRepositoryConflictError();
      }
      const account: StoredAccount = {
        displayName: input.displayName,
        domainStatus: 'incubator_participant',
        email: input.email,
        functionalGrants: [],
        isServerOwner: false,
        status: 'active',
        userId: input.userId,
      };
      this.accountsById.set(account.userId, account);
      this.accountsByEmail.set(account.email, account);
      return cloneAccount(account);
    });
  }

  findAccountById(userId: UserId): Promise<AccountRecord | null> {
    return this.queue.run(() => {
      const account = this.accountsById.get(userId);
      return account === undefined ? null : cloneAccount(account);
    });
  }

  grantFunctionalGrantAsAdministrator(
    input: Parameters<AuthRepository['grantFunctionalGrantAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      const actor = this.requireAdministrator(input.actorSessionVerifier, input.now);
      if (input.grant === 'platform_administrator' && !actor.isServerOwner) {
        throw new AuthRepositoryAuthorizationError();
      }
      const account = this.requireAccount(input.userId);
      if (!account.functionalGrants.includes(input.grant)) {
        account.functionalGrants.push(input.grant);
      }
      return cloneAccount(account);
    });
  }

  invalidateChallenge(challengeId: Uuid, now: number): Promise<void> {
    return this.queue.run(() => {
      const challenge = this.challenges.get(challengeId);
      if (challenge !== undefined && challenge.usedAt === null) {
        challenge.invalidatedAt = now;
      }
    });
  }

  isReady(): Promise<boolean> {
    return Promise.resolve(true);
  }

  issueEmailChallenge(
    input: Parameters<AuthRepository['issueEmailChallenge']>[0],
  ): Promise<IssueChallengeResult> {
    return this.queue.run(() => {
      const account = this.accountsByEmail.get(input.email);
      if (account === undefined || account.status !== 'active') {
        return { kind: 'neutral' };
      }
      const lastIssuedAt = this.latestChallengeAt.get(account.userId);
      if (
        lastIssuedAt !== undefined &&
        input.challenge.issuedAt - lastIssuedAt < input.resendCooldownMs
      ) {
        return { kind: 'neutral' };
      }

      for (const challenge of this.challenges.values()) {
        if (
          challenge.accountId === account.userId &&
          challenge.usedAt === null &&
          challenge.invalidatedAt === null
        ) {
          challenge.invalidatedAt = input.challenge.issuedAt;
        }
      }
      this.challenges.set(input.challenge.challengeId, {
        ...input.challenge,
        accountId: account.userId,
        attempts: 0,
        invalidatedAt: null,
        usedAt: null,
      });
      this.latestChallengeAt.set(account.userId, input.challenge.issuedAt);
      return {
        challengeId: input.challenge.challengeId,
        kind: 'issued',
        recipient: account.email,
      };
    });
  }

  readPasskeyByCredentialId(
    credentialId: Uint8Array,
    now: number,
  ): Promise<AuthPasskeyCredential | null> {
    return this.queue.run(() => {
      const passkey = this.passkeysByCredentialId.get(
        Buffer.from(credentialId).toString('base64url'),
      );
      const account = passkey === undefined ? undefined : this.accountsById.get(passkey.accountId);
      if (
        passkey === undefined ||
        passkey.revokedAt !== null ||
        now < passkey.createdAt ||
        account?.status !== 'active'
      ) {
        return null;
      }
      return Object.freeze({
        aaguid: passkey.aaguid,
        accountId: passkey.accountId,
        attestationFormat: passkey.attestationFormat,
        credentialId: Uint8Array.from(passkey.credentialId),
        lastBackupEligible: passkey.lastBackupEligible,
        lastBackupState: passkey.lastBackupState,
        passkeyId: passkey.passkeyId,
        publicKey: Uint8Array.from(passkey.publicKey),
        registeredBackupEligible: passkey.registeredBackupEligible,
        registeredBackupState: passkey.registeredBackupState,
        signCount: passkey.signCount,
        transports: Object.freeze([...passkey.transports]),
      });
    });
  }

  registerPasskey(
    input: Parameters<AuthRepository['registerPasskey']>[0],
  ): ReturnType<AuthRepository['registerPasskey']> {
    return this.queue.run(() => {
      const session = this.sessionsByVerifier.get(input.actorSessionVerifier);
      const account = session === undefined ? undefined : this.accountsById.get(session.accountId);
      if (
        session === undefined ||
        session.revokedAt !== null ||
        input.now < session.issuedAt ||
        input.now >= session.idleExpiresAt ||
        input.now >= session.absoluteExpiresAt ||
        account?.status !== 'active' ||
        !input.userVerified
      ) {
        throw new AuthRepositoryAuthorizationError();
      }
      const credentialKey = Buffer.from(input.credentialId).toString('base64url');
      if (
        this.passkeysByCredentialId.has(credentialKey) ||
        this.passkeysById.has(input.passkeyId)
      ) {
        throw new AuthRepositoryConflictError();
      }
      const passkey: StoredPasskey = {
        aaguid: input.aaguid,
        accountId: account.userId,
        attestationFormat: input.attestationFormat,
        credentialId: Uint8Array.from(input.credentialId),
        createdAt: input.now,
        lastBackupEligible: input.backupEligible,
        lastBackupState: input.backupState,
        lastUsedAt: null,
        passkeyId: input.passkeyId,
        publicKey: Uint8Array.from(input.publicKey),
        registeredBackupEligible: input.backupEligible,
        registeredBackupState: input.backupState,
        revokedAt: null,
        signCount: input.signCount,
        transports: Object.freeze([...input.transports]),
      };
      this.passkeysByCredentialId.set(credentialKey, passkey);
      this.passkeysById.set(passkey.passkeyId, passkey);
      return { accountId: account.userId, passkeyId: passkey.passkeyId };
    });
  }

  revokeAllSessionsAsAdministrator(
    input: Parameters<AuthRepository['revokeAllSessionsAsAdministrator']>[0],
  ): Promise<number> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      if (!this.accountsById.has(input.userId)) {
        throw new AuthRepositoryNotFoundError();
      }
      let revokedSessionCount = 0;
      for (const session of this.sessionsByVerifier.values()) {
        if (session.accountId === input.userId && session.revokedAt === null) {
          session.revokedAt = input.now;
          revokedSessionCount += 1;
        }
      }
      return revokedSessionCount;
    });
  }

  revokeFunctionalGrantAsAdministrator(
    input: Parameters<AuthRepository['revokeFunctionalGrantAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      const actor = this.requireAdministrator(input.actorSessionVerifier, input.now);
      if (input.grant === 'platform_administrator' && !actor.isServerOwner) {
        throw new AuthRepositoryAuthorizationError();
      }
      const account = this.requireAccount(input.userId);
      if (input.grant === 'platform_administrator' && account.isServerOwner) {
        throw new AuthRepositoryConflictError();
      }
      account.functionalGrants = account.functionalGrants.filter((grant) => grant !== input.grant);
      return cloneAccount(account);
    });
  }

  revokeSessionAsAdministrator(
    input: Parameters<AuthRepository['revokeSessionAsAdministrator']>[0],
  ): Promise<boolean> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      if (!this.accountsById.has(input.userId)) {
        throw new AuthRepositoryNotFoundError();
      }
      for (const session of this.sessionsByVerifier.values()) {
        if (
          session.accountId === input.userId &&
          session.sessionId === input.sessionId &&
          session.revokedAt === null
        ) {
          session.revokedAt = input.now;
          return true;
        }
      }
      return false;
    });
  }

  revokeSessionByVerifier(tokenVerifier: string, now: number): Promise<boolean> {
    return this.queue.run(() => {
      const session = this.sessionsByVerifier.get(tokenVerifier);
      if (session === undefined || session.revokedAt !== null) {
        return false;
      }
      session.revokedAt = now;
      return true;
    });
  }

  setAccountStatusAsAdministrator(
    input: Parameters<AuthRepository['setAccountStatusAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      const account = this.accountsById.get(input.userId);
      if (account === undefined) {
        throw new AuthRepositoryNotFoundError();
      }
      account.status = input.status;
      if (input.status === 'deactivated') {
        for (const session of this.sessionsByVerifier.values()) {
          if (session.accountId === input.userId && session.revokedAt === null) {
            session.revokedAt = input.now;
          }
        }
        for (const challenge of this.challenges.values()) {
          if (
            challenge.accountId === input.userId &&
            challenge.invalidatedAt === null &&
            challenge.usedAt === null
          ) {
            challenge.invalidatedAt = input.now;
          }
        }
        for (const passkey of this.passkeysById.values()) {
          if (passkey.accountId === input.userId && passkey.revokedAt === null) {
            passkey.revokedAt = input.now;
          }
        }
      }
      return cloneAccount(account);
    });
  }

  setDomainStatusAsAdministrator(
    input: Parameters<AuthRepository['setDomainStatusAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      const account = this.requireAccount(input.userId);
      account.domainStatus = input.domainStatus;
      return cloneAccount(account);
    });
  }

  updateAccountAsAdministrator(
    input: Parameters<AuthRepository['updateAccountAsAdministrator']>[0],
  ): Promise<AccountRecord> {
    return this.queue.run(() => {
      this.requireAdministrator(input.actorSessionVerifier, input.now);
      const account = this.accountsById.get(input.userId);
      if (account === undefined) {
        throw new AuthRepositoryNotFoundError();
      }
      const emailOwner = this.accountsByEmail.get(input.email);
      if (emailOwner !== undefined && emailOwner.userId !== account.userId) {
        throw new AuthRepositoryConflictError();
      }
      this.accountsByEmail.delete(account.email);
      account.email = input.email;
      account.displayName = input.displayName;
      this.accountsByEmail.set(account.email, account);
      return cloneAccount(account);
    });
  }

  private requireAdministrator(actorSessionVerifier: string, now: number): StoredAccount {
    const session = this.sessionsByVerifier.get(actorSessionVerifier);
    if (
      session === undefined ||
      session.revokedAt !== null ||
      now < session.issuedAt ||
      now >= session.idleExpiresAt ||
      now >= session.absoluteExpiresAt
    ) {
      throw new AuthRepositoryAuthorizationError();
    }
    const account = this.accountsById.get(session.accountId);
    if (
      account === undefined ||
      account.status !== 'active' ||
      !account.functionalGrants.includes('platform_administrator')
    ) {
      throw new AuthRepositoryAuthorizationError();
    }
    session.lastSeenAt = now;
    session.idleExpiresAt = Math.min(session.absoluteExpiresAt, now + session.idleLifetimeMs);
    return account;
  }

  private requireAccount(userId: UserId): StoredAccount {
    const account = this.accountsById.get(userId);
    if (account === undefined) throw new AuthRepositoryNotFoundError();
    return account;
  }
}

export class LocalEmailChallengeDelivery implements EmailChallengeDelivery {
  readonly messages: EmailChallengeMessage[] = [];

  constructor(environment: Readonly<{ NODE_ENV?: string | undefined }> = process.env) {
    if (environment.NODE_ENV === 'production') {
      throw new Error('Local email challenge delivery is unavailable in production');
    }
  }

  send(message: EmailChallengeMessage): Promise<void> {
    this.messages.push(Object.freeze({ ...message }));
    return Promise.resolve();
  }
}

export class LocalRateLimiter implements RateLimiter {
  private readonly attempts = new Map<string, number[]>();
  private readonly queue = new ExclusiveQueue();

  constructor(environment: Readonly<{ NODE_ENV?: string | undefined }> = process.env) {
    if (environment.NODE_ENV === 'production') {
      throw new Error('Local rate limiter is unavailable in production');
    }
  }

  consume(input: {
    readonly key: string;
    readonly now: number;
    readonly rule: RateLimitRule;
  }): Promise<RateLimitDecision> {
    return this.queue.run(() => {
      const cutoff = input.now - input.rule.windowMs;
      const recent = (this.attempts.get(input.key) ?? []).filter((attempt) => attempt > cutoff);
      if (recent.length >= input.rule.limit) {
        this.attempts.set(input.key, recent);
        return 'limited';
      }
      recent.push(input.now);
      this.attempts.set(input.key, recent);
      return 'allowed';
    });
  }
}

export class UnavailableRateLimiter implements RateLimiter {
  consume(): Promise<RateLimitDecision> {
    return Promise.resolve('unavailable');
  }
}

export class ManualClock implements Clock {
  constructor(private currentTime: number) {}

  advance(milliseconds: number): void {
    this.currentTime += milliseconds;
  }

  now(): number {
    return this.currentTime;
  }
}
