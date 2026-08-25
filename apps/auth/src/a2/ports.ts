import type {
  CorrelationId,
  DomainStatus,
  FunctionalGrant,
  SessionId,
  UserId,
  Uuid,
} from '@kovcheg/contracts';

import type {
  AccountRecord,
  AccountStatus,
  BootstrapAdministratorInput,
  ChallengeRecordInput,
  EmailChallengeMessage,
  RateLimitRule,
  SessionPrincipal,
  SessionRecordInput,
} from './contracts.js';

export type BootstrapAdministratorResult =
  | { readonly account: AccountRecord; readonly created: false }
  | { readonly account: AccountRecord; readonly created: true };

export type IssueChallengeResult =
  | {
      readonly accountId: UserId;
      readonly challengeId: Uuid;
      readonly kind: 'issued';
      readonly recipient: string;
    }
  | { readonly kind: 'neutral' };

export type ConsumeChallengeResult =
  | { readonly kind: 'authenticated'; readonly principal: SessionPrincipal }
  | { readonly kind: 'invalid' };

export interface AuthRepository {
  readonly productionSafe?: true;
  authenticateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null>;
  validateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null>;
  bootstrapAdministrator(input: BootstrapAdministratorInput): Promise<BootstrapAdministratorResult>;
  consumeChallengeAndCreateSession(input: {
    readonly candidateCodeVerifier: string;
    readonly challengeId: Uuid;
    readonly now: number;
    readonly session: SessionRecordInput;
  }): Promise<ConsumeChallengeResult>;
  createAccountAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly displayName: string;
    readonly email: string;
    readonly now: number;
    readonly userId: UserId;
  }): Promise<AccountRecord>;
  grantFunctionalGrantAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly grant: FunctionalGrant;
    readonly now: number;
    readonly reason: string;
    readonly userId: UserId;
    readonly version: number;
  }): Promise<AccountRecord>;
  findAccountById(userId: UserId): Promise<AccountRecord | null>;
  invalidateChallenge(challengeId: Uuid, now: number): Promise<void>;
  isReady(): Promise<boolean>;
  issueChallengeForActiveAccount(input: {
    readonly challenge: ChallengeRecordInput;
    readonly email: string;
    readonly resendCooldownMs: number;
  }): Promise<IssueChallengeResult>;
  revokeAllSessionsAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly userId: UserId;
  }): Promise<number>;
  revokeFunctionalGrantAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly grant: FunctionalGrant;
    readonly now: number;
    readonly reason: string;
    readonly userId: UserId;
    readonly version: number;
  }): Promise<AccountRecord>;
  revokeSessionAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly sessionId: SessionId;
    readonly userId: UserId;
  }): Promise<boolean>;
  revokeSessionByVerifier(tokenVerifier: string, now: number): Promise<boolean>;
  setAccountStatusAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly status: AccountStatus;
    readonly userId: UserId;
  }): Promise<AccountRecord>;
  setDomainStatusAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly domainStatus: DomainStatus;
    readonly now: number;
    readonly reason: string;
    readonly userId: UserId;
    readonly version: number;
  }): Promise<AccountRecord>;
  updateAccountAsAdministrator(input: {
    readonly actorSessionVerifier: string;
    readonly correlationId: CorrelationId;
    readonly displayName: string;
    readonly email: string;
    readonly now: number;
    readonly userId: UserId;
  }): Promise<AccountRecord>;
}

export interface AuthCrypto {
  challengeCodeVerifier(challengeId: Uuid, code: string): string;
  rateLimitKey(namespace: string, value: string): string;
  sessionTokenVerifier(sessionToken: string): string;
}

export interface AuthRandomSource {
  challengeCode(digits: number): string;
  opaqueToken(): string;
  sessionId(): SessionId;
  userId(): UserId;
  uuid(): Uuid;
}

export interface Clock {
  now(): number;
}

export interface EmailChallengeDelivery {
  readonly productionSafe?: true;
  send(message: EmailChallengeMessage): Promise<void>;
}

export type RateLimitDecision = 'allowed' | 'limited' | 'unavailable';

export interface RateLimiter {
  consume(input: {
    readonly key: string;
    readonly now: number;
    readonly rule: RateLimitRule;
  }): Promise<RateLimitDecision>;
}
