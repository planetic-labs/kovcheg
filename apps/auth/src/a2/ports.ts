import type { SessionId, UserId, Uuid } from '@kovcheg/contracts';

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
  authenticateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null>;
  bootstrapAdministrator(input: BootstrapAdministratorInput): Promise<BootstrapAdministratorResult>;
  consumeChallengeAndCreateSession(input: {
    readonly candidateCodeVerifier: string;
    readonly challengeId: Uuid;
    readonly now: number;
    readonly session: SessionRecordInput;
  }): Promise<ConsumeChallengeResult>;
  createAccount(input: {
    readonly displayName: string;
    readonly email: string;
    readonly userId: UserId;
  }): Promise<AccountRecord>;
  findAccountById(userId: UserId): Promise<AccountRecord | null>;
  invalidateChallenge(challengeId: Uuid, now: number): Promise<void>;
  issueChallengeForActiveAccount(input: {
    readonly challenge: ChallengeRecordInput;
    readonly email: string;
    readonly resendCooldownMs: number;
  }): Promise<IssueChallengeResult>;
  revokeSessionById(sessionId: SessionId, now: number): Promise<boolean>;
  revokeSessionByVerifier(tokenVerifier: string, now: number): Promise<boolean>;
  setAccountStatusAndRevoke(input: {
    readonly now: number;
    readonly status: AccountStatus;
    readonly userId: UserId;
  }): Promise<AccountRecord | null>;
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
