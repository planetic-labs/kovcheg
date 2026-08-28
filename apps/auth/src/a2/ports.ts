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
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

export type BootstrapAdministratorResult =
  | { readonly account: AccountRecord; readonly created: false }
  | { readonly account: AccountRecord; readonly created: true };

export type IssueChallengeResult =
  | {
      readonly challengeId: Uuid;
      readonly kind: 'issued';
      readonly recipient: string;
    }
  | { readonly kind: 'neutral' };

export type ConsumeChallengeResult =
  | { readonly kind: 'authenticated'; readonly principal: SessionPrincipal }
  | { readonly kind: 'invalid' };

interface CompletePasskeyLoginResult {
  readonly accountId: UserId;
  readonly reused: boolean;
  readonly sessionId: SessionId;
  readonly signCountStatus: AuthPasskeySignCountStatus;
}

export type PasskeyCeremonyState =
  | {
      readonly accountId: UserId;
      readonly challenge: string;
      readonly clientContextKey: string;
      readonly ceremony: 'registration';
      readonly sessionVerifier: string;
    }
  | {
      readonly challenge: string;
      readonly clientContextKey: string;
      readonly ceremony: 'authentication';
    };

export type TakePasskeyCeremonyResult =
  | { readonly kind: 'found'; readonly state: PasskeyCeremonyState }
  | { readonly kind: 'missing' }
  | { readonly kind: 'unavailable' };

export interface PasskeyCeremonyStore {
  put(
    ceremonyId: Uuid,
    state: PasskeyCeremonyState,
    ttlMs: number,
  ): Promise<'stored' | 'unavailable'>;
  take(ceremonyId: Uuid): Promise<TakePasskeyCeremonyResult>;
}

export interface PasskeyRegistrationVerification {
  readonly aaguid: Uuid;
  readonly attestationFormat: string;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly signCount: number;
  readonly transports: readonly AuthPasskeyTransport[];
  readonly userVerified: boolean;
}

export interface PasskeyAuthenticationVerification {
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  readonly observedSignCount: number;
  readonly userVerified: boolean;
}

export interface WebAuthnServer {
  generateAuthenticationOptions(input: {
    readonly rpId: string;
    readonly timeoutMs: number;
  }): Promise<PublicKeyCredentialRequestOptionsJSON>;
  generateRegistrationOptions(input: {
    readonly accountId: UserId;
    readonly accountLabel: string;
    readonly rpId: string;
    readonly rpName: string;
    readonly timeoutMs: number;
  }): Promise<PublicKeyCredentialCreationOptionsJSON>;
  verifyAuthentication(input: {
    readonly credential: AuthPasskeyCredential;
    readonly expectedChallenge: string;
    readonly expectedOrigins: readonly string[];
    readonly expectedRpId: string;
    readonly response: AuthenticationResponseJSON;
  }): Promise<PasskeyAuthenticationVerification | null>;
  verifyRegistration(input: {
    readonly expectedChallenge: string;
    readonly expectedOrigins: readonly string[];
    readonly expectedRpId: string;
    readonly response: RegistrationResponseJSON;
  }): Promise<PasskeyRegistrationVerification | null>;
}

export interface AuthRepository {
  readonly productionSafe?: true;
  authenticateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null>;
  validateSession(tokenVerifier: string, now: number): Promise<SessionPrincipal | null>;
  adminSecurityResetAuthAccess(input: {
    readonly actorSessionVerifier: string;
    readonly accountId: UserId;
    readonly correlationId: CorrelationId;
    readonly now: number;
  }): Promise<AuthSecurityResetResult>;
  bootstrapAdministrator(input: BootstrapAdministratorInput): Promise<BootstrapAdministratorResult>;
  completePasskeyLogin(input: {
    readonly assertionId: Uuid;
    readonly correlationId: CorrelationId;
    readonly credentialId: Uint8Array;
    readonly expectedSignCount: number;
    readonly now: number;
    readonly observedBackupEligible: boolean;
    readonly observedBackupState: boolean;
    readonly observedSignCount: number;
    readonly session: SessionRecordInput;
    readonly userVerified: boolean;
  }): Promise<CompletePasskeyLoginResult | null>;
  consumeChallengeAndCreateSession(input: {
    readonly candidateCodeVerifier: string;
    readonly challengeId: Uuid;
    readonly now: number;
    readonly session: SessionRecordInput;
  }): Promise<ConsumeChallengeResult>;
  createOidcSession(input: {
    readonly accountId: UserId;
    readonly correlationId: CorrelationId;
    readonly now: number;
    readonly session: SessionRecordInput;
    readonly sourceTokenVerifier: string;
  }): Promise<boolean>;
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
  issueEmailChallenge(input: {
    readonly challenge: ChallengeRecordInput;
    readonly correlationId: CorrelationId;
    readonly email: string;
    readonly resendCooldownMs: number;
  }): Promise<IssueChallengeResult>;
  readPasskeyByCredentialId(
    credentialId: Uint8Array,
    now: number,
  ): Promise<AuthPasskeyCredential | null>;
  registerPasskey(input: {
    readonly actorSessionVerifier: string;
    readonly aaguid: Uuid;
    readonly attestationFormat: string;
    readonly backupEligible: boolean;
    readonly backupState: boolean;
    readonly correlationId: CorrelationId;
    readonly credentialId: Uint8Array;
    readonly now: number;
    readonly passkeyId: Uuid;
    readonly publicKey: Uint8Array;
    readonly signCount: number;
    readonly transports: readonly AuthPasskeyTransport[];
    readonly userVerified: boolean;
  }): Promise<{ readonly accountId: UserId; readonly passkeyId: Uuid }>;
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
