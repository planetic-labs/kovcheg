export const foundationContractVersion = 1 as const;

export type ServiceName = 'api' | 'auth' | 'web' | 'worker';

export type Uuid = `${string}-${string}-${string}-${string}-${string}`;
export type UserId = Uuid;
export type SessionId = Uuid;

export type IdentityStatus = 'active' | 'deactivated';

export interface IdentityRecord {
  readonly userId: UserId;
  readonly status: IdentityStatus;
}

export interface IdentityReader {
  findById(userId: UserId): Promise<IdentityRecord | null>;
}

export type SessionState = 'anonymous' | 'authenticated' | 'revoked';

export interface SessionRecord {
  readonly sessionId: SessionId;
  readonly state: SessionState;
  readonly userId: UserId | null;
}

export interface SessionReader {
  findById(sessionId: SessionId): Promise<SessionRecord | null>;
}

export type CoreModuleName =
  | 'authorization'
  | 'chats'
  | 'identity'
  | 'messages'
  | 'notifications'
  | 'realtime'
  | 'session'
  | 'users';

export const coreModuleNames = Object.freeze([
  'identity',
  'session',
  'authorization',
  'users',
  'chats',
  'messages',
  'realtime',
  'notifications',
]) satisfies readonly CoreModuleName[];

export interface ModuleResource {
  readonly module: CoreModuleName;
  readonly resourceId: Uuid | null;
}

export interface AuthorizationRequest {
  readonly action: string;
  readonly identity: IdentityRecord | null;
  readonly resource: ModuleResource;
  readonly session: SessionRecord | null;
}

export type AuthorizationReason =
  'allowed' | 'anonymous' | 'deactivated-identity' | 'not-implemented' | 'revoked-session';

export interface AuthorizationDecision {
  readonly allowed: boolean;
  readonly reason: AuthorizationReason;
}

export interface AuthorizationEvaluator {
  authorize(request: AuthorizationRequest): Promise<AuthorizationDecision>;
}

export interface ModuleDescriptor {
  readonly contractVersion: typeof foundationContractVersion;
  readonly dependencies: readonly CoreModuleName[];
  readonly name: CoreModuleName;
}

export interface ServiceDescriptor {
  readonly contractVersion: typeof foundationContractVersion;
  readonly name: ServiceName;
}

export type HealthState = 'live' | 'ready';

export interface ServiceHealth {
  readonly contractVersion: typeof foundationContractVersion;
  readonly service: ServiceName;
  readonly state: HealthState;
  readonly status: 'ok';
}

export function createServiceHealth(service: ServiceName, state: HealthState): ServiceHealth {
  return {
    contractVersion: foundationContractVersion,
    service,
    state,
    status: 'ok',
  };
}
