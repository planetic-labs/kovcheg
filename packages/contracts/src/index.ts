import { messageFlowErrorCodes } from './message-flow.js';

export const foundationContractVersion = 1 as const;
export const buildMetadataContractVersion = foundationContractVersion;
export const healthContractVersion = foundationContractVersion;
export const machineErrorContractVersion = foundationContractVersion;
export const operationalEventContractVersion = foundationContractVersion;

export type ServiceName = 'api' | 'auth' | 'web' | 'worker';

export const serviceNames = Object.freeze([
  'api',
  'auth',
  'web',
  'worker',
] satisfies readonly ServiceName[]);

export type Uuid = `${string}-${string}-${string}-${string}-${string}`;
export type UserId = Uuid;
export type SessionId = Uuid;

declare const correlationIdBrand: unique symbol;
export type CorrelationId = string & { readonly [correlationIdBrand]: true };

export const correlationIdHeaderName = 'x-correlation-id' as const;
export const correlationIdPattern = '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' as const;

const correlationIdExpression = new RegExp(correlationIdPattern);

export function parseCorrelationId(value: unknown): CorrelationId | null {
  return typeof value === 'string' && correlationIdExpression.test(value)
    ? (value as CorrelationId)
    : null;
}

export function createCorrelationId(): CorrelationId {
  return globalThis.crypto.randomUUID() as CorrelationId;
}

export interface CorrelationRequest {
  correlationId?: CorrelationId;
  readonly headers: Record<string, string | readonly string[] | undefined>;
}

export interface CorrelationResponse {
  setHeader(name: string, value: string): unknown;
}

export function correlationIdMiddleware(
  request: CorrelationRequest,
  response: CorrelationResponse,
  next: () => void,
): void {
  const correlationId =
    parseCorrelationId(request.headers[correlationIdHeaderName]) ?? createCorrelationId();

  request.correlationId = correlationId;
  response.setHeader(correlationIdHeaderName, correlationId);
  next();
}

export interface BuildMetadata {
  readonly commitSha: string | null;
  readonly contractVersion: typeof buildMetadataContractVersion;
  readonly imageDigest: string | null;
  readonly migrationVersion: string | null;
}

export const unknownBuildMetadata: BuildMetadata = Object.freeze({
  commitSha: null,
  contractVersion: buildMetadataContractVersion,
  imageDigest: null,
  migrationVersion: null,
});

export const errorCodes = Object.freeze([
  'foundation.invalid-request',
  'foundation.not-found',
  'foundation.conflict',
  'foundation.unavailable',
  'foundation.internal-error',
  ...messageFlowErrorCodes,
] as const);

export type ErrorCode = (typeof errorCodes)[number];

export interface MachineError {
  readonly code: ErrorCode;
  readonly contractVersion: typeof machineErrorContractVersion;
  readonly correlationId: CorrelationId;
  readonly httpStatus: number;
  readonly title: string;
}

export const machineErrorJsonSchema = {
  additionalProperties: false,
  properties: {
    code: { enum: [...errorCodes], type: 'string' },
    contractVersion: { enum: [machineErrorContractVersion], type: 'integer' },
    correlationId: { pattern: correlationIdPattern, type: 'string' },
    httpStatus: { maximum: 599, minimum: 400, type: 'integer' },
    title: { minLength: 1, type: 'string' },
  },
  required: ['code', 'contractVersion', 'correlationId', 'httpStatus', 'title'],
  type: 'object',
};

export const operationalEventNames = Object.freeze([
  'service.started',
  'service.start-failed',
  'http.request.completed',
] as const);

export type OperationalEventName = (typeof operationalEventNames)[number];
export type OperationalEventOutcome = 'failure' | 'success';

export interface OperationalEvent {
  readonly build: BuildMetadata;
  readonly contractVersion: typeof operationalEventContractVersion;
  readonly correlationId: CorrelationId;
  readonly name: OperationalEventName;
  readonly occurredAt: string;
  readonly outcome: OperationalEventOutcome;
  readonly service: ServiceName;
}

export interface CreateOperationalEventInput {
  readonly build?: BuildMetadata;
  readonly correlationId: CorrelationId;
  readonly name: OperationalEventName;
  readonly occurredAt?: string;
  readonly outcome: OperationalEventOutcome;
  readonly service: ServiceName;
}

export function createOperationalEvent(input: CreateOperationalEventInput): OperationalEvent {
  return Object.freeze({
    build: input.build ?? unknownBuildMetadata,
    contractVersion: operationalEventContractVersion,
    correlationId: input.correlationId,
    name: input.name,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    outcome: input.outcome,
    service: input.service,
  });
}

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
] satisfies readonly CoreModuleName[]);

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

export type AuthorizationDeniedReason =
  'anonymous' | 'deactivated-identity' | 'not-implemented' | 'revoked-session';
export type AuthorizationReason = 'allowed' | AuthorizationDeniedReason;

export type AuthorizationDecision =
  | { readonly allowed: true; readonly reason: 'allowed' }
  | { readonly allowed: false; readonly reason: AuthorizationDeniedReason };

export interface AuthorizationEvaluator {
  authorize(request: AuthorizationRequest): Promise<AuthorizationDecision>;
}

export const denyAllAuthorizationEvaluator: AuthorizationEvaluator = Object.freeze({
  authorize(): Promise<AuthorizationDecision> {
    return Promise.resolve({ allowed: false, reason: 'not-implemented' });
  },
});

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
export type HealthStatus = 'degraded' | 'ok' | 'unavailable';

export interface HealthCheck {
  readonly name: string;
  readonly status: HealthStatus;
}

export interface ServiceHealth {
  readonly build: BuildMetadata;
  readonly checks: readonly HealthCheck[];
  readonly contractVersion: typeof healthContractVersion;
  readonly service: ServiceName;
  readonly state: HealthState;
  readonly status: HealthStatus;
}

export interface CreateServiceHealthOptions {
  readonly build?: BuildMetadata;
  readonly checks?: readonly HealthCheck[];
  readonly status?: HealthStatus;
}

export function createServiceHealth(
  service: ServiceName,
  state: HealthState,
  options: CreateServiceHealthOptions = {},
): ServiceHealth {
  return Object.freeze({
    build: options.build ?? unknownBuildMetadata,
    checks: Object.freeze([...(options.checks ?? [])]),
    contractVersion: healthContractVersion,
    service,
    state,
    status: options.status ?? 'ok',
  });
}

export const buildMetadataJsonSchema = {
  additionalProperties: false,
  properties: {
    commitSha: { nullable: true, pattern: '^[0-9a-f]{40}$', type: 'string' },
    contractVersion: { enum: [buildMetadataContractVersion], type: 'integer' },
    imageDigest: { nullable: true, pattern: '^sha256:[0-9a-f]{64}$', type: 'string' },
    migrationVersion: { nullable: true, type: 'string' },
  },
  required: ['commitSha', 'contractVersion', 'imageDigest', 'migrationVersion'],
  type: 'object',
};

export const serviceHealthJsonSchema = {
  additionalProperties: false,
  properties: {
    build: buildMetadataJsonSchema,
    checks: {
      items: {
        additionalProperties: false,
        properties: {
          name: { minLength: 1, type: 'string' },
          status: { enum: ['ok', 'degraded', 'unavailable'], type: 'string' },
        },
        required: ['name', 'status'],
        type: 'object',
      },
      type: 'array',
    },
    contractVersion: { enum: [healthContractVersion], type: 'integer' },
    service: { enum: [...serviceNames], type: 'string' },
    state: { enum: ['live', 'ready'], type: 'string' },
    status: { enum: ['ok', 'degraded', 'unavailable'], type: 'string' },
  },
  required: ['build', 'checks', 'contractVersion', 'service', 'state', 'status'],
  type: 'object',
};

export {
  availableChatJsonSchema,
  availableChatListJsonSchema,
  chatListContractVersion,
  createTextMessageRequestJsonSchema,
  createTextMessageResponseJsonSchema,
  messageFlowContractVersion,
  messageFlowErrorCodes,
  messageHistoryPageJsonSchema,
  textMessageJsonSchema,
} from './message-flow.js';
export type {
  AvailableChat,
  AvailableChatList,
  ChatKind,
  ChatSequence,
  CreateTextMessageRequest,
  CreateTextMessageResponse,
  MessageFlowErrorCode,
  MessageFlowRequestContext,
  MessageHistoryPage,
  TextMessage,
} from './message-flow.js';
export {
  createRealtimeEventDeduplicator,
  parseMessageCreatedRealtimeEvent,
  parseRealtimeSubscribeRequest,
  realtimeAdapterStreamName,
  realtimeApplicationStreamName,
  realtimeContractVersion,
  realtimeRelayConsumerGroup,
  realtimeSocketEvents,
  realtimeSocketPath,
} from './realtime.js';
export type {
  MessageCreatedRealtimeEvent,
  MessageCreatedRealtimePayload,
  RealtimeEventDeduplicator,
  RealtimeReadyEvent,
  RealtimeSocketIdentity,
  RealtimeSubscribeRequest,
  RealtimeSubscribeResult,
} from './realtime.js';
