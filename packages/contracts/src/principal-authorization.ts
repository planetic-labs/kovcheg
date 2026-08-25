import type { SessionId, UserId } from './foundation-types.js';

export const principalAuthorizationContractVersion = 2 as const;

export const domainStatuses = Object.freeze(['incubator_participant', 'disciple'] as const);
export type DomainStatus = (typeof domainStatuses)[number];

export const functionalGrants = Object.freeze([
  'warrior',
  'platform_administrator',
  'chronicler',
  'editor',
  'technical_administrator',
] as const);
export type FunctionalGrant = (typeof functionalGrants)[number];

export type MaterialCapabilityType = string;

export const materialCapabilityActions = Object.freeze(['create', 'edit', 'publish'] as const);
export type MaterialCapabilityAction = (typeof materialCapabilityActions)[number];

export interface MaterialCapability {
  readonly actions: readonly MaterialCapabilityAction[];
  readonly materialType: MaterialCapabilityType;
}

export interface AdministrativeCapabilities {
  readonly canManageAccounts: boolean;
  readonly canManageDomainStatus: boolean;
  readonly canManageFunctionalGrants: boolean;
  readonly canManagePlatformAdministrators: boolean;
}

export interface DiagnosticCapabilities {
  readonly canReadBuildAndMigrationVersions: boolean;
  readonly canReadHealthAndReadiness: boolean;
  readonly canReadQueueAndTechnicalState: boolean;
  readonly canReadSanitizedDiagnostics: boolean;
}

export interface SensitiveCapabilities {
  readonly canPerformSensitiveActions: boolean;
}

export interface CurrentPrincipalAuthorization {
  readonly accountAccess: 'member';
  readonly accountStatus: 'active';
  readonly administrativeCapabilities: AdministrativeCapabilities;
  readonly contractVersion: typeof principalAuthorizationContractVersion;
  readonly diagnosticCapabilities: DiagnosticCapabilities;
  readonly domainStatus: DomainStatus;
  readonly functionalGrants: readonly FunctionalGrant[];
  readonly isServerOwner: boolean;
  readonly materialCapabilities: readonly MaterialCapability[];
  readonly sensitiveCapabilities: SensitiveCapabilities;
  readonly sessionId: SessionId;
  readonly sessionStatus: 'active';
  readonly userId: UserId;
}

const uuidExpression =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function parseCurrentPrincipalAuthorization(
  value: unknown,
): CurrentPrincipalAuthorization | null {
  if (
    !isRecord(value) ||
    !isRecord(value.administrativeCapabilities) ||
    !isRecord(value.diagnosticCapabilities) ||
    !isRecord(value.sensitiveCapabilities)
  ) {
    return null;
  }
  if (
    Object.keys(value).sort().join(',') !==
      'accountAccess,accountStatus,administrativeCapabilities,contractVersion,diagnosticCapabilities,domainStatus,functionalGrants,isServerOwner,materialCapabilities,sensitiveCapabilities,sessionId,sessionStatus,userId' ||
    Object.keys(value.administrativeCapabilities).sort().join(',') !==
      'canManageAccounts,canManageDomainStatus,canManageFunctionalGrants,canManagePlatformAdministrators' ||
    Object.keys(value.diagnosticCapabilities).sort().join(',') !==
      'canReadBuildAndMigrationVersions,canReadHealthAndReadiness,canReadQueueAndTechnicalState,canReadSanitizedDiagnostics' ||
    Object.keys(value.sensitiveCapabilities).sort().join(',') !== 'canPerformSensitiveActions'
  ) {
    return null;
  }
  const grants = value.functionalGrants;
  const materialCapabilities = value.materialCapabilities;
  if (
    value.contractVersion !== principalAuthorizationContractVersion ||
    value.accountAccess !== 'member' ||
    value.accountStatus !== 'active' ||
    value.sessionStatus !== 'active' ||
    typeof value.sessionId !== 'string' ||
    !uuidExpression.test(value.sessionId) ||
    typeof value.userId !== 'string' ||
    !uuidExpression.test(value.userId) ||
    !domainStatuses.includes(value.domainStatus as DomainStatus) ||
    !Array.isArray(grants) ||
    grants.some((grant) => !functionalGrants.includes(grant as FunctionalGrant)) ||
    !Array.isArray(materialCapabilities) ||
    materialCapabilities.some(
      (capability) =>
        !isRecord(capability) ||
        Object.keys(capability).sort().join(',') !== 'actions,materialType' ||
        typeof capability.materialType !== 'string' ||
        !/^[a-z][a-z0-9.-]{2,63}$/.test(capability.materialType) ||
        !Array.isArray(capability.actions) ||
        capability.actions.some(
          (action) => !materialCapabilityActions.includes(action as MaterialCapabilityAction),
        ) ||
        new Set(capability.actions).size !== capability.actions.length,
    ) ||
    typeof value.isServerOwner !== 'boolean' ||
    typeof value.administrativeCapabilities.canManageAccounts !== 'boolean' ||
    typeof value.administrativeCapabilities.canManageDomainStatus !== 'boolean' ||
    typeof value.administrativeCapabilities.canManageFunctionalGrants !== 'boolean' ||
    typeof value.administrativeCapabilities.canManagePlatformAdministrators !== 'boolean' ||
    typeof value.diagnosticCapabilities.canReadBuildAndMigrationVersions !== 'boolean' ||
    typeof value.diagnosticCapabilities.canReadHealthAndReadiness !== 'boolean' ||
    typeof value.diagnosticCapabilities.canReadQueueAndTechnicalState !== 'boolean' ||
    typeof value.diagnosticCapabilities.canReadSanitizedDiagnostics !== 'boolean' ||
    typeof value.sensitiveCapabilities.canPerformSensitiveActions !== 'boolean'
  ) {
    return null;
  }
  const parsedGrants = grants as FunctionalGrant[];
  if (new Set(parsedGrants).size !== parsedGrants.length) return null;
  return Object.freeze({
    accountAccess: 'member',
    accountStatus: 'active',
    administrativeCapabilities: Object.freeze({
      canManageAccounts: value.administrativeCapabilities.canManageAccounts,
      canManageDomainStatus: value.administrativeCapabilities.canManageDomainStatus,
      canManageFunctionalGrants: value.administrativeCapabilities.canManageFunctionalGrants,
      canManagePlatformAdministrators:
        value.administrativeCapabilities.canManagePlatformAdministrators,
    }),
    contractVersion: principalAuthorizationContractVersion,
    diagnosticCapabilities: Object.freeze({
      canReadBuildAndMigrationVersions:
        value.diagnosticCapabilities.canReadBuildAndMigrationVersions,
      canReadHealthAndReadiness: value.diagnosticCapabilities.canReadHealthAndReadiness,
      canReadQueueAndTechnicalState: value.diagnosticCapabilities.canReadQueueAndTechnicalState,
      canReadSanitizedDiagnostics: value.diagnosticCapabilities.canReadSanitizedDiagnostics,
    }),
    domainStatus: value.domainStatus as DomainStatus,
    functionalGrants: Object.freeze([...parsedGrants]),
    isServerOwner: value.isServerOwner,
    materialCapabilities: Object.freeze(
      materialCapabilities.map((capability) => {
        const parsed = capability as {
          readonly actions: readonly MaterialCapabilityAction[];
          readonly materialType: MaterialCapabilityType;
        };
        return Object.freeze({
          actions: Object.freeze([...parsed.actions]),
          materialType: parsed.materialType,
        });
      }),
    ),
    sensitiveCapabilities: Object.freeze({
      canPerformSensitiveActions: value.sensitiveCapabilities.canPerformSensitiveActions,
    }),
    sessionId: value.sessionId as SessionId,
    sessionStatus: 'active',
    userId: value.userId as UserId,
  });
}

export const currentPrincipalAuthorizationJsonSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    accountAccess: { enum: ['member'], type: 'string' },
    accountStatus: { enum: ['active'], type: 'string' },
    administrativeCapabilities: {
      additionalProperties: false,
      properties: {
        canManageAccounts: { type: 'boolean' },
        canManageDomainStatus: { type: 'boolean' },
        canManageFunctionalGrants: { type: 'boolean' },
        canManagePlatformAdministrators: { type: 'boolean' },
      },
      required: [
        'canManageAccounts',
        'canManageDomainStatus',
        'canManageFunctionalGrants',
        'canManagePlatformAdministrators',
      ],
      type: 'object',
    },
    contractVersion: { enum: [principalAuthorizationContractVersion], type: 'integer' },
    diagnosticCapabilities: {
      additionalProperties: false,
      properties: {
        canReadBuildAndMigrationVersions: { type: 'boolean' },
        canReadHealthAndReadiness: { type: 'boolean' },
        canReadQueueAndTechnicalState: { type: 'boolean' },
        canReadSanitizedDiagnostics: { type: 'boolean' },
      },
      required: [
        'canReadBuildAndMigrationVersions',
        'canReadHealthAndReadiness',
        'canReadQueueAndTechnicalState',
        'canReadSanitizedDiagnostics',
      ],
      type: 'object',
    },
    domainStatus: { enum: [...domainStatuses], type: 'string' },
    functionalGrants: { items: { enum: [...functionalGrants] }, type: 'array' },
    isServerOwner: { type: 'boolean' },
    materialCapabilities: {
      items: {
        additionalProperties: false,
        properties: {
          actions: { items: { enum: [...materialCapabilityActions] }, type: 'array' },
          materialType: { pattern: '^[a-z][a-z0-9.-]{2,63}$', type: 'string' },
        },
        required: ['actions', 'materialType'],
        type: 'object',
      },
      type: 'array',
    },
    sensitiveCapabilities: {
      additionalProperties: false,
      properties: { canPerformSensitiveActions: { type: 'boolean' } },
      required: ['canPerformSensitiveActions'],
      type: 'object',
    },
    sessionId: { format: 'uuid', type: 'string' },
    sessionStatus: { enum: ['active'], type: 'string' },
    userId: { format: 'uuid', type: 'string' },
  },
  required: [
    'accountAccess',
    'accountStatus',
    'administrativeCapabilities',
    'contractVersion',
    'diagnosticCapabilities',
    'domainStatus',
    'functionalGrants',
    'isServerOwner',
    'materialCapabilities',
    'sensitiveCapabilities',
    'sessionId',
    'sessionStatus',
    'userId',
  ],
  type: 'object',
});
