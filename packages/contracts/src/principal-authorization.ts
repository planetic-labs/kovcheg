import type { SessionId, UserId } from './foundation-types.js';

export const principalAuthorizationContractVersion = 1 as const;

export const domainStatuses = Object.freeze(['incubator_participant', 'disciple'] as const);
export type DomainStatus = (typeof domainStatuses)[number];

export const functionalGrants = Object.freeze([
  'warrior',
  'platform_administrator',
  'chronicler',
] as const);
export type FunctionalGrant = (typeof functionalGrants)[number];

export interface AdministrativeCapabilities {
  readonly canManageAccounts: boolean;
  readonly canManageDomainStatus: boolean;
  readonly canManageFunctionalGrants: boolean;
}

export interface CurrentPrincipalAuthorization {
  readonly accountAccess: 'member';
  readonly accountStatus: 'active';
  readonly administrativeCapabilities: AdministrativeCapabilities;
  readonly contractVersion: typeof principalAuthorizationContractVersion;
  readonly domainStatus: DomainStatus;
  readonly functionalGrants: readonly FunctionalGrant[];
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
  if (!isRecord(value) || !isRecord(value.administrativeCapabilities)) return null;
  if (
    Object.keys(value).sort().join(',') !==
      'accountAccess,accountStatus,administrativeCapabilities,contractVersion,domainStatus,functionalGrants,sessionId,sessionStatus,userId' ||
    Object.keys(value.administrativeCapabilities).sort().join(',') !==
      'canManageAccounts,canManageDomainStatus,canManageFunctionalGrants'
  ) {
    return null;
  }
  const grants = value.functionalGrants;
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
    typeof value.administrativeCapabilities.canManageAccounts !== 'boolean' ||
    typeof value.administrativeCapabilities.canManageDomainStatus !== 'boolean' ||
    typeof value.administrativeCapabilities.canManageFunctionalGrants !== 'boolean'
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
    }),
    contractVersion: principalAuthorizationContractVersion,
    domainStatus: value.domainStatus as DomainStatus,
    functionalGrants: Object.freeze([...parsedGrants]),
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
      },
      required: ['canManageAccounts', 'canManageDomainStatus', 'canManageFunctionalGrants'],
      type: 'object',
    },
    contractVersion: { enum: [principalAuthorizationContractVersion], type: 'integer' },
    domainStatus: { enum: [...domainStatuses], type: 'string' },
    functionalGrants: { items: { enum: [...functionalGrants] }, type: 'array' },
    sessionId: { format: 'uuid', type: 'string' },
    sessionStatus: { enum: ['active'], type: 'string' },
    userId: { format: 'uuid', type: 'string' },
  },
  required: [
    'accountAccess',
    'accountStatus',
    'administrativeCapabilities',
    'contractVersion',
    'domainStatus',
    'functionalGrants',
    'sessionId',
    'sessionStatus',
    'userId',
  ],
  type: 'object',
});
