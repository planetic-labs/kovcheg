import { describe, expect, it } from 'vitest';

import {
  currentPrincipalAuthorizationJsonSchema,
  parseCurrentPrincipalAuthorization,
  principalAuthorizationContractVersion,
} from './principal-authorization.js';

const principal = Object.freeze({
  accountAccess: 'member',
  accountStatus: 'active',
  administrativeCapabilities: Object.freeze({
    canManageAccounts: false,
    canManageDomainStatus: false,
    canManageFunctionalGrants: false,
    canManagePlatformAdministrators: false,
  }),
  contractVersion: principalAuthorizationContractVersion,
  diagnosticCapabilities: Object.freeze({
    canReadBuildAndMigrationVersions: false,
    canReadHealthAndReadiness: false,
    canReadQueueAndTechnicalState: false,
    canReadSanitizedDiagnostics: false,
  }),
  domainStatus: 'incubator_participant',
  functionalGrants: Object.freeze(['chronicler', 'editor']),
  isServerOwner: false,
  materialCapabilities: Object.freeze([]),
  sensitiveCapabilities: Object.freeze({ canPerformSensitiveActions: false }),
  sessionId: '00000000-0000-4000-8000-000000006101',
  sessionStatus: 'active',
  userId: '00000000-0000-4000-8000-000000006001',
});

describe('principal authorization contract', () => {
  it('accepts a versioned server-authoritative principal', () => {
    expect(parseCurrentPrincipalAuthorization(principal)).toEqual(principal);
    expect(currentPrincipalAuthorizationJsonSchema.required).toContain('functionalGrants');
    expect(principal.functionalGrants).toEqual(['chronicler', 'editor']);
    expect(principal.materialCapabilities).toEqual([]);
  });

  it('rejects browser-supplied or ambiguous authorization state', () => {
    expect(
      parseCurrentPrincipalAuthorization({ ...principal, domainStatus: 'unknown_status' }),
    ).toBeNull();
    expect(
      parseCurrentPrincipalAuthorization({
        ...principal,
        functionalGrants: ['warrior', 'warrior'],
      }),
    ).toBeNull();
    expect(
      parseCurrentPrincipalAuthorization({ ...principal, roles: ['browser-role'] }),
    ).toBeNull();
  });
});
