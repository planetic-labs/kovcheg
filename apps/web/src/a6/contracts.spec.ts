import { describe, expect, it } from 'vitest';

import {
  parseAccountRecord,
  parseAccountDetail,
  parseAccountListPage,
  parseOwnPasskeySettings,
  parseChatListResponse,
  parseMessageHistoryPage,
  parseSessionPrincipal,
} from './contracts';

const session = Object.freeze({
  accountAccess: 'member',
  accountStatus: 'active',
  administrativeCapabilities: Object.freeze({
    canManageAccounts: true,
    canManageDomainStatus: true,
    canManageFunctionalGrants: true,
    canManagePlatformAdministrators: false,
  }),
  contractVersion: 2,
  diagnosticCapabilities: Object.freeze({
    canReadBuildAndMigrationVersions: false,
    canReadHealthAndReadiness: false,
    canReadQueueAndTechnicalState: false,
    canReadSanitizedDiagnostics: false,
  }),
  domainStatus: 'disciple',
  functionalGrants: Object.freeze(['warrior']),
  isServerOwner: false,
  materialCapabilities: Object.freeze([]),
  sensitiveCapabilities: Object.freeze({ canPerformSensitiveActions: false }),
  sessionId: '00000000-0000-4000-8000-000000000501',
  sessionStatus: 'active',
  userId: '00000000-0000-4000-8000-000000000502',
});

describe('A6 browser contract parsing', () => {
  it('requires authoritative versions, bounded unique account pages and value-free own keys', () => {
    const item = {
      userId: session.userId,
      displayName: 'Synthetic Member',
      email: 'member@example.invalid',
      status: 'active',
    };
    expect(parseAccountListPage({ items: [item], nextAfterAccountId: null })).not.toBeNull();
    expect(parseAccountListPage({ items: [item, item], nextAfterAccountId: null })).toBeNull();
    expect(
      parseAccountListPage({ items: [item], nextAfterAccountId: session.sessionId }),
    ).toBeNull();
    const account = {
      ...item,
      accountAccess: 'member',
      domainStatus: 'disciple',
      functionalGrants: [],
      nextAuthorizationVersion: 2,
      isServerOwner: false,
    };
    expect(parseAccountDetail(account)).not.toBeNull();
    expect(parseAccountDetail({ ...account, nextAuthorizationVersion: 1 })).toBeNull();
    expect(parseAccountDetail({ ...account, functionalGrants: ['invented'] })).toBeNull();
    const key = {
      id: session.userId,
      createdAt: '2026-01-01T12:00:00Z',
      lastUsedAt: null,
      status: 'active',
    };
    const settings = { everAdded: true, activePasskeyCount: 1, activePasskeys: [key] };
    expect(parseOwnPasskeySettings(settings)).not.toBeNull();
    expect(parseOwnPasskeySettings({ ...settings, everAdded: false })).toBeNull();
    expect(
      parseOwnPasskeySettings({
        ...settings,
        activePasskeys: [{ ...key, publicKey: 'unexpected' }],
      }),
    ).toBeNull();
    expect(
      parseOwnPasskeySettings({ ...settings, activePasskeys: [key, key], activePasskeyCount: 2 }),
    ).toBeNull();
    expect(
      parseOwnPasskeySettings({ everAdded: true, activePasskeyCount: 0, activePasskeys: [] }),
    ).not.toBeNull();
  });
  it('accepts the server principal and rejects invented browser grants', () => {
    expect(parseSessionPrincipal(session)).not.toBeNull();
    expect(parseSessionPrincipal({ ...session, functionalGrants: ['invented-grant'] })).toBeNull();
  });

  it('parses the versioned account status and functional grants', () => {
    expect(
      parseAccountRecord({
        accountAccess: 'member',
        displayName: 'Synthetic Member',
        domainStatus: 'incubator_participant',
        email: 'member@example.invalid',
        functionalGrants: ['chronicler'],
        status: 'active',
        userId: '00000000-0000-4000-8000-000000000503',
      }),
    ).not.toBeNull();
  });

  it('requires server-provided read and write capabilities for every chat', () => {
    expect(
      parseChatListResponse({
        contractVersion: 2,
        items: [
          {
            capabilities: { canRead: true, canWrite: false },
            id: '00000000-0000-4000-8000-000000000504',
            kind: 'group',
          },
        ],
      }),
    ).not.toBeNull();
    expect(
      parseChatListResponse({
        contractVersion: 2,
        items: [{ id: '00000000-0000-4000-8000-000000000504', kind: 'group' }],
      }),
    ).toBeNull();
  });

  it('rejects history that does not match the published cursor contract', () => {
    expect(
      parseMessageHistoryPage({
        contractVersion: 3,
        hasMore: false,
        items: [],
        nextAfterSequence: null,
        nextBeforeSequence: null,
      }),
    ).not.toBeNull();
    expect(
      parseMessageHistoryPage({
        contractVersion: 3,
        hasMore: false,
        items: [],
        nextAfterSequence: 'invalid',
        nextBeforeSequence: null,
      }),
    ).toBeNull();
  });
});
