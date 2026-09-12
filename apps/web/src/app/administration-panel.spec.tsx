import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { parseSessionPrincipal } from '../a6/contracts';
import { AdministrationPanel } from './administration-panel';

const principal = parseSessionPrincipal({
  accountAccess: 'member',
  accountStatus: 'active',
  administrativeCapabilities: {
    canManageAccounts: true,
    canManageDomainStatus: true,
    canManageFunctionalGrants: true,
    canManagePlatformAdministrators: true,
  },
  contractVersion: 2,
  diagnosticCapabilities: {
    canReadBuildAndMigrationVersions: false,
    canReadHealthAndReadiness: false,
    canReadQueueAndTechnicalState: false,
    canReadSanitizedDiagnostics: false,
  },
  domainStatus: 'disciple',
  functionalGrants: ['platform_administrator'],
  isServerOwner: true,
  materialCapabilities: [],
  sensitiveCapabilities: { canPerformSensitiveActions: false },
  sessionId: '00000000-0000-4000-8000-000000000501',
  sessionStatus: 'active',
  userId: '00000000-0000-4000-8000-000000000502',
});
if (principal === null) throw new Error('Invalid synthetic principal');

describe('AdministrationPanel initial rendering', () => {
  it('renders the list surface without claiming an unread list is empty or saved', () => {
    const markup = renderToStaticMarkup(
      <AdministrationPanel principal={principal} onSessionInvalid={() => undefined} />,
    );

    expect(markup).toContain('<h1>Пользователи</h1>');
    expect(markup).toContain('aria-label="Список пользователей"');
    expect(markup).toContain('Обновить</button>');
    expect(markup).toContain('Создать пользователя</button>');
    expect(markup).toContain('Выберите пользователя из списка.');
    expect(markup).not.toContain('Список не содержит пользователей.');
    expect(markup).not.toContain('Сохранено и подтверждено сервером.');
    expect(markup).not.toMatch(/<(?:input|select)\b/u);
    expect(markup).not.toContain('Следующая версия права');
  });

  it.each([false, true])(
    'does not substitute another capability for account-list access: %s',
    (otherCapabilities) => {
      const denied = {
        ...principal,
        administrativeCapabilities: {
          canManageAccounts: false,
          canManageDomainStatus: otherCapabilities,
          canManageFunctionalGrants: otherCapabilities,
          canManagePlatformAdministrators: otherCapabilities,
        },
      };
      const markup = renderToStaticMarkup(
        <AdministrationPanel principal={denied} onSessionInvalid={() => undefined} />,
      );

      expect(markup).toContain('role="alert"');
      expect(markup).toContain('Недостаточно прав для просмотра списка.');
      expect(markup).not.toContain('aria-label="Список пользователей"');
      expect(markup).not.toMatch(/<(?:button|input|select|form)\b/u);
    },
  );
});
