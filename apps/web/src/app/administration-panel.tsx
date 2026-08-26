'use client';

import { domainStatuses, functionalGrants } from '@kovcheg/contracts';
import type { FunctionalGrant } from '@kovcheg/contracts';
import { useState } from 'react';
import type { FormEvent } from 'react';

import { parseAccountRecord } from '../a6/contracts';
import type { AccountRecord, SessionPrincipal } from '../a6/contracts';

async function jsonOrNull(response: Response): Promise<unknown> {
  return response.json().catch(() => null);
}

export function AdministrationPanel({
  onSessionInvalid,
  principal,
}: Readonly<{ onSessionInvalid: () => void; principal: SessionPrincipal }>) {
  const [result, setResult] = useState<AccountRecord | string | null>(null);
  const [busy, setBusy] = useState(false);
  const capabilities = principal.administrativeCapabilities;

  async function run(
    method: 'DELETE' | 'PATCH' | 'POST' | 'PUT',
    path: string,
    body?: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    setBusy(true);
    setResult(null);
    try {
      const response = await fetch(`/bff/admin/accounts${path}`, {
        ...(body === undefined
          ? {}
          : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
        method,
      });
      if (response.status === 401) {
        onSessionInvalid();
        return;
      }
      const payload = await jsonOrNull(response);
      if (!response.ok) {
        setResult('Операция не выполнена. Проверьте право, версию и введённые данные.');
        return;
      }
      setResult(parseAccountRecord(payload) ?? 'Операция выполнена.');
    } catch {
      setResult('Сервис управления пользователями временно недоступен.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="admin-layout">
      <header className="section-heading">
        <div>
          <p className="eyebrow">Администрирование</p>
          <h1>Пользователи</h1>
        </div>
        <p>Действия доступны только по подтверждённым сервером административным правам.</p>
      </header>

      <div className="admin-grid">
        {capabilities.canManageAccounts && (
          <>
            <AccountForm
              busy={busy}
              mode="create"
              onSubmit={({ displayName, email }) => void run('POST', '', { displayName, email })}
            />
            <AccountForm
              busy={busy}
              mode="update"
              onSubmit={({ accountId, ...input }) => void run('PATCH', `/${accountId}`, input)}
            />
            <StatusForm
              busy={busy}
              onSubmit={(accountId, status) =>
                void run('PATCH', `/${accountId}/status`, { status })
              }
            />
            <SessionRevocationForm
              busy={busy}
              onRevokeAll={(accountId) => void run('DELETE', `/${accountId}/sessions`)}
              onRevokeOne={(accountId, sessionId) =>
                void run('DELETE', `/${accountId}/sessions/${sessionId}`)
              }
            />
          </>
        )}
        {capabilities.canManageDomainStatus && (
          <DomainStatusForm
            busy={busy}
            onSubmit={(accountId, domainStatus, reason, version) =>
              void run('PATCH', `/${accountId}/domain-status`, {
                domainStatus,
                reason,
                version,
              })
            }
          />
        )}
        {capabilities.canManageFunctionalGrants && (
          <FunctionalGrantForm
            allowPlatformAdministrator={capabilities.canManagePlatformAdministrators}
            busy={busy}
            onSubmit={(accountId, grant, granted, reason, version) =>
              void run(granted ? 'PUT' : 'DELETE', `/${accountId}/functional-grants/${grant}`, {
                reason,
                version,
              })
            }
          />
        )}
      </div>
      {result !== null && <OperationResult result={result} />}
    </section>
  );
}

type AccountFormInput = Readonly<{ accountId: string; displayName: string; email: string }>;

function AccountForm({
  busy,
  mode,
  onSubmit,
}: Readonly<{
  busy: boolean;
  mode: 'create' | 'update';
  onSubmit: (input: AccountFormInput) => void;
}>) {
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    onSubmit({
      accountId: String(data.get('accountId') ?? ''),
      displayName: String(data.get('displayName') ?? ''),
      email: String(data.get('email') ?? ''),
    });
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>{mode === 'create' ? 'Создать пользователя' : 'Изменить пользователя'}</h2>
      {mode === 'update' && <Field label="ID пользователя" name="accountId" required />}
      <Field label="Имя" maxLength={120} name="displayName" required />
      <Field label="Email" maxLength={254} name="email" required type="email" />
      <button className="secondary-button" disabled={busy} type="submit">
        {mode === 'create' ? 'Создать' : 'Сохранить'}
      </button>
    </form>
  );
}

function StatusForm({
  busy,
  onSubmit,
}: Readonly<{
  busy: boolean;
  onSubmit: (accountId: string, status: 'active' | 'deactivated') => void;
}>) {
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const status = data.get('status');
    if (status === 'active' || status === 'deactivated') {
      onSubmit(String(data.get('accountId') ?? ''), status);
    }
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>Статус доступа</h2>
      <Field label="ID пользователя" name="accountId" required />
      <label htmlFor="account-status">Статус</label>
      <select defaultValue="active" id="account-status" name="status">
        <option value="active">Активен</option>
        <option value="deactivated">Деактивирован</option>
      </select>
      <button className="secondary-button" disabled={busy} type="submit">
        Применить
      </button>
    </form>
  );
}

function DomainStatusForm({
  busy,
  onSubmit,
}: Readonly<{
  busy: boolean;
  onSubmit: (accountId: string, status: string, reason: string, version: number) => void;
}>) {
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    onSubmit(
      String(data.get('accountId') ?? ''),
      String(data.get('domainStatus') ?? ''),
      String(data.get('reason') ?? ''),
      Number(data.get('version')),
    );
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>Доменный статус</h2>
      <Field label="ID пользователя" name="accountId" required />
      <label htmlFor="domain-status">Новый статус</label>
      <select defaultValue={domainStatuses[0]} id="domain-status" name="domainStatus">
        {domainStatuses.map((status) => (
          <option key={status} value={status}>
            {status}
          </option>
        ))}
      </select>
      <AuthorizationFields />
      <button className="secondary-button" disabled={busy} type="submit">
        Изменить статус
      </button>
    </form>
  );
}

function FunctionalGrantForm({
  allowPlatformAdministrator,
  busy,
  onSubmit,
}: Readonly<{
  allowPlatformAdministrator: boolean;
  busy: boolean;
  onSubmit: (
    accountId: string,
    grant: FunctionalGrant,
    granted: boolean,
    reason: string,
    version: number,
  ) => void;
}>) {
  const available = functionalGrants.filter(
    (grant) => grant !== 'platform_administrator' || allowPlatformAdministrator,
  );
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const grant = data.get('grant');
    if (!functionalGrants.includes(grant as FunctionalGrant)) return;
    onSubmit(
      String(data.get('accountId') ?? ''),
      grant as FunctionalGrant,
      data.get('operation') === 'grant',
      String(data.get('reason') ?? ''),
      Number(data.get('version')),
    );
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>Функциональное право</h2>
      <Field label="ID пользователя" name="accountId" required />
      <label htmlFor="functional-grant">Право</label>
      <select defaultValue={available[0]} id="functional-grant" name="grant">
        {available.map((grant) => (
          <option key={grant} value={grant}>
            {grant}
          </option>
        ))}
      </select>
      <label htmlFor="grant-operation">Операция</label>
      <select defaultValue="grant" id="grant-operation" name="operation">
        <option value="grant">Назначить</option>
        <option value="revoke">Отозвать</option>
      </select>
      <AuthorizationFields />
      <button className="secondary-button" disabled={busy} type="submit">
        Применить право
      </button>
    </form>
  );
}

function AuthorizationFields() {
  return (
    <>
      <Field label="Причина" maxLength={64} name="reason" required />
      <label htmlFor="authorization-version">Следующая версия права</label>
      <input id="authorization-version" min={2} name="version" required type="number" />
    </>
  );
}

function SessionRevocationForm({
  busy,
  onRevokeAll,
  onRevokeOne,
}: Readonly<{
  busy: boolean;
  onRevokeAll: (accountId: string) => void;
  onRevokeOne: (accountId: string, sessionId: string) => void;
}>) {
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    onRevokeOne(String(data.get('accountId') ?? ''), String(data.get('sessionId') ?? ''));
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>Отозвать сеансы</h2>
      <Field label="ID пользователя" name="accountId" required />
      <Field label="ID одного сеанса" name="sessionId" required />
      <div className="button-row">
        <button className="secondary-button" disabled={busy} type="submit">
          Отозвать один
        </button>
        <button
          className="danger-button"
          disabled={busy}
          onClick={(event) => {
            const accountId = event.currentTarget.form?.elements.namedItem('accountId');
            if (accountId instanceof HTMLInputElement && accountId.value.length > 0) {
              onRevokeAll(accountId.value);
            }
          }}
          type="button"
        >
          Отозвать все
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  maxLength,
  name,
  required,
  type = 'text',
}: Readonly<{
  label: string;
  maxLength?: number;
  name: string;
  required?: boolean;
  type?: 'email' | 'text';
}>) {
  const id = `field-${name}-${label.replace(/\s+/gu, '-').toLowerCase()}`;
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input id={id} maxLength={maxLength} name={name} required={required} type={type} />
    </>
  );
}

function OperationResult({ result }: Readonly<{ result: AccountRecord | string }>) {
  if (typeof result === 'string') {
    return (
      <p aria-live="polite" className="operation-result">
        {result}
      </p>
    );
  }
  return (
    <dl aria-live="polite" className="operation-result result-grid">
      <div>
        <dt>Пользователь</dt>
        <dd>{result.displayName}</dd>
      </div>
      <div>
        <dt>Статус</dt>
        <dd>{result.status === 'active' ? 'Активен' : 'Деактивирован'}</dd>
      </div>
      <div>
        <dt>Доменный статус</dt>
        <dd>{result.domainStatus}</dd>
      </div>
      <div>
        <dt>Права</dt>
        <dd>{result.functionalGrants.join(', ') || 'Нет'}</dd>
      </div>
      <div>
        <dt>ID</dt>
        <dd>{result.userId}</dd>
      </div>
    </dl>
  );
}
