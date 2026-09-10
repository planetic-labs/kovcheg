'use client';

import { domainStatuses, functionalGrants } from '@kovcheg/contracts';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';

import { parseAccountDetail, parseAccountListPage, parseAccountRecord } from '../a6/contracts';
import type { AccountDetail, AccountListItem, SessionPrincipal } from '../a6/contracts';

type Mutation = (
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE',
  path: string,
  body?: Readonly<Record<string, unknown>>,
) => Promise<void>;

function administrationError(status: number): string {
  if (status === 403) return 'Недостаточно прав для этого действия.';
  if (status === 404) return 'Пользователь больше недоступен.';
  if (status === 409)
    return 'Данные изменились или уже существуют. Обновите карточку и проверьте изменения.';
  if (status === 400) return 'Проверьте введённые данные.';
  return 'Сервис недоступен. Изменения не подтверждены.';
}

const domainLabels = { incubator_participant: 'Участник Инкубатора', disciple: 'Ученик' };
const grantLabels = {
  warrior: 'Воин',
  platform_administrator: 'Администратор платформы',
  chronicler: 'Летописец',
  editor: 'Редактор',
  technical_administrator: 'Технический администратор',
};

export function AdministrationPanel({
  onSessionInvalid,
  principal,
}: Readonly<{ onSessionInvalid: () => void; principal: SessionPrincipal }>) {
  const [items, setItems] = useState<readonly AccountListItem[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [detail, setDetail] = useState<AccountDetail | null>(null);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(false);
  const [listLoaded, setListLoaded] = useState(false);
  const [detailRevision, setDetailRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const selection = useRef(0);
  const listRequest = useRef(0);
  const mounted = useRef(true);
  const allowed = principal.administrativeCapabilities.canManageAccounts;

  const loadList = useCallback(
    async (cursor: string | null = null): Promise<boolean> => {
      const request = ++listRequest.current;
      setLoading(true);
      try {
        const response = await fetch(
          '/bff/admin/accounts?limit=50' +
            (cursor === null ? '' : '&afterAccountId=' + encodeURIComponent(cursor)),
          { cache: 'no-store' },
        );
        if (!mounted.current || request !== listRequest.current) return false;
        if (response.status === 401) {
          onSessionInvalid();
          return false;
        }
        const page = response.ok
          ? parseAccountListPage(await response.json().catch(() => null))
          : null;
        if (!mounted.current || request !== listRequest.current) return false;
        if (page === null) {
          setListLoaded(false);
          if (response.status === 403) {
            setItems([]);
            setDetail(null);
            selection.current++;
          }
          setMessage(administrationError(response.status));
          return false;
        }
        setItems((current) =>
          cursor === null
            ? page.items
            : [...new Map([...current, ...page.items].map((item) => [item.userId, item])).values()],
        );
        setNext(page.nextAfterAccountId);
        setListLoaded(true);
        return true;
      } catch {
        if (mounted.current && request === listRequest.current) {
          setListLoaded(false);
          setMessage(administrationError(503));
        }
        return false;
      } finally {
        if (mounted.current && request === listRequest.current) setLoading(false);
      }
    },
    [onSessionInvalid],
  );

  useEffect(() => {
    mounted.current = true;
    if (allowed) void loadList();
    return () => {
      mounted.current = false;
      selection.current++;
      listRequest.current++;
    };
  }, [allowed, loadList]);

  async function loadDetail(id: string, preserve = false): Promise<boolean> {
    const request = ++selection.current;
    if (!preserve) setDetail(null);
    setCreating(false);
    try {
      const response = await fetch('/bff/admin/accounts/' + encodeURIComponent(id), {
        cache: 'no-store',
      });
      if (!mounted.current || request !== selection.current) return false;
      if (response.status === 401) {
        onSessionInvalid();
        return false;
      }
      const account = response.ok
        ? parseAccountDetail(await response.json().catch(() => null))
        : null;
      if (!mounted.current || request !== selection.current) return false;
      if (account === null || account.userId !== id) {
        if ([403, 404].includes(response.status)) setDetail(null);
        if (response.status === 403) {
          setItems([]);
          setListLoaded(false);
        }
        setMessage(administrationError(response.status));
        return false;
      }
      setDetail(account);
      setDetailRevision((current) => current + 1);
      return true;
    } catch {
      if (mounted.current && request === selection.current) setMessage(administrationError(503));
      return false;
    }
  }

  const run: Mutation = async (method, path, body) => {
    if (busy) return;
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/bff/admin/accounts' + path, {
        method,
        ...(body === undefined
          ? {}
          : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
      });
      if (!mounted.current) return;
      if (response.status === 401) {
        onSessionInvalid();
        return;
      }
      if (!response.ok) {
        if (response.status === 403) {
          setDetail(null);
          setItems([]);
          setListLoaded(false);
        }
        setMessage(administrationError(response.status));
        return;
      }
      const returned = parseAccountRecord(await response.json().catch(() => null));
      const id = returned?.userId ?? detail?.userId;
      const listOk = await loadList();
      const detailOk = id !== undefined && (await loadDetail(id, true));
      if (mounted.current)
        setMessage(
          listOk && detailOk
            ? 'Сохранено и подтверждено сервером.'
            : 'Операция выполнена, но повторное чтение не подтверждено. Обновите данные.',
        );
    } catch {
      if (mounted.current) setMessage(administrationError(503));
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  if (!allowed)
    return (
      <section className="admin-layout">
        <h1>Пользователи</h1>
        <p role="alert">Недостаточно прав для просмотра списка.</p>
      </section>
    );
  return (
    <section className="admin-layout">
      <header className="section-heading">
        <div>
          <p className="eyebrow">Администрирование</p>
          <h1>Пользователи</h1>
        </div>
        <div className="button-row">
          <button
            type="button"
            disabled={busy || loading}
            onClick={() => {
              setMessage('');
              void loadList();
              if (detail !== null) void loadDetail(detail.userId, true);
            }}
          >
            Обновить
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              selection.current++;
              setDetail(null);
              setCreating(true);
              setMessage('');
            }}
          >
            Создать пользователя
          </button>
        </div>
      </header>
      {message !== '' && (
        <p role="status" className="operation-result">
          {message}
        </p>
      )}
      <div className="users-layout">
        <section aria-label="Список пользователей" aria-busy={loading} className="admin-card">
          {loading && items.length === 0 && <p role="status">Загружаем пользователей…</p>}
          {listLoaded && !loading && items.length === 0 && <p>Список не содержит пользователей.</p>}
          <ul className="account-list">
            {items.map((item) => (
              <li key={item.userId}>
                <button
                  type="button"
                  disabled={busy}
                  aria-current={detail?.userId === item.userId ? 'true' : undefined}
                  onClick={() => {
                    setMessage('');
                    void loadDetail(item.userId);
                  }}
                >
                  <strong>{item.displayName}</strong>
                  <span>{item.email}</span>
                  <small>{item.status === 'active' ? 'Активен' : 'Деактивирован'}</small>
                </button>
              </li>
            ))}
          </ul>
          {next !== null && (
            <button type="button" disabled={loading || busy} onClick={() => void loadList(next)}>
              Показать ещё
            </button>
          )}
        </section>
        {creating ? (
          <AccountEditor busy={busy} onSubmit={(body) => void run('POST', '', body)} />
        ) : detail === null ? (
          <p>Выберите пользователя из списка.</p>
        ) : (
          <AccountCard
            key={`${detail.userId}:${detailRevision}`}
            account={detail}
            busy={busy}
            principal={principal}
            run={run}
          />
        )}
      </div>
    </section>
  );
}

function AccountEditor({
  account,
  busy,
  onSubmit,
}: Readonly<{
  account?: AccountDetail;
  busy: boolean;
  onSubmit: (body: { displayName: string; email: string }) => void;
}>) {
  const id = useId();
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    onSubmit({
      displayName: String(data.get('displayName') ?? ''),
      email: String(data.get('email') ?? ''),
    });
  }
  return (
    <form className="admin-card" onSubmit={submit}>
      <h2>{account === undefined ? 'Новый пользователь' : 'Карточка пользователя'}</h2>
      <label htmlFor={`${id}-name`}>Имя</label>
      <input
        id={`${id}-name`}
        name="displayName"
        maxLength={120}
        defaultValue={account?.displayName ?? ''}
        required
      />
      <label htmlFor={`${id}-email`}>Email</label>
      <input
        id={`${id}-email`}
        name="email"
        type="email"
        maxLength={254}
        defaultValue={account?.email ?? ''}
        required
      />
      <button className="secondary-button" disabled={busy} type="submit">
        {account === undefined ? 'Создать' : 'Сохранить имя и email'}
      </button>
    </form>
  );
}

function AccountCard({
  account,
  busy,
  principal,
  run,
}: Readonly<{
  account: AccountDetail;
  busy: boolean;
  principal: SessionPrincipal;
  run: Mutation;
}>) {
  const id = useId();
  const path = '/' + account.userId;
  const caps = principal.administrativeCapabilities;
  const canManageTarget =
    !account.isServerOwner || (principal.isServerOwner && account.userId === principal.userId);
  function authorization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const domainStatus = data.get('domainStatus');
    if (typeof domainStatus === 'string')
      void run('PATCH', path + '/domain-status', {
        domainStatus,
        version: account.nextAuthorizationVersion,
        reason: 'account-management',
      });
  }
  return (
    <div className="account-detail">
      {caps.canManageAccounts && canManageTarget && (
        <AccountEditor
          account={account}
          busy={busy}
          onSubmit={(body) => void run('PATCH', path, body)}
        />
      )}
      <section className="admin-card">
        <h2>Доступ</h2>
        <p>{account.status === 'active' ? 'Активен' : 'Деактивирован'}</p>
        {caps.canManageAccounts && canManageTarget && (
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void run('PATCH', path + '/status', {
                status: account.status === 'active' ? 'deactivated' : 'active',
              })
            }
          >
            {account.status === 'active' ? 'Деактивировать' : 'Активировать'}
          </button>
        )}
        <p>Доменный статус: {domainLabels[account.domainStatus]}</p>
        {caps.canManageDomainStatus && canManageTarget && (
          <form onSubmit={authorization}>
            <label htmlFor={`${id}-domain-status`}>Доменный статус</label>
            <select
              id={`${id}-domain-status`}
              name="domainStatus"
              defaultValue={account.domainStatus}
            >
              {domainStatuses.map((status) => (
                <option key={status} value={status}>
                  {domainLabels[status]}
                </option>
              ))}
            </select>
            <button type="submit" disabled={busy}>
              Сохранить статус
            </button>
          </form>
        )}
      </section>
      <section className="admin-card">
        <h2>Роли и права</h2>
        <ul className="grant-list">
          {functionalGrants.map((grant) => {
            const granted = account.functionalGrants.includes(grant);
            const permitted =
              canManageTarget &&
              caps.canManageFunctionalGrants &&
              (grant !== 'platform_administrator' ||
                (caps.canManagePlatformAdministrators && !account.isServerOwner));
            return (
              <li key={grant}>
                <span>
                  {grantLabels[grant]} — {granted ? 'назначено' : 'не назначено'}
                </span>
                {permitted && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void run(granted ? 'DELETE' : 'PUT', path + '/functional-grants/' + grant, {
                        version: account.nextAuthorizationVersion,
                        reason: 'account-management',
                      })
                    }
                  >
                    {granted ? 'Отозвать' : 'Назначить'} {grantLabels[grant]}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      </section>
      {caps.canManageAccounts && canManageTarget && (
        <section className="admin-card">
          <h2>Сеансы</h2>
          <button
            type="button"
            disabled={busy}
            onClick={() => void run('DELETE', path + '/sessions')}
          >
            Отозвать все сеансы пользователя
          </button>
        </section>
      )}
    </div>
  );
}
