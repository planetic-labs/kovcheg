'use client';

import type { OwnPasskeySettings } from '../a6/contracts';

export function PasskeySettingsPanel({
  settings,
  busy,
  status,
  onRefresh,
  onAdd,
  onRevoke,
}: Readonly<{
  settings: OwnPasskeySettings | null;
  busy: boolean;
  status: string;
  onRefresh: () => void;
  onAdd: () => void;
  onRevoke: (id: string) => void;
}>) {
  return (
    <section className="admin-layout">
      <header className="section-heading">
        <h1>Настройки</h1>
      </header>
      <section className="admin-card">
        <h2>Ключи доступа</h2>
        <p role="status">{status}</p>
        {settings === null ? (
          <p>Данные ключей пока не получены.</p>
        ) : (
          <>
            <p>Активных ключей: {settings.activePasskeyCount}</p>
            <ul className="passkey-list">
              {settings.activePasskeys.map((key, index) => (
                <li key={key.id}>
                  <div>
                    <strong>Ключ доступа {index + 1}</strong>
                    <p>
                      Добавлен:{' '}
                      <time dateTime={key.createdAt}>
                        {new Date(key.createdAt).toLocaleDateString('ru-RU', { timeZone: 'UTC' })}
                      </time>
                    </p>
                    {key.lastUsedAt !== null && (
                      <p>
                        Последний вход:{' '}
                        <time dateTime={key.lastUsedAt}>
                          {new Date(key.lastUsedAt).toLocaleDateString('ru-RU', {
                            timeZone: 'UTC',
                          })}
                        </time>
                      </p>
                    )}
                  </div>
                  <button type="button" disabled={busy} onClick={() => onRevoke(key.id)}>
                    Отозвать ключ {index + 1}
                  </button>
                </li>
              ))}
            </ul>
            {settings.activePasskeyCount === 0 && (
              <p>Для входа остаётся email с одноразовым кодом.</p>
            )}
          </>
        )}
        <div className="button-row">
          <button type="button" disabled={busy} onClick={onRefresh}>
            Обновить ключи
          </button>
          <button type="button" disabled={busy || settings === null} onClick={onAdd}>
            Добавить passkey
          </button>
        </div>
      </section>
    </section>
  );
}
