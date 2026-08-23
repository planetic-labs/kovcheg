'use client';

import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';

import { parseSessionPrincipal } from '../a6/contracts';
import type { SessionPrincipal } from '../a6/contracts';
import { AdministrationPanel } from './administration-panel';
import { ChatPanel } from './chat-panel';
import { CodeInput } from './code-input';

type SessionState = 'loading' | SessionPrincipal | null;
type WorkspaceView = 'chats' | 'users';

async function jsonOrNull(response: Response): Promise<unknown> {
  return response.json().catch(() => null);
}

export function ClientShell() {
  const [session, setSession] = useState<SessionState>('loading');
  const [sessionError, setSessionError] = useState(false);

  const refreshSession = useCallback(async () => {
    setSessionError(false);
    try {
      const response = await fetch('/bff/session', { cache: 'no-store' });
      if (response.status === 401) {
        setSession(null);
        return;
      }
      const principal = response.ok ? parseSessionPrincipal(await jsonOrNull(response)) : null;
      if (principal === null) {
        setSessionError(response.status >= 500);
        setSession(null);
        return;
      }
      setSession(principal);
    } catch {
      setSessionError(true);
      setSession(null);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  if (session === 'loading') {
    return (
      <main className="center-stage">
        <div aria-live="polite" className="loading-card">
          Подключаем защищённый сеанс…
        </div>
      </main>
    );
  }

  if (session === null) {
    return <LoginPanel onAuthenticated={refreshSession} sessionUnavailable={sessionError} />;
  }

  return <Workspace principal={session} onLoggedOut={() => setSession(null)} />;
}

function Brand() {
  return (
    <div className="brand" aria-label="Ковчег">
      <span className="brand-mark" aria-hidden="true">
        К
      </span>
      <span>
        <strong>Ковчег</strong>
        <small>закрытое пространство</small>
      </span>
    </div>
  );
}

function LoginPanel({
  onAuthenticated,
  sessionUnavailable,
}: Readonly<{ onAuthenticated: () => Promise<void>; sessionUnavailable: boolean }>) {
  const [step, setStep] = useState<'code' | 'email'>('email');
  const [email, setEmail] = useState('');
  const [digits, setDigits] = useState<readonly string[]>(Object.freeze(Array(6).fill('')));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function requestCode(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/bff/auth/challenge', {
        body: JSON.stringify({ email }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (!response.ok) throw new Error('challenge-unavailable');
      setStep('code');
    } catch {
      setError('Не удалось отправить запрос. Проверьте соединение и попробуйте снова.');
    } finally {
      setBusy(false);
    }
  }

  async function verifyCode(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const code = digits.join('');
    if (!/^\d{6}$/u.test(code)) {
      setError('Введите все шесть цифр кода.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/bff/auth/challenge/verify', {
        body: JSON.stringify({ code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (!response.ok) {
        setError('Код не подошёл или устарел. Запросите новый код.');
        return;
      }
      await onAuthenticated();
    } catch {
      setError('Не удалось проверить код. Попробуйте снова.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-layout">
      <section className="login-intro">
        <Brand />
        <div>
          <p className="eyebrow">Минимальный PWA-клиент</p>
          <h1>Разговоры группы в одном спокойном пространстве</h1>
          <p className="lead">
            Вход доступен только заранее созданным активным участникам. Паролей и саморегистрации
            нет.
          </p>
        </div>
        <p className="security-note">Сеанс хранится только в защищённой HTTP-only cookie.</p>
      </section>

      <section aria-labelledby="login-title" className="login-card">
        <p className="step-label">{step === 'email' ? 'Шаг 1 из 2' : 'Шаг 2 из 2'}</p>
        <h2 id="login-title">{step === 'email' ? 'Войти по email' : 'Введите код'}</h2>
        {step === 'email' ? (
          <form onSubmit={(event) => void requestCode(event)}>
            <label htmlFor="email">Email</label>
            <input
              autoComplete="email"
              id="email"
              maxLength={254}
              onChange={(event) => setEmail(event.currentTarget.value)}
              placeholder="name@example.com"
              required
              type="email"
              value={email}
            />
            <button className="primary-button" disabled={busy} type="submit">
              {busy ? 'Отправляем…' : 'Получить код'}
            </button>
            <p className="neutral-copy">
              Если аккаунт активен, шестизначный код придёт на указанную почту.
            </p>
          </form>
        ) : (
          <form onSubmit={(event) => void verifyCode(event)}>
            <p className="neutral-copy">
              Если аккаунт активен, письмо уже отправлено. Ответ одинаков для любого email.
            </p>
            <CodeInput disabled={busy} onChange={setDigits} />
            <button className="primary-button" disabled={busy} type="submit">
              {busy ? 'Проверяем…' : 'Продолжить'}
            </button>
            <button
              className="text-button"
              disabled={busy}
              onClick={() => {
                setDigits(Object.freeze(Array(6).fill('')));
                setError(null);
                setStep('email');
              }}
              type="button"
            >
              Указать другой email
            </button>
          </form>
        )}
        {(sessionUnavailable || error !== null) && (
          <p aria-live="polite" className="error-banner">
            {error ?? 'Сервис входа временно недоступен. Попробуйте ещё раз.'}
          </p>
        )}
      </section>
    </main>
  );
}

function Workspace({
  onLoggedOut,
  principal,
}: Readonly<{ onLoggedOut: () => void; principal: SessionPrincipal }>) {
  const hasAdministrativeAccess = Object.values(principal.administrativeCapabilities).some(Boolean);
  const [view, setView] = useState<WorkspaceView>('chats');
  const [logoutBusy, setLogoutBusy] = useState(false);

  async function logout(): Promise<void> {
    setLogoutBusy(true);
    try {
      const response = await fetch('/bff/session', { method: 'DELETE' });
      if (response.ok) onLoggedOut();
    } finally {
      setLogoutBusy(false);
    }
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <Brand />
        <nav aria-label="Основная навигация" className="main-nav">
          <button
            aria-current={view === 'chats' ? 'page' : undefined}
            onClick={() => setView('chats')}
            type="button"
          >
            Чаты
          </button>
          {hasAdministrativeAccess && (
            <button
              aria-current={view === 'users' ? 'page' : undefined}
              onClick={() => setView('users')}
              type="button"
            >
              Пользователи
            </button>
          )}
        </nav>
        <button className="session-button" disabled={logoutBusy} onClick={() => void logout()}>
          {logoutBusy ? 'Завершаем…' : 'Завершить сеанс'}
        </button>
      </header>
      {view === 'users' && hasAdministrativeAccess ? (
        <AdministrationPanel onSessionInvalid={onLoggedOut} principal={principal} />
      ) : (
        <ChatPanel onSessionInvalid={onLoggedOut} principalUserId={principal.userId} />
      )}
    </main>
  );
}
