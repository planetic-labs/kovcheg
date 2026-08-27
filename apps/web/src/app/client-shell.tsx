'use client';

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';

import { parseSessionPrincipal } from '../a6/contracts';
import type { SessionPrincipal } from '../a6/contracts';
import { attemptConditionalPasskey, registerPasskey } from '../a6/passkey-client';
import { AdministrationPanel } from './administration-panel';
import { ChatPanel } from './chat-panel';
import { CodeInput } from './code-input';
import { ProblemReportEntry } from './problem-report-entry';

type SessionState = 'loading' | SessionPrincipal | null;
type WorkspaceView = 'chats' | 'users';

async function jsonOrNull(response: Response): Promise<unknown> {
  return response.json().catch(() => null);
}

export function ClientShell() {
  const [session, setSession] = useState<SessionState>('loading');
  const [sessionError, setSessionError] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const pendingGateCode = useRef<string | null>(null);

  useLayoutEffect(() => {
    const fragment = window.location.hash;
    const parameters = new URLSearchParams(fragment.startsWith('#') ? fragment.slice(1) : fragment);
    pendingGateCode.current = parameters.get('gate');
    if (fragment.length > 0) {
      window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }
  }, []);

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
        <div aria-atomic="true" aria-live="polite" className="loading-card" role="status">
          Подключаем защищённый сеанс…
        </div>
      </main>
    );
  }

  if (session === null) {
    return (
      <LoginPanel
        initialGateCode={pendingGateCode.current}
        onAuthenticated={refreshSession}
        sessionExpired={sessionExpired}
        sessionUnavailable={sessionError}
      />
    );
  }

  return (
    <Workspace
      onLoggedOut={() => {
        setSessionExpired(false);
        setSession(null);
      }}
      onSessionInvalid={() => {
        setSessionExpired(true);
        setSession(null);
      }}
      principal={session}
    />
  );
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
  initialGateCode,
  onAuthenticated,
  sessionExpired,
  sessionUnavailable,
}: Readonly<{
  initialGateCode: string | null;
  onAuthenticated: () => Promise<void>;
  sessionExpired: boolean;
  sessionUnavailable: boolean;
}>) {
  const [step, setStep] = useState<'code' | 'email' | 'gate' | 'loading'>('loading');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const emailInput = useRef<HTMLInputElement>(null);
  const conditionalPasskeyStarted = useRef(false);
  const verifyingCode = useRef(false);
  const statusId = 'authentication-status';
  const volatileClientKey = useRef<string | null>(null);

  function clientIdempotencyKey(): string {
    const storageKey = 'kovcheg-personal-gate-client';
    try {
      const existing = window.localStorage.getItem(storageKey);
      if (existing !== null && /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/u.test(existing)) {
        return existing;
      }
      const created = crypto.randomUUID();
      window.localStorage.setItem(storageKey, created);
      return created;
    } catch {
      volatileClientKey.current ??= crypto.randomUUID();
      return volatileClientKey.current;
    }
  }

  const activateGate = useCallback(async (code: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/bff/auth/gate', {
        body: JSON.stringify({ clientIdempotencyKey: clientIdempotencyKey(), code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      const payload = (await jsonOrNull(response)) as { readonly next?: unknown } | null;
      setStep(response.ok && payload?.next === 'email' ? 'email' : 'gate');
      if (!response.ok) {
        setError('Не удалось проверить доступ. Попробуйте снова.');
      }
    } catch {
      setStep('gate');
      setError('Не удалось проверить доступ. Попробуйте снова.');
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (initialGateCode !== null) {
      void activateGate(initialGateCode);
      return;
    }
    void fetch('/bff/auth/gate', { cache: 'no-store' })
      .then(async (response) => {
        const payload = (await jsonOrNull(response)) as { readonly status?: unknown } | null;
        setStep(response.ok && payload?.status === 'active' ? 'email' : 'gate');
      })
      .catch(() => {
        setStep('gate');
        setError('Не удалось проверить доступ. Попробуйте снова.');
      });
  }, [activateGate, initialGateCode]);

  useEffect(() => {
    if (step === 'loading' || conditionalPasskeyStarted.current) return;
    conditionalPasskeyStarted.current = true;
    void attemptConditionalPasskey().then(async (result) => {
      if (result === 'authenticated') await onAuthenticated();
    });
  }, [onAuthenticated, step]);

  async function submitGate(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get('gateCode') ?? '');
    await activateGate(code);
  }

  async function requestCode(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const submittedEmail = String(new FormData(event.currentTarget).get('email') ?? '');
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/bff/auth/challenge', {
        body: JSON.stringify({ email: submittedEmail }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (response.status === 401) {
        setStep('gate');
        return;
      }
      if (!response.ok) throw new Error('challenge-unavailable');
      const payload = (await jsonOrNull(response)) as { readonly next?: unknown } | null;
      if (payload?.next === 'code') setStep('code');
    } catch {
      setError('Не удалось отправить запрос. Проверьте соединение и попробуйте снова.');
    } finally {
      setBusy(false);
    }
  }

  async function verifyCode(nextDigits: readonly string[]): Promise<void> {
    const code = nextDigits.join('');
    if (!/^\d{6}$/u.test(code)) {
      return;
    }
    if (verifyingCode.current) return;
    verifyingCode.current = true;
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/bff/auth/challenge/verify', {
        body: JSON.stringify({ code }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (!response.ok) {
        if (response.status === 401) setStep('gate');
        setError('Код не подошёл или устарел. Запросите новый код.');
        return;
      }
      await onAuthenticated();
    } catch {
      setError('Не удалось проверить код. Попробуйте снова.');
    } finally {
      verifyingCode.current = false;
      setBusy(false);
    }
  }

  function updateDigits(nextDigits: readonly string[]): void {
    if (nextDigits.every((digit) => /^\d$/u.test(digit))) {
      void verifyCode(nextDigits);
    }
  }

  const statusMessage =
    error ??
    (sessionUnavailable
      ? 'Сервис входа временно недоступен. Попробуйте ещё раз.'
      : sessionExpired
        ? 'Сеанс завершён. Войдите снова.'
        : busy
          ? step === 'email'
            ? 'Проверяем адрес и отправляем код.'
            : step === 'code'
              ? 'Проверяем код.'
              : 'Проверяем доступ.'
          : '');
  const authState = error !== null || sessionUnavailable ? 'error' : busy ? 'busy' : 'ready';

  return (
    <main className="login-layout">
      <section aria-label="Вход" className="login-card">
        <form
          aria-busy={busy}
          className="auth-control"
          data-state={authState}
          hidden={step !== 'gate'}
          onSubmit={(event) => void submitGate(event)}
        >
          <label className="visually-hidden" htmlFor="gate-code">
            Персональный код доступа
          </label>
          <input
            aria-describedby={statusId}
            aria-invalid={authState === 'error'}
            autoComplete="webauthn"
            autoFocus={step === 'gate'}
            disabled={busy}
            id="gate-code"
            inputMode="text"
            maxLength={9}
            name="gateCode"
            pattern="[0-9A-Za-z]{4}-?[0-9A-Za-z]{4}"
            required
            spellCheck={false}
            type="text"
          />
        </form>
        <form
          aria-busy={busy}
          className="auth-control"
          data-state={authState}
          hidden={step !== 'email'}
          onSubmit={(event) => void requestCode(event)}
        >
          <label className="visually-hidden" htmlFor="email">
            Email
          </label>
          <input
            aria-describedby={statusId}
            aria-invalid={authState === 'error'}
            autoComplete="username webauthn"
            autoFocus={step === 'email'}
            disabled={busy}
            id="email"
            maxLength={254}
            name="email"
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
            ref={emailInput}
            required
            type="email"
          />
        </form>
        {step === 'code' && (
          <div aria-busy={busy} className="auth-control" data-state={authState}>
            <CodeInput
              descriptionId={statusId}
              disabled={busy}
              invalid={authState === 'error'}
              onChange={updateDigits}
            />
            <button
              aria-label="Вернуться к вводу email"
              className="auth-back"
              disabled={busy}
              onClick={() => {
                setError(null);
                setStep('email');
                requestAnimationFrame(() => emailInput.current?.focus());
              }}
              type="button"
            >
              <span aria-hidden="true">←</span>
            </button>
          </div>
        )}
        <p
          aria-atomic="true"
          aria-live={authState === 'error' || sessionExpired ? 'assertive' : 'polite'}
          className="visually-hidden"
          id={statusId}
          role="status"
        >
          {statusMessage}
        </p>
      </section>
      <div className="auth-help">
        <ProblemReportEntry
          context={sessionUnavailable ? { errorCode: 'SESSION_UNAVAILABLE' } : undefined}
        />
      </div>
    </main>
  );
}

function Workspace({
  onLoggedOut,
  onSessionInvalid,
  principal,
}: Readonly<{
  onLoggedOut: () => void;
  onSessionInvalid: () => void;
  principal: SessionPrincipal;
}>) {
  const hasAdministrativeAccess = Object.values(principal.administrativeCapabilities).some(Boolean);
  const [view, setView] = useState<WorkspaceView>('chats');
  const [logoutBusy, setLogoutBusy] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyStatus, setPasskeyStatus] = useState('');

  async function addPasskey(): Promise<void> {
    if (passkeyBusy) return;
    setPasskeyBusy(true);
    setPasskeyStatus('');
    const result = await registerPasskey();
    setPasskeyStatus(
      result === 'registered'
        ? 'Passkey добавлен.'
        : result === 'failed'
          ? 'Не удалось добавить passkey.'
          : '',
    );
    setPasskeyBusy(false);
  }

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
      <a className="skip-link" href="#workspace-content">
        К основному содержимому
      </a>
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
        <div className="header-actions">
          <ProblemReportEntry />
          <button
            aria-describedby="passkey-registration-status"
            aria-busy={passkeyBusy}
            className="passkey-button"
            disabled={passkeyBusy}
            onClick={() => void addPasskey()}
            type="button"
          >
            Добавить passkey
          </button>
          <span
            aria-atomic="true"
            aria-live="polite"
            className="visually-hidden"
            id="passkey-registration-status"
            role="status"
          >
            {passkeyStatus}
          </span>
          <button className="session-button" disabled={logoutBusy} onClick={() => void logout()}>
            {logoutBusy ? 'Завершаем…' : 'Завершить сеанс'}
          </button>
        </div>
      </header>
      <div className="workspace-content" id="workspace-content" tabIndex={-1}>
        {view === 'users' && hasAdministrativeAccess ? (
          <AdministrationPanel onSessionInvalid={onSessionInvalid} principal={principal} />
        ) : (
          <ChatPanel onSessionInvalid={onSessionInvalid} principalUserId={principal.userId} />
        )}
      </div>
    </main>
  );
}
