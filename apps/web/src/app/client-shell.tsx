'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';

import { parseSessionPrincipal } from '../a6/contracts';
import type { SessionPrincipal } from '../a6/contracts';
import { parseEmailChallengeResponse, prepareEmailSubmission } from '../a6/email-auth';
import {
  attemptConditionalPasskey,
  cancelPasskeyCeremony,
  registerPasskey,
} from '../a6/passkey-client';
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
  onAuthenticated,
  sessionExpired,
  sessionUnavailable,
}: Readonly<{
  onAuthenticated: () => Promise<void>;
  sessionExpired: boolean;
  sessionUnavailable: boolean;
}>) {
  const [step, setStep] = useState<'code' | 'email'>('email');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [emailFallbackChosen, setEmailFallbackChosen] = useState(false);
  const [submittedEmail, setSubmittedEmail] = useState('');
  const [statusNotice, setStatusNotice] = useState('');
  const [codeInputKey, setCodeInputKey] = useState(0);
  const emailInput = useRef<HTMLInputElement>(null);
  const conditionalPasskeyStarted = useRef(false);
  const verifyingCode = useRef(false);
  const statusId = 'authentication-status';

  useEffect(() => {
    if (conditionalPasskeyStarted.current) return;
    conditionalPasskeyStarted.current = true;
    void attemptConditionalPasskey().then(async (result) => {
      if (result === 'authenticated') await onAuthenticated();
    });
  }, [onAuthenticated]);

  async function requestCodeFor(value: string, resend = false): Promise<void> {
    const preparedEmail = prepareEmailSubmission(value);
    if (preparedEmail === null) {
      setError('Проверьте формат email.');
      setStatusNotice('');
      if (!resend) setStep('email');
      return;
    }
    setBusy(true);
    setError(null);
    setStatusNotice('');
    try {
      const response = await fetch('/bff/auth/challenge', {
        body: JSON.stringify({ email: preparedEmail }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      const payload = response.ok ? parseEmailChallengeResponse(await jsonOrNull(response)) : null;
      if (payload === null) throw new Error('challenge-unavailable');
      setEmail(payload.email);
      setSubmittedEmail(payload.email);
      setCodeInputKey((current) => current + 1);
      setStep('code');
      if (resend) setStatusNotice('Запрос обработан. Введите новый код.');
    } catch {
      setError('Не удалось отправить запрос. Проверьте соединение и попробуйте снова.');
      if (!resend) setStep('email');
    } finally {
      setBusy(false);
    }
  }

  async function requestCode(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setEmailFallbackChosen(true);
    cancelPasskeyCeremony();
    await requestCodeFor(email);
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
        setError('Код не подошёл или устарел. Запросите новый код.');
        return;
      }
      setStatusNotice('Входим…');
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
            : 'Проверяем код.'
          : statusNotice);
  const authState = error !== null || sessionUnavailable ? 'error' : busy ? 'busy' : 'ready';

  return (
    <main className="login-layout">
      <section aria-label="Вход" className="login-card">
        {step === 'email' && (
          <form
            aria-busy={busy}
            className="auth-control"
            data-state={authState}
            onSubmit={(event) => void requestCode(event)}
          >
            <label className="visually-hidden" htmlFor="email">
              Email
            </label>
            <input
              aria-describedby={statusId}
              aria-invalid={authState === 'error'}
              autoComplete={emailFallbackChosen ? 'email' : 'username webauthn'}
              autoFocus
              disabled={busy}
              id="email"
              maxLength={254}
              name="email"
              onChange={(event) => {
                setEmail(event.currentTarget.value);
                setError(null);
                setStatusNotice('');
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
                  event.preventDefault();
                  event.currentTarget.form?.requestSubmit();
                }
              }}
              ref={emailInput}
              required
              type="email"
              value={email}
            />
            {email.length > 0 && (
              <button
                aria-label="Продолжить"
                className="auth-arrow auth-next"
                disabled={busy}
                type="submit"
              >
                <span aria-hidden="true">→</span>
              </button>
            )}
          </form>
        )}
        {step === 'code' && (
          <div aria-busy={busy} className="auth-control auth-code" data-state={authState}>
            <p className="auth-email-display">{submittedEmail}</p>
            <CodeInput
              descriptionId={statusId}
              disabled={busy}
              invalid={authState === 'error'}
              key={codeInputKey}
              onChange={updateDigits}
            />
            <button
              aria-label="Вернуться к вводу email"
              className="auth-arrow auth-back"
              disabled={busy}
              onClick={() => {
                setError(null);
                setEmail(submittedEmail);
                setStatusNotice('');
                setStep('email');
                requestAnimationFrame(() => emailInput.current?.focus());
              }}
              type="button"
            >
              <span aria-hidden="true">←</span>
            </button>
            <button
              className="auth-resend"
              disabled={busy}
              onClick={() => void requestCodeFor(submittedEmail, true)}
              type="button"
            >
              Запросить новый код
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
