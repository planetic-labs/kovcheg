import { parseCurrentPrincipalAuthorization } from '@kovcheg/contracts';
import type { CorrelationId, CurrentPrincipalAuthorization } from '@kovcheg/contracts';

export const applicationSessionAuthenticatorToken = Symbol('applicationSessionAuthenticator');

export type ApplicationPrincipal = Pick<CurrentPrincipalAuthorization, 'sessionId' | 'userId'>;

export interface ApplicationSessionAuthenticator {
  authenticate(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal>;
  isReady(): Promise<boolean>;
  validate(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal>;
}

export type ApplicationSessionFailure = 'unauthenticated' | 'unavailable';

export class ApplicationSessionError extends Error {
  constructor(readonly failure: ApplicationSessionFailure) {
    super(`Application session authentication failed: ${failure}`);
    this.name = 'ApplicationSessionError';
  }
}

export interface ApplicationSessionEnvironment {
  readonly AUTH_SESSION_VALIDATION_URL?: string | undefined;
}

type RuntimeEnvironment = 'development' | 'production' | 'test';
type Fetch = typeof fetch;

const sessionTokenExpression = /^[A-Za-z0-9_-]{32,512}$/u;
function parseSessionCookie(
  header: string | undefined,
  environment: RuntimeEnvironment,
): string | null {
  const expectedName = environment === 'production' ? '__Host-kovcheg_session' : 'kovcheg_session';
  for (const part of header?.split(';') ?? []) {
    const separator = part.indexOf('=');
    if (separator < 1 || part.slice(0, separator).trim() !== expectedName) {
      continue;
    }
    const token = part.slice(separator + 1).trim();
    return sessionTokenExpression.test(token) ? `${expectedName}=${token}` : null;
  }
  return null;
}

function parsePrincipal(value: unknown): ApplicationPrincipal | null {
  const principal = parseCurrentPrincipalAuthorization(value);
  return principal === null
    ? null
    : Object.freeze({ sessionId: principal.sessionId, userId: principal.userId });
}

function parseValidationUrl(
  value: string | undefined,
  environment: RuntimeEnvironment,
): URL | null {
  if (value === undefined || value.trim().length === 0) return null;
  try {
    const url = new URL(value);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username !== '' ||
      url.password !== '' ||
      url.search !== '' ||
      url.hash !== '' ||
      url.pathname !== '/internal/session'
    ) {
      return null;
    }
    if (
      environment === 'production' &&
      (url.protocol !== 'http:' || url.hostname !== 'auth' || url.port !== '3002')
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

export class UnavailableApplicationSessionAuthenticator implements ApplicationSessionAuthenticator {
  authenticate(): Promise<ApplicationPrincipal> {
    return Promise.reject(new ApplicationSessionError('unavailable'));
  }

  isReady(): Promise<boolean> {
    return Promise.resolve(false);
  }

  validate(): Promise<ApplicationPrincipal> {
    return Promise.reject(new ApplicationSessionError('unavailable'));
  }
}

export class HttpApplicationSessionAuthenticator implements ApplicationSessionAuthenticator {
  private readonly authenticationUrl: URL;
  private readonly readinessUrl: URL;

  constructor(
    private readonly environment: RuntimeEnvironment,
    private readonly validationUrl: URL,
    private readonly fetchImplementation: Fetch = fetch,
  ) {
    this.authenticationUrl = new URL('/session', validationUrl);
    this.readinessUrl = new URL('/health/ready', validationUrl);
  }

  async authenticate(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal> {
    return this.requestPrincipal(this.authenticationUrl, cookieHeader, correlationId);
  }

  async isReady(): Promise<boolean> {
    try {
      const response = await this.fetchImplementation(this.readinessUrl, {
        cache: 'no-store',
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(2_000),
      });
      if (response.status !== 200) return false;
      const body = (await response.json()) as unknown;
      return (
        body !== null &&
        typeof body === 'object' &&
        !Array.isArray(body) &&
        (body as Readonly<Record<string, unknown>>).service === 'auth' &&
        (body as Readonly<Record<string, unknown>>).state === 'ready' &&
        (body as Readonly<Record<string, unknown>>).status === 'ok'
      );
    } catch {
      return false;
    }
  }

  async validate(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal> {
    return this.requestPrincipal(this.validationUrl, cookieHeader, correlationId);
  }

  private async requestPrincipal(
    url: URL,
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal> {
    const sessionCookie = parseSessionCookie(cookieHeader, this.environment);
    if (sessionCookie === null) {
      throw new ApplicationSessionError('unauthenticated');
    }

    let response: Response;
    try {
      response = await this.fetchImplementation(url, {
        cache: 'no-store',
        headers: {
          cookie: sessionCookie,
          'x-correlation-id': correlationId,
        },
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(2_000),
      });
    } catch {
      throw new ApplicationSessionError('unavailable');
    }

    if (response.status === 401 || response.status === 403) {
      throw new ApplicationSessionError('unauthenticated');
    }
    if (response.status !== 200) {
      throw new ApplicationSessionError('unavailable');
    }

    try {
      const principal = parsePrincipal(await response.json());
      if (principal === null) {
        throw new ApplicationSessionError('unavailable');
      }
      return principal;
    } catch (error) {
      if (error instanceof ApplicationSessionError) {
        throw error;
      }
      throw new ApplicationSessionError('unavailable');
    }
  }
}

export function createApplicationSessionAuthenticator(
  environment: RuntimeEnvironment,
  source: ApplicationSessionEnvironment = process.env,
  fetchImplementation: Fetch = fetch,
): ApplicationSessionAuthenticator {
  const validationUrl = parseValidationUrl(source.AUTH_SESSION_VALIDATION_URL, environment);
  if (validationUrl === null) {
    if (environment === 'production') {
      throw new Error('Application session validation configuration is unavailable');
    }
    return new UnavailableApplicationSessionAuthenticator();
  }
  return new HttpApplicationSessionAuthenticator(environment, validationUrl, fetchImplementation);
}
