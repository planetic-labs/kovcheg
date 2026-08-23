import type { CorrelationId, SessionId, UserId } from '@kovcheg/contracts';

export const applicationSessionAuthenticatorToken = Symbol('applicationSessionAuthenticator');

export interface ApplicationPrincipal {
  readonly sessionId: SessionId;
  readonly userId: UserId;
}

export interface ApplicationSessionAuthenticator {
  authenticate(
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

interface SessionValidationResponse {
  readonly sessionId: SessionId;
  readonly userId: UserId;
}

type RuntimeEnvironment = 'development' | 'production' | 'test';
type Fetch = typeof fetch;

const sessionTokenExpression = /^[A-Za-z0-9_-]{32,512}$/u;
const uuidExpression =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

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

function parsePrincipal(value: unknown): SessionValidationResponse | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Readonly<Record<string, unknown>>;
  if (
    typeof candidate.sessionId !== 'string' ||
    !uuidExpression.test(candidate.sessionId) ||
    typeof candidate.userId !== 'string' ||
    !uuidExpression.test(candidate.userId)
  ) {
    return null;
  }
  return Object.freeze({
    sessionId: candidate.sessionId as SessionId,
    userId: candidate.userId as UserId,
  });
}

function parseValidationUrl(value: string | undefined): URL | null {
  if (value === undefined || value.trim().length === 0) {
    return null;
  }
  try {
    const url = new URL(value);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username !== '' ||
      url.password !== '' ||
      url.search !== '' ||
      url.hash !== '' ||
      url.pathname !== '/session'
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
}

export class HttpApplicationSessionAuthenticator implements ApplicationSessionAuthenticator {
  constructor(
    private readonly environment: RuntimeEnvironment,
    private readonly validationUrl: URL,
    private readonly fetchImplementation: Fetch = fetch,
  ) {}

  async authenticate(
    cookieHeader: string | undefined,
    correlationId: CorrelationId,
  ): Promise<ApplicationPrincipal> {
    const sessionCookie = parseSessionCookie(cookieHeader, this.environment);
    if (sessionCookie === null) {
      throw new ApplicationSessionError('unauthenticated');
    }

    let response: Response;
    try {
      response = await this.fetchImplementation(this.validationUrl, {
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
  const validationUrl = parseValidationUrl(source.AUTH_SESSION_VALIDATION_URL);
  return validationUrl === null
    ? new UnavailableApplicationSessionAuthenticator()
    : new HttpApplicationSessionAuthenticator(environment, validationUrl, fetchImplementation);
}
