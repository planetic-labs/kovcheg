import { AuthError } from './contracts.js';

export interface SessionCookieOptions {
  readonly absoluteLifetimeMs: number;
  readonly environment: 'development' | 'production' | 'test';
  readonly secure: boolean;
}

function parseCookieHeader(header: string | undefined): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const part of header?.split(';') ?? []) {
    const separator = part.indexOf('=');
    if (separator < 1) {
      continue;
    }
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name.length > 0 && !cookies.has(name)) {
      cookies.set(name, value);
    }
  }
  return cookies;
}

export class SessionCookie {
  readonly name: string;
  private readonly maxAgeSeconds: number;

  constructor(private readonly options: SessionCookieOptions) {
    if (!Number.isSafeInteger(options.absoluteLifetimeMs) || options.absoluteLifetimeMs <= 0) {
      throw new AuthError('auth.invalid-input', 'Session cookie lifetime must be positive');
    }
    if (options.environment === 'production' && !options.secure) {
      throw new AuthError('auth.invalid-input', 'Production session cookies must be secure');
    }
    this.name = options.secure ? '__Host-kovcheg_session' : 'kovcheg_session';
    this.maxAgeSeconds = Math.ceil(options.absoluteLifetimeMs / 1000);
  }

  clear(): string {
    return this.serialize('', 0);
  }

  issue(sessionToken: string): string {
    if (!/^[A-Za-z0-9_-]{32,512}$/.test(sessionToken)) {
      throw new AuthError('auth.invalid-input', 'Session token has an invalid shape');
    }
    return this.serialize(sessionToken, this.maxAgeSeconds);
  }

  read(header: string | undefined): string | null {
    const token = parseCookieHeader(header).get(this.name);
    return token !== undefined && /^[A-Za-z0-9_-]{32,512}$/.test(token) ? token : null;
  }

  private serialize(value: string, maxAge: number): string {
    return [
      `${this.name}=${value}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAge}`,
      ...(this.options.secure ? ['Secure'] : []),
    ].join('; ');
  }
}
