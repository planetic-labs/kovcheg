import { AuthError, personalGateLifetimeMs } from './contracts.js';

const personalGateCookieName = '__Host-kovcheg_gate';

function readCookies(header: string | undefined): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const part of header?.split(';') ?? []) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name.length > 0 && !cookies.has(name)) cookies.set(name, value);
  }
  return cookies;
}

export class PersonalGateCookie {
  readonly name = personalGateCookieName;

  clear(): string {
    return this.serialize('', 0);
  }

  issue(gateToken: string): string {
    if (!/^[A-Za-z0-9_-]{43}$/u.test(gateToken)) {
      throw new AuthError('auth.invalid-input', 'Personal gate token has an invalid shape');
    }
    return this.serialize(gateToken, Math.ceil(personalGateLifetimeMs / 1000));
  }

  read(header: string | undefined): string | null {
    const token = readCookies(header).get(this.name);
    return token !== undefined && /^[A-Za-z0-9_-]{43}$/u.test(token) ? token : null;
  }

  private serialize(value: string, maxAge: number): string {
    return [
      `${this.name}=${value}`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
    ].join('; ');
  }
}
