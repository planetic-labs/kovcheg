import { createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto';

import type { SessionId, UserId, Uuid } from '@kovcheg/contracts';

import { AuthError } from './contracts.js';
import type { AuthCrypto, AuthRandomSource, Clock } from './ports.js';

export interface AuthSecretMaterial {
  readonly challengePepper: string;
  readonly personalGatePepper: string;
  readonly rateLimitPepper: string;
  readonly sessionPepper: string;
}

function assertSecret(name: keyof AuthSecretMaterial, value: string): void {
  if (Buffer.byteLength(value, 'utf8') < 32) {
    throw new AuthError('auth.invalid-input', `${name} must contain at least 32 bytes`);
  }
}

function digest(secret: string, namespace: string, value: string): string {
  return createHmac('sha256', secret)
    .update(namespace, 'utf8')
    .update('\0', 'utf8')
    .update(value, 'utf8')
    .digest('base64url');
}

export class HmacAuthCrypto implements AuthCrypto {
  constructor(private readonly secrets: AuthSecretMaterial) {
    assertSecret('challengePepper', secrets.challengePepper);
    assertSecret('personalGatePepper', secrets.personalGatePepper);
    assertSecret('rateLimitPepper', secrets.rateLimitPepper);
    assertSecret('sessionPepper', secrets.sessionPepper);
  }

  challengeCodeVerifier(challengeId: Uuid, code: string): string {
    return digest(this.secrets.challengePepper, 'email-challenge', `${challengeId}\0${code}`);
  }

  personalGateActivationCredentials(normalizedCode: string, clientIdempotencyKey: string) {
    const gateToken = digest(
      this.secrets.personalGatePepper,
      'personal-gate-cookie',
      `${normalizedCode}\0${clientIdempotencyKey}`,
    );
    const identifierBytes = createHmac('sha256', this.secrets.personalGatePepper)
      .update('personal-gate-session\0', 'utf8')
      .update(normalizedCode, 'utf8')
      .update('\0', 'utf8')
      .update(clientIdempotencyKey, 'utf8')
      .digest()
      .subarray(0, 16);
    identifierBytes[6] = ((identifierBytes[6] ?? 0) & 0x0f) | 0x40;
    identifierBytes[8] = ((identifierBytes[8] ?? 0) & 0x3f) | 0x80;
    const hexadecimal = identifierBytes.toString('hex');
    const gateSessionId =
      `${hexadecimal.slice(0, 8)}-${hexadecimal.slice(8, 12)}-${hexadecimal.slice(12, 16)}-${hexadecimal.slice(16, 20)}-${hexadecimal.slice(20)}` as Uuid;
    return Object.freeze({
      gateSessionId,
      gateToken,
      gateTokenVerifier: this.personalGateTokenVerifier(gateToken),
    });
  }

  personalGateCodeVerifier(normalizedCode: string): string {
    return digest(this.secrets.personalGatePepper, 'personal-gate-code', normalizedCode);
  }

  personalGateTokenVerifier(gateToken: string): string {
    return digest(this.secrets.personalGatePepper, 'personal-gate-token', gateToken);
  }

  rateLimitKey(namespace: string, value: string): string {
    return digest(this.secrets.rateLimitPepper, `rate-limit:${namespace}`, value);
  }

  sessionTokenVerifier(sessionToken: string): string {
    return digest(this.secrets.sessionPepper, 'server-session', sessionToken);
  }
}

export class SystemAuthRandomSource implements AuthRandomSource {
  challengeCode(digits: number): string {
    if (!Number.isSafeInteger(digits) || digits < 4 || digits > 9) {
      throw new AuthError('auth.invalid-input', 'Challenge code digits must be from 4 through 9');
    }

    const upperBound = 10 ** digits;
    return randomInt(0, upperBound).toString().padStart(digits, '0');
  }

  opaqueToken(): string {
    return randomBytes(32).toString('base64url');
  }

  personalGateCode(): string {
    const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    return Array.from({ length: 8 }, () => alphabet[randomInt(0, alphabet.length)]).join('');
  }

  sessionId(): SessionId {
    return randomUUID() as SessionId;
  }

  userId(): UserId {
    return randomUUID() as UserId;
  }

  uuid(): Uuid {
    return randomUUID() as Uuid;
  }
}

export const systemClock: Clock = Object.freeze({
  now(): number {
    return Date.now();
  },
});
