import { HttpException, HttpStatus } from '@nestjs/common';
import type { CorrelationId } from '@kovcheg/contracts';

import { AuthError } from './contracts.js';

const statusByCode: Readonly<Record<AuthError['code'], HttpStatus>> = Object.freeze({
  'auth.conflict': HttpStatus.CONFLICT,
  'auth.forbidden': HttpStatus.FORBIDDEN,
  'auth.invalid-input': HttpStatus.BAD_REQUEST,
  'auth.invalid-or-expired-challenge': HttpStatus.UNAUTHORIZED,
  'auth.invalid-session': HttpStatus.UNAUTHORIZED,
  'auth.not-found': HttpStatus.NOT_FOUND,
  'auth.rate-limited': HttpStatus.TOO_MANY_REQUESTS,
  'auth.unavailable': HttpStatus.SERVICE_UNAVAILABLE,
});

export function authHttpException(
  code: AuthError['code'],
  correlationId: CorrelationId,
): HttpException {
  return new HttpException(Object.freeze({ correlationId, error: code }), statusByCode[code]);
}

export function toAuthHttpException(error: unknown, correlationId: CorrelationId): never {
  if (error instanceof AuthError) {
    throw authHttpException(error.code, correlationId);
  }
  throw error;
}
