import { HttpException, HttpStatus } from '@nestjs/common';

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

export function toAuthHttpException(error: unknown): never {
  if (error instanceof AuthError) {
    throw new HttpException(Object.freeze({ error: error.code }), statusByCode[error.code]);
  }
  throw error;
}
