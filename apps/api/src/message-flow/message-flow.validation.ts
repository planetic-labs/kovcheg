import type { CreateTextMessageRequest, UserId, Uuid } from '@kovcheg/contracts';

const uuidExpression = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const clientMessageIdExpression = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const sequenceExpression = /^(0|[1-9][0-9]*)$/;
const maximumSequence = 9_223_372_036_854_775_807n;

export function parseUuid(value: unknown): Uuid | null {
  return typeof value === 'string' && uuidExpression.test(value)
    ? (value.toLowerCase() as Uuid)
    : null;
}

export function parseIdentityHeader(value: unknown): UserId | null {
  return parseUuid(value) as UserId | null;
}

export function parseCreateTextMessageRequest(value: unknown): CreateTextMessageRequest | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  const keys = Object.keys(candidate).sort();
  if (keys.length !== 2 || keys[0] !== 'clientMessageId' || keys[1] !== 'text') {
    return null;
  }
  if (
    typeof candidate.clientMessageId !== 'string' ||
    !clientMessageIdExpression.test(candidate.clientMessageId) ||
    typeof candidate.text !== 'string'
  ) {
    return null;
  }

  const textLength = Array.from(candidate.text).length;
  if (textLength < 1 || textLength > 20_000) {
    return null;
  }

  return Object.freeze({
    clientMessageId: candidate.clientMessageId,
    text: candidate.text,
  });
}

export function parseAfterSequence(value: unknown): string | null {
  const candidate = value ?? '0';
  if (typeof candidate !== 'string' || !sequenceExpression.test(candidate)) {
    return null;
  }

  return BigInt(candidate) <= maximumSequence ? candidate : null;
}

export function parseHistoryLimit(value: unknown): number | null {
  const candidate = value ?? '50';
  if (typeof candidate !== 'string' || !/^[1-9][0-9]*$/.test(candidate)) {
    return null;
  }

  const limit = Number.parseInt(candidate, 10);
  return Number.isSafeInteger(limit) && limit >= 1 && limit <= 100 ? limit : null;
}
