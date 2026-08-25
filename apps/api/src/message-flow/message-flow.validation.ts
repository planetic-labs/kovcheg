import type {
  CreateGroupChatRequest,
  CreateTextMessageRequest,
  SetChatAdministratorRequest,
  Uuid,
} from '@kovcheg/contracts';

const uuidExpression = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const clientMessageIdExpression = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const sequenceExpression = /^(0|[1-9][0-9]*)$/;
const maximumSequence = 9_223_372_036_854_775_807n;
const authorizationReasonExpression = /^[a-z][a-z0-9.-]{2,63}$/;

function isExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  return (
    keys.length === expectedKeys.length && keys.every((key, index) => key === expectedKeys[index])
  );
}

export function parseCreateGroupChatRequest(value: unknown): CreateGroupChatRequest | null {
  if (!isExactRecord(value, ['chatId', 'reason'])) return null;
  const chatId = parseUuid(value.chatId);
  if (
    chatId === null ||
    typeof value.reason !== 'string' ||
    !authorizationReasonExpression.test(value.reason)
  ) {
    return null;
  }
  return Object.freeze({ chatId, reason: value.reason });
}

export function parseSetChatAdministratorRequest(
  value: unknown,
): SetChatAdministratorRequest | null {
  if (!isExactRecord(value, ['granted', 'reason', 'version'])) return null;
  if (
    typeof value.granted !== 'boolean' ||
    typeof value.reason !== 'string' ||
    !authorizationReasonExpression.test(value.reason) ||
    typeof value.version !== 'number' ||
    !Number.isSafeInteger(value.version) ||
    value.version < 2
  ) {
    return null;
  }
  return Object.freeze({ granted: value.granted, reason: value.reason, version: value.version });
}

export function parseUuid(value: unknown): Uuid | null {
  return typeof value === 'string' && uuidExpression.test(value)
    ? (value.toLowerCase() as Uuid)
    : null;
}

export function parseCreateTextMessageRequest(value: unknown): CreateTextMessageRequest | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  const keys = Object.keys(candidate).sort();
  const hasPersona = candidate.personaAccountId !== undefined;
  const expectedKeys = hasPersona
    ? ['clientMessageId', 'personaAccountId', 'text']
    : ['clientMessageId', 'text'];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    return null;
  }
  if (
    typeof candidate.clientMessageId !== 'string' ||
    !clientMessageIdExpression.test(candidate.clientMessageId) ||
    (hasPersona &&
      (typeof candidate.personaAccountId !== 'string' ||
        !uuidExpression.test(candidate.personaAccountId))) ||
    typeof candidate.text !== 'string'
  ) {
    return null;
  }

  const textLength = Array.from(candidate.text).length;
  if (textLength < 1 || textLength > 20_000) {
    return null;
  }

  return Object.freeze(
    hasPersona
      ? {
          clientMessageId: candidate.clientMessageId,
          personaAccountId: candidate.personaAccountId as Uuid,
          text: candidate.text,
        }
      : {
          clientMessageId: candidate.clientMessageId,
          text: candidate.text,
        },
  );
}

export function parseAfterSequence(value: unknown): string | null {
  if (typeof value !== 'string' || !sequenceExpression.test(value)) {
    return null;
  }

  return BigInt(value) <= maximumSequence ? value : null;
}

export function parseBeforeSequence(value: unknown): string | null {
  const candidate = parseAfterSequence(value);
  return candidate !== null && candidate !== '0' ? candidate : null;
}

export function parseHistoryLimit(value: unknown): number | null {
  const candidate = value ?? '50';
  if (typeof candidate !== 'string' || !/^[1-9][0-9]*$/.test(candidate)) {
    return null;
  }

  const limit = Number.parseInt(candidate, 10);
  return Number.isSafeInteger(limit) && limit >= 1 && limit <= 100 ? limit : null;
}
