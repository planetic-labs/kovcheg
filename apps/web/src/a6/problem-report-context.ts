export interface SafeProblemReportContext {
  readonly correlationId?: string;
  readonly errorCode?: string;
}

const errorCodePattern = /^[A-Z0-9][A-Z0-9._:-]{0,63}$/u;
const correlationIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function safeString(value: unknown, pattern: RegExp): string | undefined {
  return typeof value === 'string' && pattern.test(value) ? value : undefined;
}

export function normalizeProblemReportContext(value: unknown): SafeProblemReportContext {
  if (!isRecord(value)) return Object.freeze({});

  const correlationId = safeString(value.correlationId, correlationIdPattern);
  const errorCode = safeString(value.errorCode, errorCodePattern);

  return Object.freeze({
    ...(correlationId === undefined ? {} : { correlationId }),
    ...(errorCode === undefined ? {} : { errorCode }),
  });
}
