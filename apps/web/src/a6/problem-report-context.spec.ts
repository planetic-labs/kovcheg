import { describe, expect, it } from 'vitest';

import { normalizeProblemReportContext } from './problem-report-context';

describe('A6 problem-report safe context', () => {
  it('keeps only bounded error and correlation identifiers', () => {
    expect(
      normalizeProblemReportContext({
        correlationId: 'trace_01J6Y8F4J6Q9P7V2',
        errorCode: 'SESSION_UNAVAILABLE',
      }),
    ).toEqual({
      correlationId: 'trace_01J6Y8F4J6Q9P7V2',
      errorCode: 'SESSION_UNAVAILABLE',
    });
  });

  it('drops unknown fields and prohibited raw values', () => {
    expect(
      normalizeProblemReportContext({
        chatId: '00000000-0000-4000-8000-000000000111',
        correlationId: 'https://external.invalid/request',
        email: 'member@example.invalid',
        errorCode: { message: 'raw error' },
        logs: ['raw log'],
        messageId: '00000000-0000-4000-8000-000000000222',
        sessionId: '00000000-0000-4000-8000-000000000333',
        token: 'secret-value',
      }),
    ).toEqual({});
  });

  it('rejects non-record input and unbounded identifiers', () => {
    expect(normalizeProblemReportContext(null)).toEqual({});
    expect(normalizeProblemReportContext(['SESSION_UNAVAILABLE'])).toEqual({});
    expect(normalizeProblemReportContext({ errorCode: `E${'R'.repeat(64)}` })).toEqual({});
  });
});
