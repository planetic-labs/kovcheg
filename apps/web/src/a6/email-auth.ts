interface EmailChallengeResponse {
  readonly email: string;
  readonly next: 'code';
  readonly status: 'accepted';
}

const localEmailPattern = /^[^\s@]+@[^\s@]+$/u;

export function prepareEmailSubmission(value: string): string | null {
  const email = value.trim();
  if (email.length < 3 || email.length > 254 || !localEmailPattern.test(email)) {
    return null;
  }
  return email;
}

export function parseEmailChallengeResponse(value: unknown): EmailChallengeResponse | null {
  if (typeof value !== 'object' || value === null) return null;
  const candidate = value as Readonly<Record<string, unknown>>;
  const email =
    typeof candidate.email === 'string' ? prepareEmailSubmission(candidate.email) : null;
  if (candidate.next !== 'code' || candidate.status !== 'accepted' || email === null) return null;
  return Object.freeze({ email, next: 'code', status: 'accepted' });
}
