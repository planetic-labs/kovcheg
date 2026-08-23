import { Resend } from 'resend';

import { AuthError, normalizeEmail } from './contracts.js';
import type { EmailChallengeMessage } from './contracts.js';
import type { EmailChallengeDelivery } from './ports.js';

interface ResendSendResult {
  readonly data: { readonly id: string } | null;
  readonly error: unknown | null;
}

export interface ResendEmailClient {
  send(
    message: {
      readonly from: string;
      readonly subject: string;
      readonly text: string;
      readonly to: string;
    },
    options: { readonly idempotencyKey: string },
  ): Promise<ResendSendResult>;
}

export type ResendEmailClientFactory = (apiKey: string) => ResendEmailClient;

export interface ResendDeliveryEnvironmentSource {
  readonly AUTH_EMAIL_FROM_ADDRESS?: string | undefined;
  readonly AUTH_EMAIL_FROM_NAME?: string | undefined;
  readonly RESEND_API_KEY?: string | undefined;
}

function unavailable(): AuthError {
  return new AuthError('auth.unavailable', 'Email challenge delivery is unavailable');
}

function required(value: string | undefined): string {
  const normalized = value?.trim();
  if (normalized === undefined || normalized.length === 0) {
    throw unavailable();
  }
  return normalized;
}

function apiKey(value: string | undefined): string {
  const normalized = required(value);
  if (normalized.length < 16 || normalized.length > 512 || /\s/.test(normalized)) {
    throw unavailable();
  }
  return normalized;
}

function senderName(value: string | undefined): string {
  const normalized = required(value).replace(/\s+/g, ' ');
  if (normalized.length > 120 || /[<>\r\n]/.test(normalized)) {
    throw unavailable();
  }
  return normalized;
}

function senderAddress(value: string | undefined): string {
  try {
    return normalizeEmail(required(value));
  } catch {
    throw unavailable();
  }
}

function validateMessage(message: EmailChallengeMessage): void {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      message.challengeId,
    ) ||
    !/^\d{4,9}$/.test(message.code) ||
    !Number.isSafeInteger(message.expiresAt) ||
    message.expiresAt <= 0
  ) {
    throw unavailable();
  }
}

function renderText(message: EmailChallengeMessage): string {
  return [
    'Your one-time sign-in code:',
    '',
    message.code,
    '',
    `This code expires at ${new Date(message.expiresAt).toISOString()}.`,
    'Do not share this code with anyone.',
    'If you did not request this code, ignore this email.',
  ].join('\n');
}

function officialResendClient(apiKeyValue: string): ResendEmailClient {
  const resend = new Resend(apiKeyValue);
  const client: ResendEmailClient = {
    send: async (message, options) => resend.emails.send(message, options),
  };
  return Object.freeze(client);
}

export class ResendEmailChallengeDelivery implements EmailChallengeDelivery {
  readonly productionSafe = true;
  private readonly from: string;

  constructor(
    private readonly client: ResendEmailClient,
    sender: { readonly address: string; readonly name: string },
  ) {
    this.from = `${senderName(sender.name)} <${senderAddress(sender.address)}>`;
  }

  async send(message: EmailChallengeMessage): Promise<void> {
    try {
      validateMessage(message);
      const result = await this.client.send(
        {
          from: this.from,
          subject: 'Your one-time sign-in code',
          text: renderText(message),
          to: normalizeEmail(message.recipient),
        },
        { idempotencyKey: `auth-email-challenge/${message.challengeId}` },
      );
      if (result.error !== null || typeof result.data?.id !== 'string') {
        throw unavailable();
      }
    } catch {
      throw unavailable();
    }
  }
}

export function createResendEmailChallengeDelivery(
  source: ResendDeliveryEnvironmentSource = process.env,
  clientFactory: ResendEmailClientFactory = officialResendClient,
): ResendEmailChallengeDelivery {
  const client = clientFactory(apiKey(source.RESEND_API_KEY));
  return new ResendEmailChallengeDelivery(client, {
    address: senderAddress(source.AUTH_EMAIL_FROM_ADDRESS),
    name: senderName(source.AUTH_EMAIL_FROM_NAME),
  });
}
