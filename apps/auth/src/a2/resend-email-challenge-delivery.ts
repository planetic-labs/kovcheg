import { readFileSync } from 'node:fs';

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
      readonly html: string;
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
  readonly RESEND_API_KEY_FILE?: string | undefined;
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

function configuredApiKey(source: ResendDeliveryEnvironmentSource): string {
  const inlineValue = source.RESEND_API_KEY?.trim();
  const filePath = source.RESEND_API_KEY_FILE?.trim();
  if (
    inlineValue !== undefined &&
    inlineValue.length > 0 &&
    filePath !== undefined &&
    filePath.length > 0
  ) {
    throw unavailable();
  }
  if (filePath !== undefined && filePath.length > 0) {
    try {
      return apiKey(readFileSync(filePath, 'utf8'));
    } catch {
      throw unavailable();
    }
  }
  return apiKey(inlineValue);
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
    !/^\d{6}$/.test(message.code) ||
    !Number.isSafeInteger(message.issuedAt) ||
    !Number.isSafeInteger(message.expiresAt) ||
    message.issuedAt <= 0 ||
    message.expiresAt <= message.issuedAt
  ) {
    throw unavailable();
  }
}

function renderText(message: EmailChallengeMessage): string {
  return ['ПРОСВЕТЛЕНИЕ РЕАЛЬНО ДЛЯ ТЕБЯ', '', message.code, '', durationText(message)].join('\n');
}

function durationText(message: EmailChallengeMessage): string {
  const milliseconds = message.expiresAt - message.issuedAt;
  const minutes = milliseconds % 60_000 === 0;
  const value = milliseconds / (minutes ? 60_000 : 1_000);
  const plural = new Intl.PluralRules('ru').select(value);
  const unit = minutes
    ? plural === 'one'
      ? 'минуту'
      : plural === 'few' || plural === 'other'
        ? 'минуты'
        : 'минут'
    : plural === 'one'
      ? 'секунду'
      : plural === 'few' || plural === 'other'
        ? 'секунды'
        : 'секунд';
  const formatted = new Intl.NumberFormat('ru', {
    maximumFractionDigits: 3,
    useGrouping: false,
  }).format(value);
  return `Код действует ${formatted} ${unit}`;
}

function renderHtml(message: EmailChallengeMessage): string {
  const duration = durationText(message);
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>Код для входа</title>
<style>
  @media (prefers-color-scheme: dark) {
    .page  { background:#0F1113 !important; }
    .name  { color:#E7EAED !important; }
    .code  { color:#FFFFFF !important; }
    .note  { color:#6E757C !important; }
  }
  [data-ogsc] .name { color:#E7EAED !important; }
  [data-ogsc] .code { color:#FFFFFF !important; }
  [data-ogsc] .note { color:#6E757C !important; }
  @media (max-width:420px) {
    .code { font-size:40px !important; letter-spacing:.16em !important; text-indent:.16em !important; }
    .name { font-size:16px !important; line-height:25px !important; }
    .box  { padding-left:18px !important; padding-right:18px !important; }
  }
</style>
</head>
<body class="page" style="margin:0; padding:0; background:#FFFFFF;">

<div style="display:none; max-height:0; overflow:hidden; opacity:0; mso-hide:all;">${duration}&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;</div>

<table role="presentation" class="page" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#FFFFFF;">
<tr><td align="center" class="box" style="padding:76px 24px 92px 24px;">

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%; max-width:440px;">

    <tr><td class="name" align="center" style="font-family:-apple-system,'Helvetica Neue','Segoe UI',Roboto,Arial,sans-serif; font-weight:400; font-size:19px; line-height:28px; mso-line-height-rule:exactly; letter-spacing:.04em; text-indent:.04em; color:#2A2F34;">
      ПРОСВЕТЛЕНИЕ РЕАЛЬНО<br>ДЛЯ ТЕБЯ
    </td></tr>

    <tr><td height="34" style="height:34px; font-size:0; line-height:0;">&nbsp;</td></tr>

    <tr><td class="code" align="center" style="font-family:-apple-system,'Helvetica Neue','Segoe UI',Roboto,Arial,sans-serif; font-weight:300; font-size:52px; line-height:60px; mso-line-height-rule:exactly; letter-spacing:.22em; text-indent:.22em; color:#16191C;">
      ${message.code.slice(0, 3)}<span style="letter-spacing:.12em"> </span>${message.code.slice(3)}
    </td></tr>

    <tr><td height="34" style="height:34px; font-size:0; line-height:0;">&nbsp;</td></tr>

    <tr><td class="note" align="center" style="font-family:-apple-system,'Helvetica Neue','Segoe UI',Roboto,Arial,sans-serif; font-weight:400; font-size:13px; line-height:20px; letter-spacing:.02em; color:#AEB4B9;">
      ${duration}
    </td></tr>

  </table>

</td></tr>
</table>
</body>
</html>
`;
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
          html: renderHtml(message),
          subject: `Код для входа: ${message.code}`,
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
  const client = clientFactory(configuredApiKey(source));
  return new ResendEmailChallengeDelivery(client, {
    address: senderAddress(source.AUTH_EMAIL_FROM_ADDRESS),
    name: senderName(source.AUTH_EMAIL_FROM_NAME),
  });
}
