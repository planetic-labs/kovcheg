import { describe, expect, it, vi } from 'vitest';

import type { EmailChallengeMessage } from './contracts.js';
import {
  createResendEmailChallengeDelivery,
  ResendEmailChallengeDelivery,
} from './resend-email-challenge-delivery.js';
import type {
  ResendEmailClient,
  ResendEmailClientFactory,
} from './resend-email-challenge-delivery.js';

const message: EmailChallengeMessage = Object.freeze({
  challengeId: '00000000-0000-4000-8000-000000000081',
  code: '483920',
  expiresAt: Date.UTC(2031, 0, 1, 0, 10),
  issuedAt: Date.UTC(2031, 0, 1),
  recipient: 'recipient@auth.invalid',
});

function successfulClient() {
  const send = vi.fn<ResendEmailClient['send']>(() =>
    Promise.resolve({ data: { id: 'synthetic-email-id' }, error: null }),
  );
  return { client: Object.freeze({ send }), send };
}

describe('A2 Resend email challenge delivery', () => {
  it('sends a synthetic one-time code through the provider-neutral port', async () => {
    const fixture = successfulClient();
    const delivery = new ResendEmailChallengeDelivery(fixture.client, {
      address: 'sender@auth.invalid',
      name: 'Synthetic Auth Sender',
    });

    await delivery.send(message);

    expect(delivery.productionSafe).toBe(true);
    expect(fixture.send).toHaveBeenCalledWith(
      {
        from: 'Synthetic Auth Sender <sender@auth.invalid>',
        html: expect.stringContaining('483<span style="letter-spacing:.12em"> </span>920'),
        subject: 'Код для входа: 483920',
        text: expect.stringContaining(message.code),
        to: 'recipient@auth.invalid',
      },
      { idempotencyKey: `auth-email-challenge/${message.challengeId}` },
    );
  });

  it('renders only the name, actual code and duration with responsive light/dark styling', async () => {
    const fixture = successfulClient();
    const delivery = new ResendEmailChallengeDelivery(fixture.client, {
      address: 'sender@auth.invalid',
      name: 'Synthetic Auth Sender',
    });
    await delivery.send(message);
    const sent = fixture.send.mock.calls[0]?.[0];
    expect(sent).toBeDefined();
    expect(sent?.text).toBe('ПРОСВЕТЛЕНИЕ РЕАЛЬНО ДЛЯ ТЕБЯ\n\n483920\n\nКод действует 10 минут');
    expect(sent?.html).toContain('ПРОСВЕТЛЕНИЕ РЕАЛЬНО<br>ДЛЯ ТЕБЯ');
    expect(sent?.html.match(/Код действует 10 минут/gu)).toHaveLength(2);
    expect(sent?.html).toContain('padding:76px 24px 92px 24px');
    expect(sent?.html).toContain('width:100%; max-width:440px;');
    expect(sent?.html.match(/height="34"/gu)).toHaveLength(2);
    expect(sent?.html).toContain('font-weight:400; font-size:19px; line-height:28px');
    expect(sent?.html).toContain('letter-spacing:.04em; text-indent:.04em; color:#2A2F34');
    expect(sent?.html).toContain('font-weight:300; font-size:52px; line-height:60px');
    expect(sent?.html).toContain('letter-spacing:.22em; text-indent:.22em; color:#16191C');
    expect(sent?.html).toContain(
      'font-size:13px; line-height:20px; letter-spacing:.02em; color:#AEB4B9',
    );
    expect(sent?.html).toContain('@media (prefers-color-scheme: dark)');
    for (const color of ['#0F1113', '#E7EAED', '#FFFFFF', '#6E757C']) {
      expect(sent?.html).toContain(color);
    }
    expect(sent?.html).toContain('@media (max-width:420px)');
    expect(sent?.html).toContain('font-size:40px !important; letter-spacing:.16em !important');
    expect(sent?.html).toContain('font-size:16px !important; line-height:25px !important');
    expect(sent?.html).toContain('padding-left:18px !important; padding-right:18px !important');
    expect(sent?.html).not.toMatch(/<!--|<a\b|<img\b|https?:|recipient|Do not share|ignore this/iu);
  });

  it.each([
    [60_000, '1 минуту'],
    [120_000, '2 минуты'],
    [300_000, '5 минут'],
    [1_260_000, '21 минуту'],
    [61_000, '61 секунду'],
    [92_000, '92 секунды'],
    [59_000, '59 секунд'],
    [1_250, '1,25 секунды'],
  ])('uses the same challenge timestamps for a %i ms lifetime', async (ttl, duration) => {
    const fixture = successfulClient();
    const delivery = new ResendEmailChallengeDelivery(fixture.client, {
      address: 'sender@auth.invalid',
      name: 'Synthetic Auth Sender',
    });
    await delivery.send({
      ...message,
      code: '920483',
      expiresAt: message.issuedAt + ttl,
    });
    const sent = fixture.send.mock.calls[0]?.[0];
    expect(sent?.subject).toBe('Код для входа: 920483');
    expect(sent?.html).toContain('920<span style="letter-spacing:.12em"> </span>483');
    expect(sent?.html.match(/Код действует /gu)).toHaveLength(2);
    expect(sent?.html).toContain(`Код действует ${duration}`);
    expect(sent?.text).toContain(`920483\n\nКод действует ${duration}`);
    expect(sent?.html).not.toContain('10 минут');
  });

  it.each([
    { code: '12345' },
    { code: '1234567' },
    { code: '<html>' },
    { issuedAt: Number.NaN },
    { issuedAt: 0 },
    { issuedAt: message.expiresAt },
    { expiresAt: message.issuedAt - 1 },
    { expiresAt: Number.POSITIVE_INFINITY },
  ])('rejects malformed challenge data without sending or exposing it', async (invalid) => {
    const fixture = successfulClient();
    const delivery = new ResendEmailChallengeDelivery(fixture.client, {
      address: 'sender@auth.invalid',
      name: 'Synthetic Auth Sender',
    });
    await expect(delivery.send({ ...message, ...invalid })).rejects.toMatchObject({
      code: 'auth.unavailable',
      message: 'Email challenge delivery is unavailable',
    });
    expect(fixture.send).not.toHaveBeenCalled();
  });

  it('loads every sender field and the API key only from server configuration', () => {
    const fixture = successfulClient();
    const factory = vi.fn<ResendEmailClientFactory>(() => fixture.client);
    const delivery = createResendEmailChallengeDelivery(
      {
        AUTH_EMAIL_FROM_ADDRESS: 'sender@auth.invalid',
        AUTH_EMAIL_FROM_NAME: 'Synthetic Auth Sender',
        RESEND_API_KEY: 'synthetic-test-key-material',
      },
      factory,
    );

    expect(delivery).toBeInstanceOf(ResendEmailChallengeDelivery);
    expect(factory).toHaveBeenCalledWith('synthetic-test-key-material');
  });

  it('loads the provider credential from a container secret file', () => {
    const directory = mkdtempSync(join(tmpdir(), 'kovcheg-resend-config-'));
    try {
      const secretPath = join(directory, 'api-key');
      writeFileSync(secretPath, 'synthetic-file-key-material');
      const fixture = successfulClient();
      const factory = vi.fn<ResendEmailClientFactory>(() => fixture.client);

      createResendEmailChallengeDelivery(
        {
          AUTH_EMAIL_FROM_ADDRESS: 'sender@auth.invalid',
          AUTH_EMAIL_FROM_NAME: 'Synthetic Auth Sender',
          RESEND_API_KEY_FILE: secretPath,
        },
        factory,
      );
      expect(factory).toHaveBeenCalledWith('synthetic-file-key-material');
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it('fails closed without configuration and sanitizes provider failures', async () => {
    expect(() => createResendEmailChallengeDelivery({})).toThrow(
      'Email challenge delivery is unavailable',
    );
    expect(() =>
      createResendEmailChallengeDelivery({
        AUTH_EMAIL_FROM_ADDRESS: 'not-an-address',
        AUTH_EMAIL_FROM_NAME: 'Synthetic Auth Sender',
        RESEND_API_KEY: 'synthetic-test-key-material',
      }),
    ).toThrow('Email challenge delivery is unavailable');

    const providerFailure = 'synthetic upstream detail that must stay private';
    const delivery = new ResendEmailChallengeDelivery(
      {
        send: () =>
          Promise.resolve({
            data: null,
            error: new Error(providerFailure),
          }),
      },
      { address: 'sender@auth.invalid', name: 'Synthetic Auth Sender' },
    );
    await expect(delivery.send(message)).rejects.toMatchObject({
      code: 'auth.unavailable',
      message: 'Email challenge delivery is unavailable',
    });
    await delivery.send(message).catch((error: unknown) => {
      expect(String(error)).not.toContain(providerFailure);
      expect(String(error)).not.toContain(message.code);
      expect(String(error)).not.toContain(message.recipient);
    });
  });
});
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
