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
  code: '123456',
  expiresAt: Date.UTC(2031, 0, 1, 0, 10),
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
        subject: 'Your one-time sign-in code',
        text: expect.stringContaining(message.code),
        to: 'recipient@auth.invalid',
      },
      { idempotencyKey: `auth-email-challenge/${message.challengeId}` },
    );
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
