import { Buffer } from 'node:buffer';

import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import { describe, expect, it, vi } from 'vitest';

import {
  attemptConditionalPasskey,
  cancelPasskeyCeremony,
  registerPasskey,
  type PasskeyBrowserAdapter,
} from './passkey-client';

const ceremonyId = '00000000-0000-4000-8000-000000000721';
const syntheticAuthenticatorData = Buffer.from('authenticator', 'utf8').toString('base64url');
const authenticationOptions = {
  challenge: 'YXV0aC1jaGFsbGVuZ2U',
  rpId: 'auth.example.invalid',
  userVerification: 'required',
} as PublicKeyCredentialRequestOptionsJSON;
const registrationOptions = {
  challenge: 'cmVnaXN0cmF0aW9uLWNoYWxsZW5nZQ',
  pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
  rp: { name: 'Synthetic RP' },
  user: { displayName: 'Synthetic User', id: 'c3ludGhldGlj', name: 'synthetic' },
} as PublicKeyCredentialCreationOptionsJSON;
const authenticationResponse = {
  clientExtensionResults: {},
  id: 'c3ludGhldGlj',
  rawId: 'c3ludGhldGlj',
  response: {
    authenticatorData: syntheticAuthenticatorData,
    clientDataJSON: 'Y2xpZW50',
    signature: 'c2lnbmF0dXJl',
    userHandle: 'c3ludGhldGlj',
  },
  type: 'public-key',
} as AuthenticationResponseJSON;
const registrationResponse = {
  clientExtensionResults: {},
  id: 'c3ludGhldGlj',
  rawId: 'c3ludGhldGlj',
  response: {
    attestationObject: 'YXR0ZXN0YXRpb24',
    clientDataJSON: 'Y2xpZW50',
  },
  type: 'public-key',
} as RegistrationResponseJSON;

function adapter(overrides?: Partial<PasskeyBrowserAdapter>): PasskeyBrowserAdapter {
  return {
    authenticate: vi.fn().mockResolvedValue(authenticationResponse),
    register: vi.fn().mockResolvedValue(registrationResponse),
    supportsConditionalMediation: vi.fn().mockResolvedValue(true),
    ...overrides,
  };
}

describe('A6 browser passkey client', () => {
  it('cancels a pending conditional ceremony when the user chooses email fallback', () => {
    const cancel = vi.fn();
    cancelPasskeyCeremony(cancel);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('runs one conditional options/credential/verify sequence and authenticates', async () => {
    const passkeys = adapter();
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ceremonyId, options: authenticationOptions }), {
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ authenticated: true }), { status: 200 }),
      );

    await expect(attemptConditionalPasskey(passkeys, fetcher)).resolves.toBe('authenticated');
    expect(passkeys.supportsConditionalMediation).toHaveBeenCalledTimes(1);
    expect(passkeys.authenticate).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1]?.[0]).toBe('/bff/auth/passkeys/authentication/verify');
  });

  it('does nothing when unsupported and keeps cancellation quiet without verification', async () => {
    const unsupported = adapter({
      supportsConditionalMediation: vi.fn().mockResolvedValue(false),
    });
    const fetcher = vi.fn();
    await expect(attemptConditionalPasskey(unsupported, fetcher)).resolves.toBe('unsupported');
    expect(fetcher).not.toHaveBeenCalled();

    const cancelled = adapter({
      authenticate: vi
        .fn()
        .mockRejectedValue(new DOMException('Synthetic cancellation', 'NotAllowedError')),
    });
    const cancelledFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ceremonyId, options: authenticationOptions }), {
        status: 200,
      }),
    );
    await expect(attemptConditionalPasskey(cancelled, cancelledFetch)).resolves.toBe('cancelled');
    expect(cancelledFetch).toHaveBeenCalledTimes(1);
  });

  it('registers only when the explicit registration workflow is invoked', async () => {
    const passkeys = adapter();
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ceremonyId, options: registrationOptions }), { status: 200 }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ registered: true }), { status: 201 }));

    expect(passkeys.register).not.toHaveBeenCalled();
    await expect(registerPasskey(passkeys, fetcher)).resolves.toBe('registered');
    expect(passkeys.register).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
