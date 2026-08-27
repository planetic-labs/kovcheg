import {
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
} from '@simplewebauthn/browser';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export type ConditionalPasskeyResult =
  'authenticated' | 'cancelled' | 'unavailable' | 'unsupported';
export type PasskeyRegistrationResult = 'cancelled' | 'failed' | 'registered';

export interface PasskeyBrowserAdapter {
  authenticate(options: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON>;
  register(options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON>;
  supportsConditionalMediation(): Promise<boolean>;
}

export function cancelPasskeyCeremony(
  cancel: () => void = () => WebAuthnAbortService.cancelCeremony(),
): void {
  cancel();
}

type PasskeyFetch = (input: string, init: RequestInit) => Promise<Response>;

const browserAdapter: PasskeyBrowserAdapter = Object.freeze({
  async authenticate(options: PublicKeyCredentialRequestOptionsJSON) {
    return startAuthentication({ optionsJSON: options, useBrowserAutofill: true });
  },
  async register(options: PublicKeyCredentialCreationOptionsJSON) {
    return startRegistration({ optionsJSON: options });
  },
  async supportsConditionalMediation() {
    if (
      typeof PublicKeyCredential === 'undefined' ||
      typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function'
    ) {
      return false;
    }
    return browserSupportsWebAuthnAutofill();
  },
});

function objectValue(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cancelled(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    (error.name === 'AbortError' || error.name === 'NotAllowedError')
  );
}

async function options<T extends object>(
  fetcher: PasskeyFetch,
  path: string,
): Promise<{ readonly ceremonyId: string; readonly options: T } | null> {
  const response = await fetcher(path, {
    cache: 'no-store',
    method: 'POST',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) return null;
  const payload = (await response.json().catch(() => null)) as unknown;
  if (
    !objectValue(payload) ||
    typeof payload.ceremonyId !== 'string' ||
    !uuidPattern.test(payload.ceremonyId) ||
    !objectValue(payload.options)
  ) {
    return null;
  }
  return { ceremonyId: payload.ceremonyId, options: payload.options as T };
}

async function verify(
  fetcher: PasskeyFetch,
  path: string,
  ceremonyId: string,
  response: AuthenticationResponseJSON | RegistrationResponseJSON,
): Promise<boolean> {
  const result = await fetcher(path, {
    body: JSON.stringify({ ceremonyId, response }),
    cache: 'no-store',
    headers: { 'content-type': 'application/json' },
    method: 'POST',
    referrerPolicy: 'no-referrer',
  });
  return result.ok;
}

export async function attemptConditionalPasskey(
  adapter: PasskeyBrowserAdapter = browserAdapter,
  fetcher: PasskeyFetch = fetch,
): Promise<ConditionalPasskeyResult> {
  try {
    if (!(await adapter.supportsConditionalMediation())) return 'unsupported';
    const ceremony = await options<PublicKeyCredentialRequestOptionsJSON>(
      fetcher,
      '/bff/auth/passkeys/authentication/options',
    );
    if (ceremony === null) return 'unavailable';
    const response = await adapter.authenticate(ceremony.options);
    return (await verify(
      fetcher,
      '/bff/auth/passkeys/authentication/verify',
      ceremony.ceremonyId,
      response,
    ))
      ? 'authenticated'
      : 'unavailable';
  } catch (error) {
    return cancelled(error) ? 'cancelled' : 'unavailable';
  }
}

export async function registerPasskey(
  adapter: PasskeyBrowserAdapter = browserAdapter,
  fetcher: PasskeyFetch = fetch,
): Promise<PasskeyRegistrationResult> {
  try {
    const ceremony = await options<PublicKeyCredentialCreationOptionsJSON>(
      fetcher,
      '/bff/auth/passkeys/registration/options',
    );
    if (ceremony === null) return 'failed';
    const response = await adapter.register(ceremony.options);
    return (await verify(
      fetcher,
      '/bff/auth/passkeys/registration/verify',
      ceremony.ceremonyId,
      response,
    ))
      ? 'registered'
      : 'failed';
  } catch (error) {
    return cancelled(error) ? 'cancelled' : 'failed';
  }
}
