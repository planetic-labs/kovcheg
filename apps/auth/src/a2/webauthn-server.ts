import { timingSafeEqual } from 'node:crypto';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

import type { AuthPasskeyTransport } from './contracts.js';
import type {
  PasskeyAuthenticationVerification,
  PasskeyRegistrationVerification,
  WebAuthnServer,
} from './ports.js';

const aaguidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function accountIdBytes(accountId: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(Buffer.from(accountId.replaceAll('-', ''), 'hex'));
}

function transports(
  values: readonly AuthenticatorTransportFuture[] | undefined,
): readonly AuthPasskeyTransport[] {
  const normalized = new Set<AuthPasskeyTransport>();
  for (const value of values ?? []) {
    if (value === 'cable') {
      normalized.add('hybrid');
    } else if (
      value === 'ble' ||
      value === 'hybrid' ||
      value === 'internal' ||
      value === 'nfc' ||
      value === 'smart-card' ||
      value === 'usb'
    ) {
      normalized.add(value);
    }
  }
  return Object.freeze([...normalized].sort());
}

function matchesAccountHandle(value: string | undefined, accountId: string): boolean {
  if (value === undefined || !/^[A-Za-z0-9_-]{1,1024}$/u.test(value)) return false;
  const actual = Buffer.from(value, 'base64url');
  const expected = Buffer.from(accountIdBytes(accountId));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export class SimpleWebAuthnServer implements WebAuthnServer {
  generateAuthenticationOptions(
    input: Parameters<WebAuthnServer['generateAuthenticationOptions']>[0],
  ) {
    return generateAuthenticationOptions({
      rpID: input.rpId,
      timeout: input.timeoutMs,
      userVerification: 'required',
    });
  }

  generateRegistrationOptions(input: Parameters<WebAuthnServer['generateRegistrationOptions']>[0]) {
    return generateRegistrationOptions({
      attestationType: 'none',
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      },
      rpID: input.rpId,
      rpName: input.rpName,
      timeout: input.timeoutMs,
      userDisplayName: input.accountLabel,
      userID: accountIdBytes(input.accountId),
      userName: input.accountId,
    });
  }

  async verifyAuthentication(
    input: Parameters<WebAuthnServer['verifyAuthentication']>[0],
  ): Promise<PasskeyAuthenticationVerification | null> {
    if (!matchesAccountHandle(input.response.response.userHandle, input.credential.accountId)) {
      return null;
    }
    try {
      const verification = await verifyAuthenticationResponse({
        credential: {
          counter: 0,
          id: Buffer.from(input.credential.credentialId).toString('base64url'),
          publicKey: Uint8Array.from(input.credential.publicKey),
          transports: [...input.credential.transports],
        },
        expectedChallenge: input.expectedChallenge,
        expectedOrigin: [...input.expectedOrigins],
        expectedRPID: input.expectedRpId,
        requireUserVerification: true,
        response: input.response,
      });
      const information = verification.authenticationInfo;
      if (!verification.verified || !information.userVerified) return null;

      // Counter monotonicity is retained as A3 risk evidence. It must not override
      // successful signature, origin, RP ID, account, revocation, and UV checks.
      return Object.freeze({
        backupEligible: information.credentialDeviceType === 'multiDevice',
        backupState: information.credentialBackedUp,
        observedSignCount: information.newCounter,
        userVerified: information.userVerified,
      });
    } catch {
      return null;
    }
  }

  async verifyRegistration(
    input: Parameters<WebAuthnServer['verifyRegistration']>[0],
  ): Promise<PasskeyRegistrationVerification | null> {
    try {
      const verification = await verifyRegistrationResponse({
        expectedChallenge: input.expectedChallenge,
        expectedOrigin: [...input.expectedOrigins],
        expectedRPID: input.expectedRpId,
        requireUserPresence: true,
        requireUserVerification: true,
        response: input.response,
      });
      const information = verification.registrationInfo;
      if (!verification.verified || information === undefined || !information.userVerified) {
        return null;
      }
      if (!aaguidPattern.test(information.aaguid)) return null;
      return Object.freeze({
        aaguid: information.aaguid as PasskeyRegistrationVerification['aaguid'],
        attestationFormat: information.fmt,
        backupEligible: information.credentialDeviceType === 'multiDevice',
        backupState: information.credentialBackedUp,
        credentialId: Uint8Array.from(Buffer.from(information.credential.id, 'base64url')),
        publicKey: Uint8Array.from(information.credential.publicKey),
        signCount: information.credential.counter,
        transports: transports(information.credential.transports),
        userVerified: information.userVerified,
      });
    } catch {
      return null;
    }
  }
}
