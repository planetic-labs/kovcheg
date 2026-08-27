import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import type { UserId, Uuid } from '@kovcheg/contracts';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { describe, expect, it } from 'vitest';

import type { AuthPasskeyCredential } from './contracts.js';
import { SimpleWebAuthnServer } from './webauthn-server.js';

const accountId = '00000000-0000-4000-8000-000000001511' satisfies UserId;
const rpId = 'crypto-passkey.invalid';
const origin = `https://${rpId}`;
const challenge = Buffer.from('synthetic-cryptographic-challenge').toString('base64url');
const credentialId = Uint8Array.from(Buffer.from('cryptographic-credential'));

function base64UrlBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, 'base64url'));
}

function coseEc2PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  if (x.length !== 32 || y.length !== 32) throw new Error('P-256 coordinate length is invalid');
  return Uint8Array.from([
    0xa5,
    0x01,
    0x02,
    0x03,
    0x26,
    0x20,
    0x01,
    0x21,
    0x58,
    0x20,
    ...x,
    0x22,
    0x58,
    0x20,
    ...y,
  ]);
}

function assertionFixture(options: { readonly flags?: number; readonly userId?: UserId } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.x === undefined || jwk.y === undefined) throw new Error('Missing P-256 coordinates');
  const publicKeyCose = coseEc2PublicKey(base64UrlBytes(jwk.x), base64UrlBytes(jwk.y));
  const clientDataJson = Buffer.from(
    JSON.stringify({ challenge, crossOrigin: false, origin, type: 'webauthn.get' }),
    'utf8',
  );
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(5);
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(rpId).digest(),
    Buffer.from([options.flags ?? 0x1d]),
    counter,
  ]);
  const signature = sign(
    'sha256',
    Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]),
    privateKey,
  );
  const response: AuthenticationResponseJSON = {
    clientExtensionResults: {},
    id: Buffer.from(credentialId).toString('base64url'),
    rawId: Buffer.from(credentialId).toString('base64url'),
    response: {
      authenticatorData: authenticatorData.toString('base64url'),
      clientDataJSON: clientDataJson.toString('base64url'),
      signature: signature.toString('base64url'),
      userHandle: Buffer.from((options.userId ?? accountId).replaceAll('-', ''), 'hex').toString(
        'base64url',
      ),
    },
    type: 'public-key',
  };
  const credential: AuthPasskeyCredential = Object.freeze({
    aaguid: '00000000-0000-0000-0000-000000000000' as Uuid,
    accountId,
    attestationFormat: 'none',
    credentialId,
    lastBackupEligible: true,
    lastBackupState: true,
    passkeyId: '00000000-0000-4000-8000-000000001512' as Uuid,
    publicKey: publicKeyCose,
    registeredBackupEligible: true,
    registeredBackupState: true,
    signCount: 10,
    transports: Object.freeze(['hybrid'] as const),
  });
  return { credential, response };
}

describe('SimpleWebAuthnServer', () => {
  it('requests required discoverability and user verification without account hints', async () => {
    const server = new SimpleWebAuthnServer();
    const registration = await server.generateRegistrationOptions({
      accountId,
      accountLabel: 'Synthetic Account',
      rpId,
      rpName: 'Synthetic Auth',
      timeoutMs: 60_000,
    });
    const authentication = await server.generateAuthenticationOptions({
      rpId,
      timeoutMs: 60_000,
    });
    expect(registration.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(registration.attestation).toBe('none');
    expect(authentication.allowCredentials ?? []).toEqual([]);
    expect(authentication.userVerification).toBe('required');
  });

  it('cryptographically verifies signature, origin, RP, account handle, UV, and backup evidence', async () => {
    const server = new SimpleWebAuthnServer();
    const fixture = assertionFixture();
    await expect(
      server.verifyAuthentication({
        credential: fixture.credential,
        expectedChallenge: challenge,
        expectedOrigins: [origin],
        expectedRpId: rpId,
        response: fixture.response,
      }),
    ).resolves.toEqual({
      backupEligible: true,
      backupState: true,
      observedSignCount: 5,
      userVerified: true,
    });
  });

  it('fails closed for challenge, origin, RP, UV, signature, and account-handle drift', async () => {
    const server = new SimpleWebAuthnServer();
    const fixture = assertionFixture();
    const common = {
      credential: fixture.credential,
      expectedChallenge: challenge,
      expectedOrigins: [origin],
      expectedRpId: rpId,
      response: fixture.response,
    };
    await expect(
      server.verifyAuthentication({ ...common, expectedChallenge: 'wrong-challenge' }),
    ).resolves.toBeNull();
    await expect(
      server.verifyAuthentication({ ...common, expectedOrigins: ['https://wrong.invalid'] }),
    ).resolves.toBeNull();
    await expect(
      server.verifyAuthentication({ ...common, expectedRpId: 'wrong.invalid' }),
    ).resolves.toBeNull();

    const noUserVerification = assertionFixture({ flags: 0x19 });
    await expect(
      server.verifyAuthentication({
        ...common,
        credential: noUserVerification.credential,
        response: noUserVerification.response,
      }),
    ).resolves.toBeNull();

    const alteredSignature: AuthenticationResponseJSON = {
      ...fixture.response,
      response: { ...fixture.response.response, signature: 'AA' },
    };
    await expect(
      server.verifyAuthentication({ ...common, response: alteredSignature }),
    ).resolves.toBeNull();

    const wrongHandle = assertionFixture({
      userId: '00000000-0000-4000-8000-000000001599' as UserId,
    });
    await expect(
      server.verifyAuthentication({
        ...common,
        credential: wrongHandle.credential,
        response: wrongHandle.response,
      }),
    ).resolves.toBeNull();
  });
});
