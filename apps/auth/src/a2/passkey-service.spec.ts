import type { CorrelationId, UserId, Uuid } from '@kovcheg/contracts';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { describe, expect, it, vi } from 'vitest';

import { AuthService } from './auth-service.js';
import { emailChallengePolicy, passkeyPolicy, passkeyRateLimitPolicy } from './contracts.js';
import type { AuthPolicy, PasskeyRequestContext } from './contracts.js';
import { HmacAuthCrypto, SystemAuthRandomSource } from './crypto.js';
import {
  LocalAuthRepository,
  LocalEmailChallengeDelivery,
  LocalRateLimiter,
  ManualClock,
  UnavailableRateLimiter,
} from './local-adapters.js';
import { PasskeyService } from './passkey-service.js';
import type {
  PasskeyCeremonyState,
  PasskeyCeremonyStore,
  PasskeyRegistrationVerification,
  TakePasskeyCeremonyResult,
  WebAuthnServer,
} from './ports.js';
import { SimpleWebAuthnServer } from './webauthn-server.js';

const now = Date.UTC(2026, 7, 27, 12);
const administratorId = '00000000-0000-4000-8000-000000001501' satisfies UserId;
const correlationId = 'synthetic-passkey-correlation' as CorrelationId;
const context: PasskeyRequestContext = Object.freeze({
  correlationId,
  fingerprint: 'synthetic-browser',
  networkAddress: 'synthetic-network',
});

function policy(): AuthPolicy {
  const rule = Object.freeze({ limit: 100, windowMs: 15 * 60_000 });
  return Object.freeze({
    challenge: emailChallengePolicy,
    passkey: passkeyPolicy,
    rateLimits: Object.freeze({
      challengeByEmail: rule,
      challengeByFingerprint: rule,
      challengeByNetwork: rule,
      ...passkeyRateLimitPolicy,
      verifyByChallenge: rule,
      verifyByNetwork: rule,
    }),
    session: Object.freeze({
      absoluteLifetimeMs: 30 * 24 * 60 * 60_000,
      idleLifetimeMs: 7 * 24 * 60 * 60_000,
    }),
  });
}

class MemoryCeremonyStore implements PasskeyCeremonyStore {
  readonly ceremonies = new Map<Uuid, PasskeyCeremonyState>();
  unavailable = false;

  put(ceremonyId: Uuid, state: PasskeyCeremonyState): Promise<'stored' | 'unavailable'> {
    if (this.unavailable || this.ceremonies.has(ceremonyId)) {
      return Promise.resolve('unavailable');
    }
    this.ceremonies.set(ceremonyId, state);
    return Promise.resolve('stored');
  }

  take(ceremonyId: Uuid): Promise<TakePasskeyCeremonyResult> {
    if (this.unavailable) return Promise.resolve({ kind: 'unavailable' });
    const state = this.ceremonies.get(ceremonyId);
    if (state === undefined) return Promise.resolve({ kind: 'missing' });
    this.ceremonies.delete(ceremonyId);
    return Promise.resolve({ kind: 'found', state });
  }
}

interface SyntheticClientData {
  readonly challenge: string;
  readonly observedSignCount?: number;
  readonly origin: string;
  readonly rpId: string;
  readonly userVerified: boolean;
}

function clientData(data: SyntheticClientData): string {
  return Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
}

function parsedClientData(value: string): SyntheticClientData | null {
  try {
    const candidate = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as unknown;
    if (candidate === null || typeof candidate !== 'object') return null;
    return candidate as SyntheticClientData;
  } catch {
    return null;
  }
}

class SyntheticWebAuthnServer implements WebAuthnServer {
  private readonly options = new SimpleWebAuthnServer();

  generateAuthenticationOptions(
    input: Parameters<WebAuthnServer['generateAuthenticationOptions']>[0],
  ) {
    return this.options.generateAuthenticationOptions(input);
  }

  generateRegistrationOptions(input: Parameters<WebAuthnServer['generateRegistrationOptions']>[0]) {
    return this.options.generateRegistrationOptions(input);
  }

  verifyAuthentication(
    input: Parameters<WebAuthnServer['verifyAuthentication']>[0],
  ): ReturnType<WebAuthnServer['verifyAuthentication']> {
    const data = parsedClientData(input.response.response.clientDataJSON);
    if (
      data === null ||
      data.challenge !== input.expectedChallenge ||
      !input.expectedOrigins.includes(data.origin) ||
      data.rpId !== input.expectedRpId ||
      !data.userVerified
    ) {
      return Promise.resolve(null);
    }
    return Promise.resolve({
      backupEligible: true,
      backupState: true,
      observedSignCount: data.observedSignCount ?? 11,
      userVerified: true,
    });
  }

  verifyRegistration(
    input: Parameters<WebAuthnServer['verifyRegistration']>[0],
  ): ReturnType<WebAuthnServer['verifyRegistration']> {
    const data = parsedClientData(input.response.response.clientDataJSON);
    if (
      data === null ||
      data.challenge !== input.expectedChallenge ||
      !input.expectedOrigins.includes(data.origin) ||
      data.rpId !== input.expectedRpId ||
      !data.userVerified
    ) {
      return Promise.resolve(null);
    }
    const verification: PasskeyRegistrationVerification = Object.freeze({
      aaguid: '00000000-0000-0000-0000-000000000000' as Uuid,
      attestationFormat: 'none',
      backupEligible: true,
      backupState: true,
      credentialId: Uint8Array.from(Buffer.from(input.response.id, 'base64url')),
      publicKey: Uint8Array.from([1, 2, 3, 4]),
      signCount: data.observedSignCount ?? 10,
      transports: Object.freeze(['hybrid', 'internal'] as const),
      userVerified: true,
    });
    return Promise.resolve(verification);
  }
}

function registrationResponse(
  challenge: string,
  credential: string,
  override: Partial<SyntheticClientData> = {},
): RegistrationResponseJSON {
  const id = Buffer.from(credential, 'utf8').toString('base64url');
  return {
    clientExtensionResults: {},
    id,
    rawId: id,
    response: {
      attestationObject: 'synthetic',
      clientDataJSON: clientData({
        challenge,
        observedSignCount: 10,
        origin: 'https://passkey.invalid',
        rpId: 'passkey.invalid',
        userVerified: true,
        ...override,
      }),
      transports: ['hybrid', 'internal'],
    },
    type: 'public-key',
  };
}

function authenticationResponse(
  challenge: string,
  credential: string,
  override: Partial<SyntheticClientData> = {},
): AuthenticationResponseJSON {
  const id = Buffer.from(credential, 'utf8').toString('base64url');
  return {
    clientExtensionResults: {},
    id,
    rawId: id,
    response: {
      authenticatorData: 'synthetic',
      clientDataJSON: clientData({
        challenge,
        observedSignCount: 11,
        origin: 'https://passkey.invalid',
        rpId: 'passkey.invalid',
        userVerified: true,
        ...override,
      }),
      signature: 'synthetic',
      userHandle: Buffer.from(administratorId.replaceAll('-', ''), 'hex').toString('base64url'),
    },
    type: 'public-key',
  };
}

async function login(
  service: AuthService,
  delivery: LocalEmailChallengeDelivery,
  email: string,
  suffix: string,
) {
  const challenge = await service.requestEmailChallenge({
    email,
    fingerprint: `fingerprint-${suffix}`,
    networkAddress: `network-${suffix}`,
  });
  const message = delivery.messages.at(-1);
  if (message === undefined || message.challengeId !== challenge.challengeId) {
    throw new Error('Synthetic challenge was not delivered');
  }
  return service.verifyEmailChallenge({
    challengeId: challenge.challengeId,
    code: message.code,
    networkAddress: `network-${suffix}`,
  });
}

async function fixture(options: { readonly rateLimiter?: LocalRateLimiter } = {}) {
  const clock = new ManualClock(now);
  const repository = new LocalAuthRepository({ NODE_ENV: 'test' });
  const delivery = new LocalEmailChallengeDelivery({ NODE_ENV: 'test' });
  const crypto = new HmacAuthCrypto({
    challengePepper: 'c'.repeat(64),
    personalGatePepper: 'g'.repeat(64),
    rateLimitPepper: 'r'.repeat(64),
    sessionPepper: 's'.repeat(64),
  });
  const random = new SystemAuthRandomSource();
  const rateLimiter = options.rateLimiter ?? new LocalRateLimiter({ NODE_ENV: 'test' });
  const auth = new AuthService({
    clock,
    crypto,
    delivery,
    policy: policy(),
    random,
    rateLimiter,
    repository,
  });
  await auth.bootstrapAdministrator({
    bootstrapId: 'synthetic-passkey-bootstrap',
    displayName: 'Synthetic Administrator',
    email: 'administrator@passkey.invalid',
    userId: administratorId,
  });
  const administratorSession = await login(
    auth,
    delivery,
    'administrator@passkey.invalid',
    'administrator',
  );
  const member = await auth.createAccount(
    administratorSession.sessionToken,
    { displayName: 'Synthetic Member', email: 'member@passkey.invalid' },
    correlationId,
  );
  const memberSession = await login(auth, delivery, 'member@passkey.invalid', 'member');
  const ceremonyStore = new MemoryCeremonyStore();
  const webauthn = new SyntheticWebAuthnServer();
  const service = new PasskeyService({
    ceremonyStore,
    clock,
    configuration: {
      origins: Object.freeze(['https://passkey.invalid']),
      rpId: 'passkey.invalid',
      rpName: 'Synthetic Auth',
    },
    crypto,
    policy: policy(),
    random,
    rateLimiter,
    repository,
    webauthn,
  });
  return {
    administratorSession,
    auth,
    ceremonyStore,
    crypto,
    member,
    memberSession,
    repository,
    service,
    webauthn,
  };
}

async function register(
  value: Awaited<ReturnType<typeof fixture>>,
  credential: string,
  sessionToken = value.memberSession.sessionToken,
) {
  const options = await value.service.beginRegistration(sessionToken, context);
  const result = await value.service.finishRegistration(
    sessionToken,
    {
      ceremonyId: options.ceremonyId,
      response: registrationResponse(options.options.challenge, credential),
    },
    context,
  );
  return { options, result };
}

describe('A6 passkey registration', () => {
  it('requires an active application session and requests a synced discoverable credential', async () => {
    const value = await fixture();
    await expect(
      value.service.beginRegistration('invalid-session-token', context),
    ).rejects.toMatchObject({ code: 'auth.invalid-session' });

    const first = await register(value, 'credential-one');
    const second = await register(value, 'credential-two');

    expect(first.options.options.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(first.options.options.attestation).toBe('none');
    expect(first.result.status).toBe('registered');
    expect(second.result.passkeyId).not.toBe(first.result.passkeyId);
    await expect(
      value.repository.readPasskeyByCredentialId(
        Uint8Array.from(Buffer.from('credential-two')),
        now,
      ),
    ).resolves.toMatchObject({
      lastBackupEligible: true,
      lastBackupState: true,
      registeredBackupEligible: true,
      registeredBackupState: true,
      transports: ['hybrid', 'internal'],
    });
  });

  it('binds registration to ceremony, session, and client context and consumes state once', async () => {
    const value = await fixture();
    const options = await value.service.beginRegistration(
      value.memberSession.sessionToken,
      context,
    );
    const response = registrationResponse(options.options.challenge, 'bound-credential');
    await expect(
      value.service.finishRegistration(
        value.memberSession.sessionToken,
        { ceremonyId: options.ceremonyId, response },
        { ...context, fingerprint: 'other-browser' },
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });
    await expect(
      value.service.finishRegistration(
        value.memberSession.sessionToken,
        { ceremonyId: options.ceremonyId, response },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });
  });
});

describe('A6 discoverable passkey authentication', () => {
  it('starts without gate or email and creates a session only after verified assertion', async () => {
    const value = await fixture();
    await register(value, 'discoverable-credential');
    const complete = vi.spyOn(value.repository, 'completePasskeyLogin');

    const rejectedOptions = await value.service.beginAuthentication(context);
    expect(rejectedOptions.mediation).toBe('conditional');
    expect(rejectedOptions.options.allowCredentials ?? []).toEqual([]);
    expect(rejectedOptions.options.userVerification).toBe('required');
    await expect(
      value.service.finishAuthentication(
        {
          ceremonyId: rejectedOptions.ceremonyId,
          response: authenticationResponse(
            rejectedOptions.options.challenge,
            'discoverable-credential',
            { origin: 'https://wrong.invalid' },
          ),
        },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });
    expect(complete).not.toHaveBeenCalled();

    const options = await value.service.beginAuthentication(context);
    const authenticated = await value.service.finishAuthentication(
      {
        ceremonyId: options.ceremonyId,
        response: authenticationResponse(options.options.challenge, 'discoverable-credential'),
      },
      context,
    );
    expect(authenticated.userId).toBe(value.member.userId);
    await expect(
      value.repository.validateSession(
        value.crypto.sessionTokenVerifier(authenticated.sessionToken),
        now,
      ),
    ).resolves.toMatchObject({ userId: value.member.userId });
  });

  it.each([
    ['challenge', { challenge: 'wrong-challenge-value' }],
    ['origin', { origin: 'https://wrong.invalid' }],
    ['RP ID', { rpId: 'wrong.invalid' }],
    ['user verification', { userVerified: false }],
  ])('fails closed for wrong %s', async (_label, override) => {
    const value = await fixture();
    await register(value, 'rejected-credential');
    const complete = vi.spyOn(value.repository, 'completePasskeyLogin');
    const options = await value.service.beginAuthentication(context);
    await expect(
      value.service.finishAuthentication(
        {
          ceremonyId: options.ceremonyId,
          response: authenticationResponse(
            options.options.challenge,
            'rejected-credential',
            override,
          ),
        },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });
    expect(complete).not.toHaveBeenCalled();
  });

  it('returns the same neutral failure for unknown, revoked, and deactivated credentials', async () => {
    const unknown = await fixture();
    const unknownOptions = await unknown.service.beginAuthentication(context);
    await expect(
      unknown.service.finishAuthentication(
        {
          ceremonyId: unknownOptions.ceremonyId,
          response: authenticationResponse(unknownOptions.options.challenge, 'unknown-credential'),
        },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });

    const revoked = await fixture();
    await register(revoked, 'revoked-credential');
    await revoked.auth.securityResetAuthAccess(
      revoked.administratorSession.sessionToken,
      revoked.member.userId,
      correlationId,
    );
    const revokedOptions = await revoked.service.beginAuthentication(context);
    await expect(
      revoked.service.finishAuthentication(
        {
          ceremonyId: revokedOptions.ceremonyId,
          response: authenticationResponse(revokedOptions.options.challenge, 'revoked-credential'),
        },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });

    const deactivated = await fixture();
    await register(deactivated, 'deactivated-credential');
    await deactivated.auth.setAccountStatus(
      deactivated.administratorSession.sessionToken,
      deactivated.member.userId,
      'deactivated',
      correlationId,
    );
    const deactivatedOptions = await deactivated.service.beginAuthentication(context);
    await expect(
      deactivated.service.finishAuthentication(
        {
          ceremonyId: deactivatedOptions.ceremonyId,
          response: authenticationResponse(
            deactivatedOptions.options.challenge,
            'deactivated-credential',
          ),
        },
        context,
      ),
    ).rejects.toMatchObject({ code: 'auth.invalid-passkey' });
  });

  it('allows exactly one concurrent finish and rejects replay', async () => {
    const value = await fixture();
    await register(value, 'race-credential');
    const options = await value.service.beginAuthentication(context);
    const input = {
      ceremonyId: options.ceremonyId,
      response: authenticationResponse(options.options.challenge, 'race-credential'),
    };
    const results = await Promise.allSettled([
      value.service.finishAuthentication(input, context),
      value.service.finishAuthentication(input, context),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    await expect(value.service.finishAuthentication(input, context)).rejects.toMatchObject({
      code: 'auth.invalid-passkey',
    });
  });

  it('accepts a counter regression as recorded risk evidence without lowering the stored counter', async () => {
    const value = await fixture();
    await register(value, 'counter-credential');
    const options = await value.service.beginAuthentication(context);
    const authenticated = await value.service.finishAuthentication(
      {
        ceremonyId: options.ceremonyId,
        response: authenticationResponse(options.options.challenge, 'counter-credential', {
          observedSignCount: 5,
        }),
      },
      context,
    );
    expect(authenticated.signCountStatus).toBe('regressed');
    await expect(
      value.repository.readPasskeyByCredentialId(
        Uint8Array.from(Buffer.from('counter-credential')),
        now,
      ),
    ).resolves.toMatchObject({ signCount: 10 });
  });

  it('fails closed when Redis-backed state or rate limiting is unavailable', async () => {
    const value = await fixture();
    value.ceremonyStore.unavailable = true;
    await expect(value.service.beginAuthentication(context)).rejects.toMatchObject({
      code: 'auth.unavailable',
    });

    const unavailable = new PasskeyService({
      ceremonyStore: new MemoryCeremonyStore(),
      clock: new ManualClock(now),
      configuration: {
        origins: ['https://passkey.invalid'],
        rpId: 'passkey.invalid',
        rpName: 'Synthetic Auth',
      },
      crypto: value.crypto,
      policy: policy(),
      random: new SystemAuthRandomSource(),
      rateLimiter: new UnavailableRateLimiter(),
      repository: value.repository,
      webauthn: value.webauthn,
    });
    await expect(unavailable.beginAuthentication(context)).rejects.toMatchObject({
      code: 'auth.unavailable',
    });

    const limited = new PasskeyService({
      ceremonyStore: new MemoryCeremonyStore(),
      clock: new ManualClock(now),
      configuration: {
        origins: ['https://passkey.invalid'],
        rpId: 'passkey.invalid',
        rpName: 'Synthetic Auth',
      },
      crypto: value.crypto,
      policy: policy(),
      random: new SystemAuthRandomSource(),
      rateLimiter: { consume: () => Promise.resolve('limited') },
      repository: value.repository,
      webauthn: value.webauthn,
    });
    await expect(limited.beginAuthentication(context)).rejects.toMatchObject({
      code: 'auth.invalid-passkey',
    });
  });
});
