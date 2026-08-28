import type { IncomingMessage, ServerResponse } from 'node:http';

import type { UserId } from '@kovcheg/contracts';
import Provider from 'oidc-provider';
import type {
  AdapterConstructor,
  AdapterFactory,
  ClientMetadata,
  Configuration,
  JWKS,
} from 'oidc-provider';

import { AuthError } from './contracts.js';
import type { AuthRepository, Clock } from './ports.js';
import type { AuthService } from './auth-service.js';

export interface PublicOidcClient {
  readonly clientId: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly tokenEndpointAuthMethod: 'none';
}

export interface ConfidentialOidcClient {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUris: readonly string[];
  readonly scopes: readonly string[];
  readonly tokenEndpointAuthMethod: 'client_secret_basic';
}

export type RegisteredOidcClient = ConfidentialOidcClient | PublicOidcClient;

export interface OidcClientRepository {
  readonly productionSafe?: true;
  listRegisteredClients(): Promise<readonly RegisteredOidcClient[]>;
}

export type OidcStorageAdapter = AdapterConstructor | AdapterFactory;

interface TtlAwareOidcGrant {
  save(ttlSeconds: number): Promise<unknown>;
}

export interface CreateOidcProviderInput {
  readonly accountRepository: AuthRepository;
  readonly clientRepository: OidcClientRepository;
  readonly cookieKeys: readonly string[];
  readonly environment: 'development' | 'production' | 'test';
  readonly issuer: string;
  readonly jwks: JWKS;
  readonly oidcSessionTtlSeconds: number;
  readonly secureCookies: boolean;
  readonly storageAdapter?: OidcStorageAdapter;
}

function isLoopback(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === '::1' || hostname === 'localhost';
}

function parseSecureUrl(value: string, environment: CreateOidcProviderInput['environment']): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthError('auth.invalid-input', 'OIDC URL must be absolute');
  }
  if (
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== '' ||
    parsed.search !== '' ||
    value.includes('*')
  ) {
    throw new AuthError('auth.invalid-input', 'OIDC URL contains a prohibited component');
  }
  if (
    parsed.protocol !== 'https:' &&
    !(parsed.protocol === 'http:' && isLoopback(parsed.hostname))
  ) {
    throw new AuthError('auth.invalid-input', 'OIDC URL must use HTTPS or a loopback HTTP origin');
  }
  if (environment === 'production' && parsed.protocol !== 'https:') {
    throw new AuthError('auth.invalid-input', 'Production OIDC URLs must use HTTPS');
  }
  return parsed;
}

function validateClient(
  client: RegisteredOidcClient,
  environment: CreateOidcProviderInput['environment'],
): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(client.clientId)) {
    throw new AuthError('auth.invalid-input', 'OIDC client ID is invalid');
  }
  if (
    client.redirectUris.length < 1 ||
    new Set(client.redirectUris).size !== client.redirectUris.length
  ) {
    throw new AuthError('auth.invalid-input', 'OIDC clients require unique redirect URIs');
  }
  for (const redirectUri of client.redirectUris) {
    parseSecureUrl(redirectUri, environment);
  }
  if (client.scopes.length !== 1 || client.scopes[0] !== 'openid') {
    throw new AuthError('auth.invalid-input', 'A2 OIDC clients may register only the openid scope');
  }
  if (
    client.tokenEndpointAuthMethod === 'client_secret_basic' &&
    Buffer.byteLength(client.clientSecret, 'utf8') < 32
  ) {
    throw new AuthError(
      'auth.invalid-input',
      'Confidential OIDC client secrets must contain 32 bytes',
    );
  }
}

function toClientMetadata(client: RegisteredOidcClient): ClientMetadata {
  const base = {
    application_type: 'web' as const,
    client_id: client.clientId,
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'ES256' as const,
    redirect_uris: [...client.redirectUris],
    response_types: ['code'] as const,
    scope: [...new Set(client.scopes)].join(' '),
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
  };
  return client.tokenEndpointAuthMethod === 'client_secret_basic'
    ? { ...base, client_secret: client.clientSecret }
    : base;
}

function parseUserId(value: string): UserId | null {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    ? (value as UserId)
    : null;
}

export async function resolveOidcApplicationIdentity(input: {
  readonly accessToken: string;
  readonly applicationClientId: string;
  readonly provider: Provider;
}): Promise<UserId> {
  if (
    input.accessToken.length < 16 ||
    input.accessToken.length > 4096 ||
    /\s/u.test(input.accessToken)
  ) {
    throw new AuthError('auth.invalid-session', 'The OIDC session proof is invalid');
  }
  const token = await input.provider.AccessToken.find(input.accessToken);
  const accountId = token?.accountId === undefined ? null : parseUserId(token.accountId);
  if (
    token === undefined ||
    token.kind !== 'AccessToken' ||
    token.clientId !== input.applicationClientId ||
    token.gty !== 'authorization_code' ||
    token.scope !== 'openid' ||
    !token.isValid ||
    token.isExpired ||
    accountId === null
  ) {
    throw new AuthError('auth.invalid-session', 'The OIDC identity is not authorized');
  }
  return accountId;
}

export async function createOidcProvider(input: CreateOidcProviderInput): Promise<Provider> {
  const issuer = parseSecureUrl(input.issuer, input.environment);
  if (issuer.pathname !== '/' && issuer.pathname.endsWith('/')) {
    throw new AuthError('auth.invalid-input', 'OIDC issuer must not end with a trailing slash');
  }
  if (input.environment === 'production' && !input.secureCookies) {
    throw new AuthError('auth.invalid-input', 'Production OIDC cookies must be secure');
  }
  if (input.storageAdapter === undefined && input.environment !== 'test') {
    throw new AuthError('auth.unavailable', 'A durable OIDC storage adapter is required');
  }
  if (
    input.cookieKeys.length < 2 ||
    input.cookieKeys.some((key) => Buffer.byteLength(key, 'utf8') < 32)
  ) {
    throw new AuthError('auth.invalid-input', 'At least two strong OIDC cookie keys are required');
  }
  if (input.jwks.keys.length < 1) {
    throw new AuthError('auth.invalid-input', 'At least one OIDC signing key is required');
  }
  if (!Number.isSafeInteger(input.oidcSessionTtlSeconds) || input.oidcSessionTtlSeconds <= 0) {
    throw new AuthError('auth.invalid-input', 'OIDC session TTL must be a positive integer');
  }

  const clients = await input.clientRepository.listRegisteredClients();
  if (clients.length < 1) {
    throw new AuthError('auth.invalid-input', 'At least one registered OIDC client is required');
  }
  const clientIds = new Set<string>();
  for (const client of clients) {
    validateClient(client, input.environment);
    if (clientIds.has(client.clientId)) {
      throw new AuthError('auth.conflict', 'OIDC client IDs must be unique');
    }
    clientIds.add(client.clientId);
  }

  const configuration: Configuration = {
    acceptQueryParamAccessTokens: false,
    allowOmittingSingleRegisteredRedirectUri: false,
    claims: { openid: ['sub'] },
    clientAuthMethods: ['none', 'client_secret_basic'],
    clientBasedCORS: () => false,
    clients: clients.map(toClientMetadata),
    conformIdTokenClaims: true,
    cookies: {
      keys: input.cookieKeys,
      long: {
        httpOnly: true,
        sameSite: 'lax',
        secure: input.secureCookies,
        signed: true,
      },
      short: {
        httpOnly: true,
        sameSite: 'lax',
        secure: input.secureCookies,
        signed: true,
      },
    },
    enabledJWA: { idTokenSigningAlgValues: ['ES256', 'RS256'] },
    features: {
      clientCredentials: { enabled: false },
      clientIdMetadataDocument: { enabled: false },
      devInteractions: { enabled: false },
      deviceFlow: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      revocation: { enabled: true },
      userinfo: { enabled: false },
    },
    findAccount: async (_context, subject) => {
      const userId = parseUserId(subject);
      if (userId === null) {
        return undefined;
      }
      const account = await input.accountRepository.findAccountById(userId);
      if (account === null || account.status !== 'active') {
        return undefined;
      }
      return {
        accountId: account.userId,
        claims: () => ({ sub: account.userId }),
      };
    },
    issueRefreshToken: () => false,
    jwks: input.jwks,
    loadExistingGrant: async (context) => {
      const client = context.oidc.client;
      const session = context.oidc.session;
      if (client === undefined || session?.accountId === undefined) {
        return undefined;
      }
      const grantId = context.oidc.result?.consent?.grantId ?? session.grantIdFor(client.clientId);
      if (grantId !== undefined) {
        return context.oidc.provider.Grant.find(grantId);
      }
      const grant = new context.oidc.provider.Grant({
        accountId: session.accountId,
        clientId: client.clientId,
      });
      grant.addOIDCScope('openid');
      await (grant as unknown as TtlAwareOidcGrant).save(input.oidcSessionTtlSeconds);
      return grant;
    },
    pkce: { required: () => true },
    renderError: (context, output) => {
      context.type = 'application/json';
      context.body = { error: output.error };
    },
    responseTypes: ['code'],
    scopes: ['openid'],
    subjectTypes: ['public'],
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      Grant: input.oidcSessionTtlSeconds,
      IdToken: 300,
      Interaction: 600,
      Session: input.oidcSessionTtlSeconds,
    },
    ...(input.storageAdapter === undefined ? {} : { adapter: input.storageAdapter }),
  };

  return new Provider(issuer.toString().replace(/\/$/, ''), configuration);
}

export async function completeOidcInteraction(input: {
  readonly authService: AuthService;
  readonly clock: Clock;
  readonly provider: Provider;
  readonly request: IncomingMessage;
  readonly response: ServerResponse;
  readonly sessionToken: string;
}): Promise<void> {
  const principal = await input.authService.authenticateSession(input.sessionToken);
  const interaction = await input.provider.interactionDetails(input.request, input.response);
  if (interaction.prompt.name !== 'login') {
    throw new AuthError('auth.forbidden', 'Only login interactions can be completed here');
  }
  await input.provider.interactionFinished(
    input.request,
    input.response,
    {
      login: {
        accountId: principal.userId,
        acr: 'email-code',
        amr: ['otp'],
        remember: false,
        ts: Math.floor(input.clock.now() / 1000),
      },
    },
    { mergeWithLastSubmission: false },
  );
}

export class StaticOidcClientRepository implements OidcClientRepository {
  constructor(
    private readonly clients: readonly RegisteredOidcClient[],
    environment: Readonly<{ NODE_ENV?: string | undefined }> = process.env,
  ) {
    if (environment.NODE_ENV === 'production') {
      throw new Error('Static OIDC client fixtures are unavailable in production');
    }
  }

  listRegisteredClients(): Promise<readonly RegisteredOidcClient[]> {
    return Promise.resolve(this.clients.map((client) => Object.freeze({ ...client })));
  }
}

export class ConfiguredOidcClientRepository implements OidcClientRepository {
  private readonly clients: readonly RegisteredOidcClient[];

  constructor(clients: readonly RegisteredOidcClient[]) {
    this.clients = Object.freeze(
      clients.map((client) =>
        Object.freeze({
          ...client,
          redirectUris: Object.freeze([...client.redirectUris]),
          scopes: Object.freeze([...client.scopes]),
        }),
      ),
    );
  }

  listRegisteredClients(): Promise<readonly RegisteredOidcClient[]> {
    return Promise.resolve(this.clients);
  }
}
