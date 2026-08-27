import {
  Body,
  Controller,
  Header,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { CorrelationId, Uuid } from '@kovcheg/contracts';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

import type {
  PasskeyAuthenticationFinishInput,
  PasskeyRegistrationFinishInput,
  PasskeyRequestContext,
} from './contracts.js';
import { authHttpException, toAuthHttpException } from './http-errors.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

interface PasskeyHttpRequest {
  readonly correlationId?: CorrelationId;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly ip?: string | undefined;
  readonly socket: { readonly remoteAddress?: string | undefined };
}

interface PasskeyHttpResponse {
  setHeader(name: string, value: string): void;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function header(request: PasskeyHttpRequest, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === 'string' ? value : value?.[0];
}

function context(request: PasskeyHttpRequest): PasskeyRequestContext {
  const networkAddress =
    request.ip?.slice(0, 128) || request.socket.remoteAddress?.slice(0, 128) || 'unavailable';
  const userAgent = header(request, 'user-agent')?.slice(0, 120) || 'unavailable';
  return Object.freeze({
    correlationId: request.correlationId as CorrelationId,
    fingerprint: `${networkAddress}|${userAgent}`,
    networkAddress,
  });
}

function finishBody<T>(
  value: unknown,
  correlationId: CorrelationId,
): {
  readonly ceremonyId: Uuid;
  readonly response: T;
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authHttpException('auth.invalid-passkey', correlationId);
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'ceremonyId,response' ||
    typeof record.ceremonyId !== 'string' ||
    !uuidPattern.test(record.ceremonyId) ||
    record.response === null ||
    typeof record.response !== 'object' ||
    Array.isArray(record.response)
  ) {
    throw authHttpException('auth.invalid-passkey', correlationId);
  }
  return Object.freeze({ ceremonyId: record.ceremonyId as Uuid, response: record.response as T });
}

@Controller('passkeys')
export class PasskeyController {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  @Post('registration/options')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  async registrationOptions(@Req() request: PasskeyHttpRequest) {
    const sessionToken = this.runtime.sessionCookie.read(header(request, 'cookie'));
    if (sessionToken === null) {
      throw authHttpException('auth.invalid-session', request.correlationId as CorrelationId);
    }
    try {
      return await this.runtime.passkeyService.beginRegistration(sessionToken, context(request));
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }

  @Post('registration/verify')
  @HttpCode(HttpStatus.CREATED)
  @Header('Cache-Control', 'no-store')
  async registrationVerify(@Body() body: unknown, @Req() request: PasskeyHttpRequest) {
    const correlationId = request.correlationId as CorrelationId;
    const sessionToken = this.runtime.sessionCookie.read(header(request, 'cookie'));
    if (sessionToken === null) throw authHttpException('auth.invalid-session', correlationId);
    const input = finishBody<RegistrationResponseJSON>(
      body,
      correlationId,
    ) satisfies PasskeyRegistrationFinishInput;
    try {
      return await this.runtime.passkeyService.finishRegistration(
        sessionToken,
        input,
        context(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId);
    }
  }

  @Post('authentication/options')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  async authenticationOptions(@Req() request: PasskeyHttpRequest) {
    try {
      return await this.runtime.passkeyService.beginAuthentication(context(request));
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }

  @Post('authentication/verify')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  async authenticationVerify(
    @Body() body: unknown,
    @Req() request: PasskeyHttpRequest,
    @Res({ passthrough: true }) response: PasskeyHttpResponse,
  ) {
    const correlationId = request.correlationId as CorrelationId;
    const input = finishBody<AuthenticationResponseJSON>(
      body,
      correlationId,
    ) satisfies PasskeyAuthenticationFinishInput;
    try {
      const session = await this.runtime.passkeyService.finishAuthentication(
        input,
        context(request),
      );
      response.setHeader('Set-Cookie', this.runtime.sessionCookie.issue(session.sessionToken));
      return Object.freeze({
        absoluteExpiresAt: session.absoluteExpiresAt,
        idleExpiresAt: session.idleExpiresAt,
        sessionId: session.sessionId,
        userId: session.userId,
      });
    } catch (error) {
      toAuthHttpException(error, correlationId);
    }
  }
}
