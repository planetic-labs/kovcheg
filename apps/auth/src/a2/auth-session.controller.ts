import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ApiExcludeEndpoint, ApiOkResponse } from '@nestjs/swagger';

import { currentPrincipalAuthorizationJsonSchema } from '@kovcheg/contracts';
import type { CorrelationId, Uuid } from '@kovcheg/contracts';

import { authHttpException, toAuthHttpException } from './http-errors.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

interface AuthHttpRequest {
  readonly correlationId?: CorrelationId;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly ip?: string | undefined;
  readonly socket: { readonly remoteAddress?: string | undefined };
}

function correlationId(request: AuthHttpRequest): CorrelationId {
  return request.correlationId as CorrelationId;
}

interface AuthHttpResponse {
  setHeader(name: string, value: string): void;
}

function headerValue(headers: AuthHttpRequest['headers'], name: string): string | undefined {
  const value = headers[name];
  return typeof value === 'string' ? value : value?.[0];
}

function requestDimensions(request: AuthHttpRequest): {
  readonly fingerprint: string;
  readonly networkAddress: string;
} {
  const networkAddress =
    request.ip?.slice(0, 128) || request.socket.remoteAddress?.slice(0, 128) || 'unavailable';
  const userAgent = headerValue(request.headers, 'user-agent')?.slice(0, 120) || 'unavailable';
  return Object.freeze({
    fingerprint: `${networkAddress}|${userAgent}`,
    networkAddress,
  });
}

function cookieHeader(request: AuthHttpRequest): string | undefined {
  return headerValue(request.headers, 'cookie');
}

@Controller()
export class AuthSessionController {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  @Post('session/challenges')
  @HttpCode(HttpStatus.ACCEPTED)
  @Header('Cache-Control', 'no-store')
  async requestChallenge(
    @Body() body: Readonly<{ email?: unknown }> | undefined,
    @Req() request: AuthHttpRequest,
  ) {
    const gateToken = this.runtime.personalGateCookie.read(cookieHeader(request));
    if (gateToken === null) {
      throw authHttpException('auth.invalid-gate', correlationId(request));
    }
    try {
      return await this.runtime.authService.requestPersonalGateEmailChallenge(gateToken, {
        correlationId: correlationId(request),
        email: typeof body?.email === 'string' ? body.email : '',
        ...requestDimensions(request),
      });
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @Post('session/challenges/:challengeId/verify')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  async verifyChallenge(
    @Param('challengeId') challengeId: string,
    @Body() body: Readonly<{ code?: unknown }> | undefined,
    @Req() request: AuthHttpRequest,
    @Res({ passthrough: true }) response: AuthHttpResponse,
  ) {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        challengeId,
      )
    ) {
      throw authHttpException('auth.invalid-or-expired-challenge', correlationId(request));
    }
    const gateToken = this.runtime.personalGateCookie.read(cookieHeader(request));
    if (gateToken === null) {
      throw authHttpException('auth.invalid-gate', correlationId(request));
    }
    try {
      const session = await this.runtime.authService.verifyPersonalGateEmailChallenge(gateToken, {
        challengeId: challengeId as Uuid,
        code: typeof body?.code === 'string' ? body.code : '',
        networkAddress: requestDimensions(request).networkAddress,
      });
      response.setHeader('Set-Cookie', this.runtime.sessionCookie.issue(session.sessionToken));
      return Object.freeze({
        absoluteExpiresAt: session.absoluteExpiresAt,
        idleExpiresAt: session.idleExpiresAt,
        sessionId: session.sessionId,
        userId: session.userId,
      });
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @Get('session')
  @Header('Cache-Control', 'no-store')
  @ApiOkResponse({ schema: currentPrincipalAuthorizationJsonSchema })
  async getSession(@Req() request: AuthHttpRequest) {
    const token = this.runtime.sessionCookie.read(cookieHeader(request));
    if (token === null) {
      throw authHttpException('auth.invalid-session', correlationId(request));
    }
    try {
      return await this.runtime.authService.authenticateSession(token);
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @Get('internal/session')
  @Header('Cache-Control', 'no-store')
  @ApiExcludeEndpoint()
  async validateSession(@Req() request: AuthHttpRequest) {
    const token = this.runtime.sessionCookie.read(cookieHeader(request));
    if (token === null) {
      throw authHttpException('auth.invalid-session', correlationId(request));
    }
    try {
      return await this.runtime.authService.validateSession(token);
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @Delete('session')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Header('Cache-Control', 'no-store')
  async logout(
    @Req() request: AuthHttpRequest,
    @Res({ passthrough: true }) response: AuthHttpResponse,
  ): Promise<void> {
    const token = this.runtime.sessionCookie.read(cookieHeader(request));
    response.setHeader('Set-Cookie', this.runtime.sessionCookie.clear());
    if (token !== null) {
      try {
        await this.runtime.authService.logout(token);
      } catch (error) {
        toAuthHttpException(error, correlationId(request));
      }
    }
  }
}
