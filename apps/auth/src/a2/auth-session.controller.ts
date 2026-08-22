import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Param,
  Post,
  Req,
  Res,
} from '@nestjs/common';

import type { Uuid } from '@kovcheg/contracts';

import { toAuthHttpException } from './http-errors.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

interface AuthHttpRequest {
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly socket: { readonly remoteAddress?: string | undefined };
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
  const networkAddress = request.socket.remoteAddress?.slice(0, 128) || 'unavailable';
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
    try {
      return await this.runtime.authService.requestEmailChallenge({
        email: typeof body?.email === 'string' ? body.email : '',
        ...requestDimensions(request),
      });
    } catch (error) {
      toAuthHttpException(error);
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
      throw new HttpException(
        Object.freeze({ error: 'auth.invalid-or-expired-challenge' }),
        HttpStatus.UNAUTHORIZED,
      );
    }
    try {
      const session = await this.runtime.authService.verifyEmailChallenge({
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
      toAuthHttpException(error);
    }
  }

  @Get('session')
  @Header('Cache-Control', 'no-store')
  async getSession(@Req() request: AuthHttpRequest) {
    const token = this.runtime.sessionCookie.read(cookieHeader(request));
    if (token === null) {
      throw new HttpException(
        Object.freeze({ error: 'auth.invalid-session' }),
        HttpStatus.UNAUTHORIZED,
      );
    }
    try {
      return await this.runtime.authService.authenticateSession(token);
    } catch (error) {
      toAuthHttpException(error);
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
        toAuthHttpException(error);
      }
    }
  }
}
