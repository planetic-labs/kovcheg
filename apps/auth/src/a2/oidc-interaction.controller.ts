import type { IncomingMessage, ServerResponse } from 'node:http';

import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ApiExcludeEndpoint } from '@nestjs/swagger';
import type { CorrelationId } from '@kovcheg/contracts';

import { authHttpException, toAuthHttpException } from './http-errors.js';
import { completeOidcInteraction, resolveOidcApplicationIdentity } from './oidc.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

type InteractionRequest = IncomingMessage & {
  readonly correlationId?: CorrelationId;
  readonly headers: IncomingMessage['headers'];
};

@Controller()
export class OidcInteractionController {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  @Get('interaction/:uid')
  async complete(
    @Req() request: InteractionRequest,
    @Res() response: ServerResponse,
  ): Promise<void> {
    const sessionToken = this.runtime.sessionCookie.read(request.headers.cookie);
    if (sessionToken === null) {
      throw authHttpException('auth.invalid-session', request.correlationId as CorrelationId);
    }
    try {
      await completeOidcInteraction({
        authService: this.runtime.authService,
        clock: this.runtime.clock,
        provider: this.runtime.oidcProvider,
        request,
        response,
        sessionToken,
      });
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }

  @Post('internal/oidc/session')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Header('Cache-Control', 'no-store')
  @ApiExcludeEndpoint()
  async createApplicationSession(
    @Body() body: Readonly<{ accessToken?: unknown }> | undefined,
    @Req() request: InteractionRequest,
    @Res({ passthrough: true }) response: ServerResponse,
  ): Promise<void> {
    if (
      body === undefined ||
      typeof body.accessToken !== 'string' ||
      Object.keys(body).length !== 1
    ) {
      throw authHttpException('auth.invalid-session', request.correlationId as CorrelationId);
    }
    try {
      const accountId = await resolveOidcApplicationIdentity({
        accessToken: body.accessToken,
        applicationClientId: this.runtime.oidcApplicationClientId,
        provider: this.runtime.oidcProvider,
      });
      const session = await this.runtime.authService.createOidcSession({
        accessToken: body.accessToken,
        accountId,
        correlationId: request.correlationId as CorrelationId,
      });
      response.setHeader('Set-Cookie', this.runtime.sessionCookie.issue(session.sessionToken));
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }
}
