import type { IncomingMessage, ServerResponse } from 'node:http';

import { Controller, Get, Inject, Req, Res } from '@nestjs/common';
import type { CorrelationId } from '@kovcheg/contracts';

import { authHttpException, toAuthHttpException } from './http-errors.js';
import { completeOidcInteraction } from './oidc.js';
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
}
