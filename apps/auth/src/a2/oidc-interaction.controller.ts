import type { IncomingMessage, ServerResponse } from 'node:http';

import { Controller, Get, HttpException, HttpStatus, Inject, Req, Res } from '@nestjs/common';

import { toAuthHttpException } from './http-errors.js';
import { completeOidcInteraction } from './oidc.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

type InteractionRequest = IncomingMessage & {
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
      throw new HttpException(
        Object.freeze({ error: 'auth.invalid-session' }),
        HttpStatus.UNAUTHORIZED,
      );
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
      toAuthHttpException(error);
    }
  }
}
