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
import type { CorrelationId } from '@kovcheg/contracts';

import { authHttpException, toAuthHttpException } from './http-errors.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

interface GateHttpRequest {
  readonly correlationId?: CorrelationId;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly ip?: string | undefined;
  readonly socket: { readonly remoteAddress?: string | undefined };
}

interface GateHttpResponse {
  setHeader(name: string, value: string): void;
}

function header(request: GateHttpRequest, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === 'string' ? value : value?.[0];
}

function requestContext(request: GateHttpRequest) {
  const networkAddress =
    request.ip?.slice(0, 128) || request.socket.remoteAddress?.slice(0, 128) || 'unavailable';
  const userAgent = header(request, 'user-agent')?.slice(0, 120) || 'unavailable';
  return Object.freeze({
    correlationId: request.correlationId as CorrelationId,
    fingerprint: `${networkAddress}|${userAgent}`,
    networkAddress,
  });
}

@Controller('personal-gate')
export class PersonalGateController {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  @Get()
  @Header('Cache-Control', 'no-store')
  @Header('Referrer-Policy', 'no-referrer')
  async status(@Req() request: GateHttpRequest) {
    const token = this.runtime.personalGateCookie.read(header(request, 'cookie'));
    if (token === null) return Object.freeze({ status: 'required' });
    try {
      const active = await this.runtime.authService.validatePersonalGate(token);
      return Object.freeze({ status: active ? 'active' : 'required' });
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }

  @Post('activate')
  @HttpCode(HttpStatus.ACCEPTED)
  @Header('Cache-Control', 'no-store')
  @Header('Referrer-Policy', 'no-referrer')
  async activate(
    @Body()
    body: Readonly<{ clientIdempotencyKey?: unknown; code?: unknown }> | undefined,
    @Req() request: GateHttpRequest,
    @Res({ passthrough: true }) response: GateHttpResponse,
  ) {
    if (typeof body?.code !== 'string' || typeof body.clientIdempotencyKey !== 'string') {
      throw authHttpException('auth.invalid-input', request.correlationId as CorrelationId);
    }
    try {
      const activation = await this.runtime.authService.activatePersonalGate(
        body.code,
        body.clientIdempotencyKey,
        requestContext(request),
      );
      if (activation === null) {
        response.setHeader('Set-Cookie', this.runtime.personalGateCookie.clear());
        return Object.freeze({ next: 'gate', status: 'accepted' });
      }
      response.setHeader('Set-Cookie', this.runtime.personalGateCookie.issue(activation.gateToken));
      return Object.freeze({ next: 'email', status: 'accepted' });
    } catch (error) {
      toAuthHttpException(error, request.correlationId as CorrelationId);
    }
  }
}
