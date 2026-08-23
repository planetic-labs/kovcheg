import { timingSafeEqual } from 'node:crypto';

import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';

import { RealtimeGateway } from './realtime.gateway.js';

export const realtimeRelayToken = Symbol('realtimeRelayToken');

@ApiExcludeController()
@Controller('internal/realtime')
export class RealtimeRelayController {
  constructor(
    @Inject(RealtimeGateway) private readonly realtime: RealtimeGateway,
    @Inject(realtimeRelayToken) private readonly relayToken: string | null,
  ) {}

  @HttpCode(HttpStatus.ACCEPTED)
  @Post('events')
  async accept(
    @Headers('authorization') authorization: string | undefined,
    @Body() body: unknown,
  ): Promise<Readonly<{ accepted: true }>> {
    if (!this.authorized(authorization)) {
      throw new UnauthorizedException();
    }
    if (!(await this.realtime.emitMessageCreated(body))) {
      throw new ServiceUnavailableException();
    }
    return Object.freeze({ accepted: true });
  }

  private authorized(authorization: string | undefined): boolean {
    if (this.relayToken === null || authorization === undefined) {
      return false;
    }
    const expected = Buffer.from(`Bearer ${this.relayToken}`, 'utf8');
    const actual = Buffer.from(authorization, 'utf8');
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }
}
