import { domainStatuses, functionalGrants } from '@kovcheg/contracts';
import type {
  CorrelationId,
  DomainStatus,
  FunctionalGrant,
  SessionId,
  UserId,
} from '@kovcheg/contracts';
import {
  Body,
  Controller,
  Delete,
  Header,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Patch,
  Post,
  Put,
  Req,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiParam,
  ApiServiceUnavailableResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

import type { AccountRecord, AccountStatus } from './contracts.js';
import { authHttpException, toAuthHttpException } from './http-errors.js';
import type { AuthRuntime } from './runtime.js';
import { authRuntimeToken } from './runtime.js';

interface AdministrationRequest {
  readonly correlationId?: CorrelationId;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const accountSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    accountAccess: { enum: ['member'], type: 'string' },
    displayName: { maxLength: 120, minLength: 1, type: 'string' },
    domainStatus: { enum: [...domainStatuses], type: 'string' },
    email: { format: 'email', maxLength: 254, type: 'string' },
    functionalGrants: { items: { enum: [...functionalGrants] }, type: 'array' },
    status: { enum: ['active', 'deactivated'] },
    userId: { format: 'uuid', type: 'string' },
  },
  required: [
    'accountAccess',
    'displayName',
    'domainStatus',
    'email',
    'functionalGrants',
    'status',
    'userId',
  ],
  type: 'object',
});

const errorSchema = Object.freeze({
  additionalProperties: false,
  properties: {
    correlationId: { maxLength: 128, minLength: 1, type: 'string' },
    error: {
      enum: [
        'auth.conflict',
        'auth.forbidden',
        'auth.invalid-input',
        'auth.invalid-session',
        'auth.not-found',
        'auth.unavailable',
      ],
    },
  },
  required: ['correlationId', 'error'],
  type: 'object',
});

const errorResponse = Object.freeze({ schema: errorSchema });
const accountIdParameter = Object.freeze({ format: 'uuid', name: 'accountId', type: 'string' });

function headerValue(headers: AdministrationRequest['headers'], name: string): string | undefined {
  const value = headers[name];
  return typeof value === 'string' ? value : value?.[0];
}

function correlationId(request: AdministrationRequest): CorrelationId {
  return request.correlationId as CorrelationId;
}

function userId(value: string, request: AdministrationRequest): UserId {
  if (!uuidPattern.test(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return value as UserId;
}

function sessionId(value: string, request: AdministrationRequest): SessionId {
  if (!uuidPattern.test(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return value as SessionId;
}

function accountInput(
  value: unknown,
  request: AdministrationRequest,
): Readonly<{ displayName: string; email: string }> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'displayName,email' ||
    typeof record.displayName !== 'string' ||
    typeof record.email !== 'string'
  ) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return Object.freeze({ displayName: record.displayName, email: record.email });
}

function accountStatus(value: unknown, request: AdministrationRequest): AccountStatus {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).join(',') !== 'status' ||
    (record.status !== 'active' && record.status !== 'deactivated')
  ) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return record.status;
}

function authorizationMutationInput(
  value: unknown,
  request: AdministrationRequest,
): Readonly<{ reason: string; version: number }> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'reason,version' ||
    typeof record.reason !== 'string' ||
    typeof record.version !== 'number'
  ) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return Object.freeze({ reason: record.reason, version: record.version });
}

function domainStatusInput(
  value: unknown,
  request: AdministrationRequest,
): Readonly<{ domainStatus: DomainStatus; reason: string; version: number }> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(',') !== 'domainStatus,reason,version' ||
    !domainStatuses.includes(record.domainStatus as DomainStatus) ||
    typeof record.reason !== 'string' ||
    typeof record.version !== 'number'
  ) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return Object.freeze({
    domainStatus: record.domainStatus as DomainStatus,
    reason: record.reason,
    version: record.version,
  });
}

function functionalGrant(value: string, request: AdministrationRequest): FunctionalGrant {
  if (!functionalGrants.includes(value as FunctionalGrant)) {
    throw authHttpException('auth.invalid-input', correlationId(request));
  }
  return value as FunctionalGrant;
}

@ApiTags('auth administration')
@ApiBadRequestResponse(errorResponse)
@ApiUnauthorizedResponse(errorResponse)
@ApiForbiddenResponse(errorResponse)
@ApiNotFoundResponse(errorResponse)
@ApiConflictResponse(errorResponse)
@ApiServiceUnavailableResponse(errorResponse)
@Controller('admin/accounts')
export class AuthAdministrationController {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  @ApiBody({
    schema: {
      additionalProperties: false,
      properties: {
        displayName: { maxLength: 120, minLength: 1, type: 'string' },
        email: { format: 'email', maxLength: 254, type: 'string' },
      },
      required: ['displayName', 'email'],
      type: 'object',
    },
  })
  @ApiCreatedResponse({ schema: accountSchema })
  @Post()
  @Header('Cache-Control', 'no-store')
  async createAccount(
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    try {
      return await this.runtime.authService.createAccount(
        this.administratorSessionToken(request),
        accountInput(body, request),
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiBody({
    schema: {
      additionalProperties: false,
      properties: {
        displayName: { maxLength: 120, minLength: 1, type: 'string' },
        email: { format: 'email', maxLength: 254, type: 'string' },
      },
      required: ['displayName', 'email'],
      type: 'object',
    },
  })
  @ApiOkResponse({ schema: accountSchema })
  @Patch(':accountId')
  @Header('Cache-Control', 'no-store')
  async updateAccount(
    @Param('accountId') accountId: string,
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    try {
      return await this.runtime.authService.updateAccount(
        this.administratorSessionToken(request),
        userId(accountId, request),
        accountInput(body, request),
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiBody({
    schema: {
      additionalProperties: false,
      properties: { status: { enum: ['active', 'deactivated'] } },
      required: ['status'],
      type: 'object',
    },
  })
  @ApiOkResponse({ schema: accountSchema })
  @Patch(':accountId/status')
  @Header('Cache-Control', 'no-store')
  async setAccountStatus(
    @Param('accountId') accountId: string,
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    try {
      return await this.runtime.authService.setAccountStatus(
        this.administratorSessionToken(request),
        userId(accountId, request),
        accountStatus(body, request),
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiOkResponse({ schema: accountSchema })
  @Patch(':accountId/domain-status')
  @Header('Cache-Control', 'no-store')
  async setDomainStatus(
    @Param('accountId') accountId: string,
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    const input = domainStatusInput(body, request);
    try {
      return await this.runtime.authService.setDomainStatus(
        this.administratorSessionToken(request),
        userId(accountId, request),
        input.domainStatus,
        input,
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiParam({ enum: [...functionalGrants], name: 'grant', type: 'string' })
  @ApiOkResponse({ schema: accountSchema })
  @Put(':accountId/functional-grants/:grant')
  @Header('Cache-Control', 'no-store')
  async grantFunctionalGrant(
    @Param('accountId') accountId: string,
    @Param('grant') grant: string,
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    try {
      return await this.runtime.authService.grantFunctionalGrant(
        this.administratorSessionToken(request),
        userId(accountId, request),
        functionalGrant(grant, request),
        authorizationMutationInput(body, request),
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiParam({ enum: [...functionalGrants], name: 'grant', type: 'string' })
  @ApiOkResponse({ schema: accountSchema })
  @Delete(':accountId/functional-grants/:grant')
  @Header('Cache-Control', 'no-store')
  async revokeFunctionalGrant(
    @Param('accountId') accountId: string,
    @Param('grant') grant: string,
    @Body() body: unknown,
    @Req() request: AdministrationRequest,
  ): Promise<AccountRecord> {
    try {
      return await this.runtime.authService.revokeFunctionalGrant(
        this.administratorSessionToken(request),
        userId(accountId, request),
        functionalGrant(grant, request),
        authorizationMutationInput(body, request),
        correlationId(request),
      );
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiParam({ format: 'uuid', name: 'sessionId', type: 'string' })
  @ApiOkResponse({
    schema: {
      additionalProperties: false,
      properties: { revoked: { type: 'boolean' } },
      required: ['revoked'],
      type: 'object',
    },
  })
  @Delete(':accountId/sessions/:sessionId')
  @Header('Cache-Control', 'no-store')
  async revokeSession(
    @Param('accountId') accountId: string,
    @Param('sessionId') sessionIdentifier: string,
    @Req() request: AdministrationRequest,
  ): Promise<Readonly<{ revoked: boolean }>> {
    try {
      const revoked = await this.runtime.authService.revokeSession(
        this.administratorSessionToken(request),
        userId(accountId, request),
        sessionId(sessionIdentifier, request),
        correlationId(request),
      );
      return Object.freeze({ revoked });
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  @ApiParam(accountIdParameter)
  @ApiOkResponse({
    schema: {
      additionalProperties: false,
      properties: { revokedSessionCount: { minimum: 0, type: 'integer' } },
      required: ['revokedSessionCount'],
      type: 'object',
    },
  })
  @Delete(':accountId/sessions')
  @Header('Cache-Control', 'no-store')
  @HttpCode(HttpStatus.OK)
  async revokeAllSessions(
    @Param('accountId') accountId: string,
    @Req() request: AdministrationRequest,
  ): Promise<Readonly<{ revokedSessionCount: number }>> {
    try {
      const revokedSessionCount = await this.runtime.authService.revokeAllSessions(
        this.administratorSessionToken(request),
        userId(accountId, request),
        correlationId(request),
      );
      return Object.freeze({ revokedSessionCount });
    } catch (error) {
      toAuthHttpException(error, correlationId(request));
    }
  }

  private administratorSessionToken(request: AdministrationRequest): string {
    const token = this.runtime.sessionCookie.read(headerValue(request.headers, 'cookie'));
    if (token === null) {
      throw authHttpException('auth.invalid-session', correlationId(request));
    }
    return token;
  }
}
