import type {
  CorrelationId,
  CorrelationRequest,
  CreateTextMessageResponse,
  MessageHistoryPage,
} from '@kovcheg/contracts';
import {
  createTextMessageRequestJsonSchema,
  createTextMessageResponseJsonSchema,
  identityStubHeaderName,
  machineErrorJsonSchema,
  messageHistoryPageJsonSchema,
} from '@kovcheg/contracts';
import {
  Body,
  Controller,
  Get,
  Headers,
  HttpStatus,
  Inject,
  Param,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiHeader,
  ApiOkResponse,
  ApiParam,
  ApiQuery,
  ApiServiceUnavailableResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

import { MessageFlowService } from './message-flow.service.js';

interface StatusResponse {
  status(code: number): unknown;
}

const errorResponse = Object.freeze({ schema: machineErrorJsonSchema });

@ApiTags('messages')
@ApiHeader({
  description: 'Synthetic A4 identity. The stub is unavailable in production.',
  name: identityStubHeaderName,
  required: true,
  schema: { format: 'uuid', type: 'string' },
})
@ApiParam({ format: 'uuid', name: 'chatId', type: 'string' })
@ApiBadRequestResponse(errorResponse)
@ApiUnauthorizedResponse(errorResponse)
@ApiForbiddenResponse(errorResponse)
@ApiServiceUnavailableResponse(errorResponse)
@Controller('chats/:chatId/messages')
export class MessageFlowController {
  constructor(@Inject(MessageFlowService) private readonly messageFlow: MessageFlowService) {}

  @ApiBody({ schema: createTextMessageRequestJsonSchema })
  @ApiCreatedResponse({ schema: createTextMessageResponseJsonSchema })
  @ApiOkResponse({
    description: 'The original message returned for an idempotent replay.',
    schema: createTextMessageResponseJsonSchema,
  })
  @ApiConflictResponse(errorResponse)
  @Post()
  async createTextMessage(
    @Param('chatId') chatId: string,
    @Headers(identityStubHeaderName) identityStubUserId: string | undefined,
    @Body() body: unknown,
    @Req() request: CorrelationRequest,
    @Res({ passthrough: true }) response: StatusResponse,
  ): Promise<CreateTextMessageResponse> {
    const result = await this.messageFlow.createTextMessage(
      chatId,
      identityStubUserId,
      body,
      request.correlationId as CorrelationId,
    );
    response.status(result.outcome === 'created' ? HttpStatus.CREATED : HttpStatus.OK);
    return result;
  }

  @ApiQuery({
    description: 'Return messages with a greater chat sequence.',
    name: 'afterSequence',
    required: false,
    schema: { default: '0', pattern: '^(0|[1-9][0-9]*)$', type: 'string' },
  })
  @ApiQuery({
    description: 'Page size from 1 through 100.',
    name: 'limit',
    required: false,
    schema: { default: 50, maximum: 100, minimum: 1, type: 'integer' },
  })
  @ApiOkResponse({ schema: messageHistoryPageJsonSchema })
  @Get()
  readMessageHistory(
    @Param('chatId') chatId: string,
    @Headers(identityStubHeaderName) identityStubUserId: string | undefined,
    @Query('afterSequence') afterSequence: string | undefined,
    @Query('limit') limit: string | undefined,
    @Req() request: CorrelationRequest,
  ): Promise<MessageHistoryPage> {
    return this.messageFlow.readMessageHistory(
      chatId,
      identityStubUserId,
      afterSequence,
      limit,
      request.correlationId as CorrelationId,
    );
  }
}
