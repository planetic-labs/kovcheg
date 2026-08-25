import type {
  AvailableChatList,
  ChatAdministrationResponse,
  CorrelationId,
  CorrelationRequest,
  CreateTextMessageResponse,
  MessageHistoryPage,
} from '@kovcheg/contracts';
import {
  availableChatListJsonSchema,
  chatAdministrationResponseJsonSchema,
  createGroupChatRequestJsonSchema,
  createTextMessageRequestJsonSchema,
  createTextMessageResponseJsonSchema,
  machineErrorJsonSchema,
  messageHistoryPageJsonSchema,
  setChatAdministratorRequestJsonSchema,
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
  ApiCookieAuth,
  ApiForbiddenResponse,
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
@ApiCookieAuth('applicationSession')
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
    @Headers('cookie') cookieHeader: string | undefined,
    @Body() body: unknown,
    @Req() request: CorrelationRequest,
    @Res({ passthrough: true }) response: StatusResponse,
  ): Promise<CreateTextMessageResponse> {
    const result = await this.messageFlow.createTextMessage(
      chatId,
      cookieHeader,
      body,
      request.correlationId as CorrelationId,
    );
    response.status(result.outcome === 'created' ? HttpStatus.CREATED : HttpStatus.OK);
    return result;
  }

  @ApiQuery({
    description:
      'Return newer messages for forward catch-up. Mutually exclusive with beforeSequence; when neither cursor is present, the latest page is returned.',
    name: 'afterSequence',
    required: false,
    schema: { pattern: '^(0|[1-9][0-9]*)$', type: 'string' },
  })
  @ApiQuery({
    description:
      'Return older messages with a lower chat sequence. Mutually exclusive with afterSequence.',
    name: 'beforeSequence',
    required: false,
    schema: { pattern: '^[1-9][0-9]*$', type: 'string' },
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
    @Headers('cookie') cookieHeader: string | undefined,
    @Query('afterSequence') afterSequence: string | undefined,
    @Query('beforeSequence') beforeSequence: string | undefined,
    @Query('limit') limit: string | undefined,
    @Req() request: CorrelationRequest,
  ): Promise<MessageHistoryPage> {
    return this.messageFlow.readMessageHistory(
      chatId,
      cookieHeader,
      afterSequence,
      beforeSequence,
      limit,
      request.correlationId as CorrelationId,
    );
  }
}

@ApiTags('chats')
@ApiCookieAuth('applicationSession')
@ApiUnauthorizedResponse(errorResponse)
@ApiServiceUnavailableResponse(errorResponse)
@Controller('chats')
export class ChatListController {
  constructor(@Inject(MessageFlowService) private readonly messageFlow: MessageFlowService) {}

  @ApiOkResponse({ schema: availableChatListJsonSchema })
  @Get()
  listAvailableChats(
    @Headers('cookie') cookieHeader: string | undefined,
    @Req() request: CorrelationRequest,
  ): Promise<AvailableChatList> {
    return this.messageFlow.listAvailableChats(
      cookieHeader,
      request.correlationId as CorrelationId,
    );
  }

  @ApiBody({ schema: createGroupChatRequestJsonSchema })
  @ApiCreatedResponse({ schema: chatAdministrationResponseJsonSchema })
  @ApiBadRequestResponse(errorResponse)
  @ApiForbiddenResponse(errorResponse)
  @Post('groups')
  createGroupChat(
    @Headers('cookie') cookieHeader: string | undefined,
    @Body() body: unknown,
    @Req() request: CorrelationRequest,
  ): Promise<ChatAdministrationResponse> {
    return this.messageFlow.createGroupChat(
      cookieHeader,
      body,
      request.correlationId as CorrelationId,
    );
  }

  @ApiParam({ format: 'uuid', name: 'chatId', type: 'string' })
  @ApiParam({ format: 'uuid', name: 'accountId', type: 'string' })
  @ApiBody({ schema: setChatAdministratorRequestJsonSchema })
  @ApiOkResponse({ schema: chatAdministrationResponseJsonSchema })
  @ApiBadRequestResponse(errorResponse)
  @ApiForbiddenResponse(errorResponse)
  @Post(':chatId/administrators/:accountId')
  setChatAdministrator(
    @Param('chatId') chatId: string,
    @Param('accountId') accountId: string,
    @Headers('cookie') cookieHeader: string | undefined,
    @Body() body: unknown,
    @Req() request: CorrelationRequest,
  ): Promise<ChatAdministrationResponse> {
    return this.messageFlow.setChatAdministrator(
      chatId,
      accountId,
      cookieHeader,
      body,
      request.correlationId as CorrelationId,
    );
  }
}
