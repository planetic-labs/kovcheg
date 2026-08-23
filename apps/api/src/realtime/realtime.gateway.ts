import type { RealtimeReadyEvent, RealtimeSubscribeResult, UserId } from '@kovcheg/contracts';
import {
  identityStubHeaderName,
  parseMessageCreatedRealtimeEvent,
  parseRealtimeSubscribeRequest,
  realtimeContractVersion,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '@kovcheg/contracts';
import { Inject, Logger } from '@nestjs/common';
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import type { OnGatewayConnection } from '@nestjs/websockets';
import type { Server, Socket } from 'socket.io';

import type { MessageFlowIdentityProvider } from '../message-flow/message-flow.repository.js';
import { messageFlowIdentityProviderToken } from '../message-flow/message-flow.repository.js';
import type { RealtimeRepository } from './realtime.repository.js';
import { RealtimeRepositoryError, realtimeRepositoryToken } from './realtime.repository.js';

export const realtimeInstanceIdToken = Symbol('realtimeInstanceId');

interface RealtimeSocketData {
  userId?: UserId;
}

@WebSocketGateway({
  path: realtimeSocketPath,
  transports: ['polling', 'websocket'],
})
export class RealtimeGateway implements OnGatewayConnection {
  @WebSocketServer()
  private server!: Server;

  private readonly logger = new Logger(RealtimeGateway.name);

  constructor(
    @Inject(messageFlowIdentityProviderToken)
    private readonly identities: MessageFlowIdentityProvider,
    @Inject(realtimeRepositoryToken)
    private readonly repository: RealtimeRepository,
    @Inject(realtimeInstanceIdToken)
    private readonly instanceId: string,
  ) {}

  async handleConnection(socket: Socket): Promise<void> {
    const identityValue = socket.handshake.auth[identityStubHeaderName];
    if (!this.identities.available || typeof identityValue !== 'string') {
      this.reject(socket);
      return;
    }
    const identity = await this.identities.findById(identityValue as UserId);
    if (identity === null || identity.status !== 'active') {
      this.reject(socket);
      return;
    }
    (socket.data as RealtimeSocketData).userId = identityValue as UserId;
    const ready: RealtimeReadyEvent = Object.freeze({
      contractVersion: realtimeContractVersion,
      instanceId: this.instanceId,
    });
    socket.emit(realtimeSocketEvents.ready, ready);
  }

  @SubscribeMessage(realtimeSocketEvents.subscribe)
  async subscribe(
    @ConnectedSocket() socket: Socket,
    @MessageBody() value: unknown,
  ): Promise<RealtimeSubscribeResult> {
    const request = parseRealtimeSubscribeRequest(value);
    const userId = (socket.data as RealtimeSocketData).userId;
    if (request === null || userId === undefined) {
      return this.rejectedSubscription('0');
    }
    try {
      const subscription = await this.repository.subscribe({
        afterSequence: request.afterSequence,
        chatId: request.chatId,
        limit: 100,
        userId,
      });
      await socket.join(`chat:${request.chatId}`);
      return Object.freeze({
        contractVersion: realtimeContractVersion,
        history: subscription.history,
        joined: true,
        nextAfterSequence: subscription.history.at(-1)?.chatSequence ?? request.afterSequence,
      });
    } catch (error) {
      if (!(error instanceof RealtimeRepositoryError)) {
        this.logger.error('Realtime subscription failed');
      }
      return this.rejectedSubscription(request.afterSequence);
    }
  }

  async emitMessageCreated(value: unknown): Promise<boolean> {
    const event = parseMessageCreatedRealtimeEvent(value);
    if (event === null) {
      return false;
    }
    try {
      await this.server.of('/').adapter.serverCount();
      this.server
        .to(`chat:${event.payload.chatId}`)
        .emit(realtimeSocketEvents.messageCreated, event);
      return true;
    } catch {
      return false;
    }
  }

  private reject(socket: Socket): void {
    socket.emit(realtimeSocketEvents.error, Object.freeze({ code: 'realtime.unauthenticated' }));
    socket.disconnect(true);
  }

  private rejectedSubscription(afterSequence: string): RealtimeSubscribeResult {
    return Object.freeze({
      contractVersion: realtimeContractVersion,
      history: Object.freeze([]),
      joined: false,
      nextAfterSequence: afterSequence,
    });
  }
}
