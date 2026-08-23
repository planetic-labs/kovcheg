import type {
  CorrelationId,
  RealtimeReadyEvent,
  RealtimeSubscribeResult,
  SessionId,
  UserId,
} from '@kovcheg/contracts';
import {
  correlationIdHeaderName,
  createCorrelationId,
  parseMessageCreatedRealtimeEvent,
  parseCorrelationId,
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

import type { ApplicationSessionAuthenticator } from '../session/application-session.js';
import { applicationSessionAuthenticatorToken } from '../session/application-session.js';
import type { RealtimeRepository } from './realtime.repository.js';
import { RealtimeRepositoryError, realtimeRepositoryToken } from './realtime.repository.js';

export const realtimeInstanceIdToken = Symbol('realtimeInstanceId');

interface RealtimeSocketData {
  sessionId?: SessionId;
  userId?: UserId;
}

interface SessionSocket {
  readonly data: RealtimeSocketData;
  readonly handshake: {
    readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  };
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
    @Inject(applicationSessionAuthenticatorToken)
    private readonly sessions: ApplicationSessionAuthenticator,
    @Inject(realtimeRepositoryToken)
    private readonly repository: RealtimeRepository,
    @Inject(realtimeInstanceIdToken)
    private readonly instanceId: string,
  ) {}

  async handleConnection(socket: Socket): Promise<void> {
    const principal = await this.authenticateSocket(socket);
    if (principal === null) {
      this.reject(socket);
      return;
    }
    (socket.data as RealtimeSocketData).sessionId = principal.sessionId;
    (socket.data as RealtimeSocketData).userId = principal.userId;
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
    if (request === null) {
      return this.rejectedSubscription('0');
    }
    const principal = await this.authenticateSocket(socket);
    if (principal === null) {
      this.reject(socket);
      return this.rejectedSubscription(request.afterSequence);
    }
    const room = `chat:${request.chatId}`;
    try {
      await socket.join(room);
      const subscription = await this.repository.subscribe({
        afterSequence: request.afterSequence,
        chatId: request.chatId,
        limit: 100,
        userId: principal.userId,
      });
      if ((await this.authenticateSocket(socket)) === null) {
        await Promise.resolve(socket.leave(room)).catch(() => undefined);
        this.reject(socket);
        return this.rejectedSubscription(request.afterSequence);
      }
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
      await Promise.resolve(socket.leave(room)).catch(() => undefined);
      return this.rejectedSubscription(request.afterSequence);
    }
  }

  async emitMessageCreated(value: unknown): Promise<boolean> {
    const event = parseMessageCreatedRealtimeEvent(value);
    if (event === null) {
      return false;
    }
    try {
      const room = `chat:${event.payload.chatId}`;
      const sockets = await this.server.in(room).fetchSockets();
      for (const socket of sockets) {
        const principal = await this.authenticateSocket(socket, event.correlationId);
        const authorized =
          principal !== null &&
          (await this.repository.canReadChat(principal.userId, event.payload.chatId));
        if (!authorized) {
          await Promise.resolve(socket.leave(room)).catch(() => undefined);
          socket.disconnect(true);
          continue;
        }
        this.server.to(socket.id).emit(realtimeSocketEvents.messageCreated, event);
      }
      return true;
    } catch {
      return false;
    }
  }

  private reject(socket: Socket): void {
    socket.emit(realtimeSocketEvents.error, Object.freeze({ code: 'realtime.unauthenticated' }));
    socket.disconnect(true);
  }

  private async authenticateSocket(socket: SessionSocket, correlationId?: CorrelationId) {
    const headerValue = socket.handshake.headers[correlationIdHeaderName];
    const requestCorrelationId =
      correlationId ??
      parseCorrelationId(typeof headerValue === 'string' ? headerValue : headerValue?.[0]) ??
      createCorrelationId();
    const cookieValue = socket.handshake.headers.cookie;
    const cookieHeader =
      typeof cookieValue === 'string' ? cookieValue : (cookieValue?.[0] ?? undefined);
    try {
      const principal = await this.sessions.authenticate(cookieHeader, requestCorrelationId);
      const current = socket.data;
      if (
        (current.sessionId !== undefined && current.sessionId !== principal.sessionId) ||
        (current.userId !== undefined && current.userId !== principal.userId)
      ) {
        return null;
      }
      return principal;
    } catch {
      return null;
    }
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
