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
import type { OnGatewayConnection, OnGatewayInit } from '@nestjs/websockets';
import type { Server, Socket } from 'socket.io';

import type { ApplicationSessionAuthenticator } from '../session/application-session.js';
import { applicationSessionAuthenticatorToken } from '../session/application-session.js';
import type { RealtimeRepository } from './realtime.repository.js';
import { RealtimeRepositoryError, realtimeRepositoryToken } from './realtime.repository.js';

export const realtimeInstanceIdToken = Symbol('realtimeInstanceId');
const clusterMessageCreatedEvent = 'kovcheg.realtime.message-created';
const clusterDeliveryAckTimeoutMilliseconds = 3_000;

type ClusterDeliveryAcknowledgement = (delivered: boolean) => void;

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
export class RealtimeGateway implements OnGatewayConnection, OnGatewayInit {
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

  afterInit(server: Server): void {
    server.on(
      clusterMessageCreatedEvent,
      (value: unknown, acknowledge?: ClusterDeliveryAcknowledgement) => {
        void this.deliverLocal(value).then((delivered) => {
          if (!delivered) this.logger.error('Cluster realtime delivery failed');
          acknowledge?.(delivered);
        });
      },
    );
  }

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
    if (event === null) return false;
    try {
      if (!(await this.deliverLocal(event))) return false;
      return await this.deliverToLivePeers(event);
    } catch {
      return false;
    }
  }

  private async deliverToLivePeers(value: unknown): Promise<boolean> {
    const serverCount = await this.server.sockets.adapter.serverCount();
    if (serverCount <= 1) return true;

    const responses = await this.withClusterAckTimeout(
      this.server.serverSideEmitWithAck(clusterMessageCreatedEvent, value),
    );
    return responses.length > 0 && responses.every((response) => response === true);
  }

  private withClusterAckTimeout<T>(operation: Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error('Cluster realtime acknowledgement timed out')),
        clusterDeliveryAckTimeoutMilliseconds,
      );
      void operation.then(
        (value) => {
          clearTimeout(timeout);
          resolve(value);
        },
        (error: unknown) => {
          clearTimeout(timeout);
          reject(error instanceof Error ? error : new Error('Cluster realtime delivery failed'));
        },
      );
    });
  }

  private async deliverLocal(value: unknown): Promise<boolean> {
    const event = parseMessageCreatedRealtimeEvent(value);
    if (event === null) return false;
    try {
      const room = `chat:${event.payload.chatId}`;
      const sockets = await this.server.local.in(room).fetchSockets();
      for (const socket of sockets) {
        const principal = await this.authenticateSocket(socket, event.correlationId, false);
        const authorized =
          principal !== null &&
          (await this.repository.canReadChat(principal.userId, event.payload.chatId));
        if (!authorized) {
          await Promise.resolve(socket.leave(room)).catch(() => undefined);
          socket.disconnect(true);
          continue;
        }
        socket.emit(realtimeSocketEvents.messageCreated, event);
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

  private async authenticateSocket(
    socket: SessionSocket,
    correlationId?: CorrelationId,
    recordActivity = true,
  ) {
    const headerValue = socket.handshake.headers[correlationIdHeaderName];
    const requestCorrelationId =
      correlationId ??
      parseCorrelationId(typeof headerValue === 'string' ? headerValue : headerValue?.[0]) ??
      createCorrelationId();
    const cookieValue = socket.handshake.headers.cookie;
    const cookieHeader =
      typeof cookieValue === 'string' ? cookieValue : (cookieValue?.[0] ?? undefined);
    try {
      const principal = recordActivity
        ? await this.sessions.authenticate(cookieHeader, requestCorrelationId)
        : await this.sessions.validate(cookieHeader, requestCorrelationId);
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
