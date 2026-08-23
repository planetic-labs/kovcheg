import { realtimeAdapterStreamName } from '@kovcheg/contracts';
import type { INestApplicationContext } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-streams-adapter';
import { createClient } from 'redis';
import type { Server, ServerOptions } from 'socket.io';

export class RedisStreamsIoAdapter extends IoAdapter {
  private closed = false;
  private readonly client: ReturnType<typeof createClient>;

  constructor(app: INestApplicationContext, redisUrl: string) {
    super(app);
    this.client = createClient({ url: redisUrl });
    this.client.on('error', () => undefined);
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  override createIOServer(port: number, options?: ServerOptions): Server {
    const server = super.createIOServer(port, options) as Server;
    server.adapter(
      createAdapter(this.client, {
        channelPrefix: 'kovcheg:socket.io:control:v1',
        maxLen: 10_000,
        onlyPlaintext: true,
        streamName: realtimeAdapterStreamName,
      }),
    );
    server.use((_socket, next) => {
      if (this.client.isReady) {
        next();
        return;
      }
      this.client.once('ready', next);
    });
    this.client.on('reconnecting', () => {
      for (const socket of server.sockets.sockets.values()) {
        socket.conn.close();
      }
    });
    return server;
  }

  override async close(server: Server): Promise<void> {
    await super.close(server);
    if (!this.closed) {
      this.closed = true;
      await this.client.quit().catch(() => undefined);
    }
  }
}
