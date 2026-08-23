import type { INestApplication } from '@nestjs/common';

type StartableWorkerApplication = Pick<
  INestApplication,
  'close' | 'enableShutdownHooks' | 'listen'
>;

export async function listenWorkerApplication(
  app: StartableWorkerApplication,
  port: number,
  host: string,
): Promise<void> {
  try {
    app.enableShutdownHooks();
    await app.listen(port, host);
  } catch (error) {
    await app.close().catch(() => undefined);
    throw error;
  }
}
