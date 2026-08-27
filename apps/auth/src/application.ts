import type { IncomingMessage, ServerResponse } from 'node:http';

import type { INestApplication } from '@nestjs/common';
import { loadServiceConfig, toNestLoggerLevels } from '@kovcheg/config';
import type { ServiceRuntimeConfig } from '@kovcheg/config';
import { correlationIdMiddleware } from '@kovcheg/contracts';
import { NestFactory } from '@nestjs/core';

import { AuthModule } from './auth.module.js';
import type { AuthRuntime } from './a2/runtime.js';
import { configureOpenApi } from './openapi.js';

function isNestOwnedPath(url: string | undefined): boolean {
  const path = url?.split('?', 1)[0] ?? '';
  return (
    path === '/openapi.json' ||
    path === '/session' ||
    path === '/internal/session' ||
    path.startsWith('/passkeys/') ||
    path === '/session/challenges' ||
    path.startsWith('/session/challenges/') ||
    path === '/admin/accounts' ||
    path.startsWith('/admin/accounts/') ||
    path === '/health' ||
    path.startsWith('/health/') ||
    path === '/docs' ||
    path.startsWith('/docs/') ||
    path.startsWith('/interaction/')
  );
}

export async function createAuthApplication(
  config: ServiceRuntimeConfig = loadServiceConfig('auth'),
  runtime?: AuthRuntime,
): Promise<INestApplication> {
  const app = await NestFactory.create(
    runtime === undefined ? AuthModule : AuthModule.register(runtime),
    {
      logger: toNestLoggerLevels(config.logLevel),
    },
  );
  const httpApplication = app.getHttpAdapter().getInstance() as {
    set(setting: string, value: unknown): void;
  };
  httpApplication.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
  app.use(correlationIdMiddleware);
  if (runtime !== undefined) {
    const oidcHandler = runtime.oidcProvider.callback();
    app.use((request: IncomingMessage, response: ServerResponse, next: () => void) => {
      if (isNestOwnedPath(request.url)) {
        next();
        return;
      }
      oidcHandler(request, response);
    });
  }
  configureOpenApi(app, config.nodeEnv !== 'production');
  await app.init();
  return app;
}
