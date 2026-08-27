import type { DynamicModule } from '@nestjs/common';
import type { OnApplicationShutdown } from '@nestjs/common';
import { Inject, Injectable, Module } from '@nestjs/common';

import { AuthAdministrationController } from './a2/auth-administration.controller.js';
import { AuthSessionController } from './a2/auth-session.controller.js';
import { OidcInteractionController } from './a2/oidc-interaction.controller.js';
import { PasskeyController } from './a2/passkey.controller.js';
import { authRuntimeToken } from './a2/runtime.js';
import type { AuthRuntime } from './a2/runtime.js';
import { HealthController } from './health.controller.js';

@Injectable()
class AuthRuntimeLifecycle implements OnApplicationShutdown {
  constructor(@Inject(authRuntimeToken) private readonly runtime: AuthRuntime) {}

  async onApplicationShutdown(): Promise<void> {
    await this.runtime.close();
  }
}

@Module({ controllers: [HealthController] })
export class AuthModule {
  static register(runtime: AuthRuntime): DynamicModule {
    return {
      controllers: [
        AuthAdministrationController,
        AuthSessionController,
        OidcInteractionController,
        PasskeyController,
      ],
      module: AuthModule,
      providers: [{ provide: authRuntimeToken, useValue: runtime }, AuthRuntimeLifecycle],
    };
  }
}
