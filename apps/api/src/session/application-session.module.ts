import type { DynamicModule } from '@nestjs/common';
import { Module } from '@nestjs/common';

import type { ApplicationSessionAuthenticator } from './application-session.js';
import {
  applicationSessionAuthenticatorToken,
  UnavailableApplicationSessionAuthenticator,
} from './application-session.js';

@Module({})
export class ApplicationSessionModule {
  static register(authenticator?: ApplicationSessionAuthenticator): DynamicModule {
    return {
      exports: [applicationSessionAuthenticatorToken],
      global: true,
      module: ApplicationSessionModule,
      providers: [
        {
          provide: applicationSessionAuthenticatorToken,
          useValue: authenticator ?? new UnavailableApplicationSessionAuthenticator(),
        },
      ],
    };
  }
}
