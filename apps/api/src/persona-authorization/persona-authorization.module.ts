import { Module } from '@nestjs/common';

import type { PersonaAuthorizer } from './persona-authorization.js';
import { personaAuthorizerToken, PostgresPersonaAuthorizer } from './persona-authorization.js';

@Module({
  exports: [personaAuthorizerToken],
  providers: [
    {
      provide: personaAuthorizerToken,
      useFactory: (): PersonaAuthorizer => new PostgresPersonaAuthorizer(),
    },
  ],
})
export class PersonaAuthorizationModule {}
