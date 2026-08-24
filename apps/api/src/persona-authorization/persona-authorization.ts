import type { UserId, Uuid } from '@kovcheg/contracts';
import type { QueryResult, QueryResultRow } from 'pg';

import type { ApplicationPrincipal } from '../session/application-session.js';

export const personaAuthorizerToken = Symbol('personaAuthorizer');

export interface PersonaAuthorizationCommand {
  readonly now: Date;
  readonly operatorPrincipal: ApplicationPrincipal;
  readonly personaAccountId: string;
}

export interface AuthorizedPersonaAction {
  readonly operatorAccountId: UserId;
  readonly personaAccountId: UserId;
}

type PersonaAuthorizationFailure = 'forbidden' | 'unavailable';

class PersonaAuthorizationError extends Error {
  constructor(readonly failure: PersonaAuthorizationFailure) {
    super(`Persona authorization failed: ${failure}`);
    this.name = 'PersonaAuthorizationError';
  }
}

export interface PersonaAuthorizationTransaction {
  query<Row extends QueryResultRow>(
    text: string,
    values: readonly unknown[],
  ): Promise<QueryResult<Row>>;
}

export interface PersonaAuthorizer {
  authorizeInTransaction(
    transaction: PersonaAuthorizationTransaction,
    command: PersonaAuthorizationCommand,
  ): Promise<AuthorizedPersonaAction>;
}

interface PersonaAuthorizationRow extends QueryResultRow {
  readonly operator_account_id: string;
  readonly persona_account_id: string;
}

const uuidExpression =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function isUuid(value: string): value is Uuid {
  return uuidExpression.test(value);
}

function unavailable(): PersonaAuthorizationError {
  return new PersonaAuthorizationError('unavailable');
}

function mapPostgresError(error: unknown): PersonaAuthorizationError {
  if (error instanceof PersonaAuthorizationError) {
    return error;
  }
  const code = (error as { readonly code?: string }).code;
  return new PersonaAuthorizationError(code === '42501' ? 'forbidden' : 'unavailable');
}

export class PostgresPersonaAuthorizer implements PersonaAuthorizer {
  async authorizeInTransaction(
    transaction: PersonaAuthorizationTransaction,
    command: PersonaAuthorizationCommand,
  ): Promise<AuthorizedPersonaAction> {
    const { operatorPrincipal, personaAccountId } = command;
    if (
      !isUuid(operatorPrincipal.sessionId) ||
      !isUuid(operatorPrincipal.userId) ||
      !isUuid(personaAccountId) ||
      !Number.isFinite(command.now.getTime())
    ) {
      throw new PersonaAuthorizationError('forbidden');
    }

    try {
      const result = await transaction.query<PersonaAuthorizationRow>(
        `SELECT operator_account_id, persona_account_id
         FROM kovcheg.authorize_system_persona_action($1, $2, $3, $4)`,
        [operatorPrincipal.sessionId, operatorPrincipal.userId, personaAccountId, command.now],
      );
      const row = result.rows[0];
      if (
        result.rows.length !== 1 ||
        row === undefined ||
        row.operator_account_id !== operatorPrincipal.userId ||
        row.persona_account_id !== personaAccountId
      ) {
        throw unavailable();
      }
      return Object.freeze({
        operatorAccountId: row.operator_account_id as UserId,
        personaAccountId: row.persona_account_id as UserId,
      });
    } catch (error) {
      throw mapPostgresError(error);
    }
  }
}
