/* global process */

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { Pool } from 'pg';

const bootstrapEmail = 'synthetic-local-administrator@auth.invalid';
const sessionIdleLifetimeMs = 7 * 24 * 60 * 60 * 1_000;
const sessionAbsoluteLifetimeMs = 30 * 24 * 60 * 60 * 1_000;

function verifier(secret, namespace, value) {
  return createHmac('sha256', secret)
    .update(namespace, 'utf8')
    .update('\0', 'utf8')
    .update(value, 'utf8')
    .digest('base64url');
}

async function requiredSecret(path) {
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32) throw new Error('Synthetic secret is unavailable');
  return value;
}

const pool = new Pool({
  database: process.env.PGDATABASE ?? 'kovcheg',
  host: process.env.PGHOST ?? 'postgres',
  password: await requiredSecret('/run/secrets/postgres_auth_password'),
  port: Number.parseInt(process.env.PGPORT ?? '5432', 10),
  user: process.env.PGUSER ?? 'kovcheg_auth_app',
});

try {
  const sessionPepper = await requiredSecret('/run/secrets/auth_session_pepper');
  const challengeId = randomUUID();
  const challengeVerifier = randomBytes(32).toString('base64url');
  const sessionId = randomUUID();
  const sessionToken = randomBytes(32).toString('base64url');
  const sessionTokenVerifier = verifier(sessionPepper, 'server-session', sessionToken);
  const now = new Date();
  const challengeExpiresAt = new Date(now.getTime() + 10 * 60 * 1_000);
  const absoluteExpiresAt = new Date(now.getTime() + sessionAbsoluteLifetimeMs);

  const issued = await pool.query(
    `SELECT outcome
     FROM kovcheg.issue_auth_email_challenge($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      bootstrapEmail,
      challengeId,
      challengeVerifier,
      now,
      challengeExpiresAt,
      5,
      '60 seconds',
      `smoke-session-${challengeId}`,
    ],
  );
  if (issued.rows[0]?.outcome !== 'issued') throw new Error('Synthetic challenge was not issued');

  const consumed = await pool.query(
    `SELECT outcome
     FROM kovcheg.consume_auth_challenge_and_create_session($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      challengeId,
      challengeVerifier,
      now,
      sessionId,
      sessionTokenVerifier,
      now,
      sessionIdleLifetimeMs,
      absoluteExpiresAt,
    ],
  );
  if (consumed.rows[0]?.outcome !== 'authenticated') {
    throw new Error('Synthetic session was not created');
  }

  process.stdout.write(sessionToken);
} catch {
  process.stderr.write('Synthetic application session setup failed.\n');
  process.exitCode = 1;
} finally {
  await pool.end();
}
