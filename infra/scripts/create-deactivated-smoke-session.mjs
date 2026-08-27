/* global process */

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { Pool } from 'pg';

const actorToken = process.env.KOVCHEG_SMOKE_ADMIN_SESSION_TOKEN;
if (!/^[A-Za-z0-9_-]{43}$/u.test(actorToken ?? '')) {
  throw new Error('A synthetic administrator session token is required');
}

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
  const actorVerifier = verifier(sessionPepper, 'server-session', actorToken);
  const accountId = randomUUID();
  const challengeId = randomUUID();
  const challengeVerifier = randomBytes(32).toString('base64url');
  const sessionId = randomUUID();
  const sessionToken = randomBytes(32).toString('base64url');
  const sessionVerifier = verifier(sessionPepper, 'server-session', sessionToken);
  const now = new Date();
  const challengeExpiresAt = new Date(now.getTime() + 10 * 60 * 1_000);
  const absoluteExpiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1_000);

  await pool.query(
    `SELECT account_id
     FROM kovcheg.admin_create_role_capable_account($1, $2, $3, $4, $5, $6)`,
    [
      actorVerifier,
      accountId,
      `deactivated-${accountId}@auth.invalid`,
      'Synthetic Deactivated Account',
      now,
      `smoke-create-${accountId}`,
    ],
  );
  const issued = await pool.query(
    `SELECT outcome
     FROM kovcheg.issue_auth_challenge_for_active_account($1, $2, $3, $4, $5, $6, $7)`,
    [
      `deactivated-${accountId}@auth.invalid`,
      challengeId,
      challengeVerifier,
      now,
      challengeExpiresAt,
      5,
      '0 seconds',
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
      sessionVerifier,
      now,
      7 * 24 * 60 * 60 * 1_000,
      absoluteExpiresAt,
    ],
  );
  if (consumed.rows[0]?.outcome !== 'authenticated') {
    throw new Error('Synthetic target session was not created');
  }
  await pool.query(
    `SELECT account_id
     FROM kovcheg.admin_set_role_capable_account_status($1, $2, 'deactivated', $3, $4)`,
    [actorVerifier, accountId, new Date(now.getTime() + 1), `smoke-deactivate-${accountId}`],
  );
  process.stdout.write(sessionToken);
} catch {
  process.stderr.write('Synthetic deactivated session setup failed.\n');
  process.exitCode = 1;
} finally {
  await pool.end();
}
