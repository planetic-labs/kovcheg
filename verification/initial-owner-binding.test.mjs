import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

// A single disposable PostgreSQL fixture, never a product/server executor.
const context = process.env.OWNER_BINDING_TEST_DOCKER_CONTEXT;
assert.ok(context, 'An explicitly selected isolated local Docker context is required');
const root = resolve(import.meta.dirname, '..');
const name = `owner-binding-test-${randomUUID()}`;
const image = readFileSync(`${root}/infra/postgres/Dockerfile`, 'utf8').match(/^FROM (\S+)/)[1];
const owner = '00000000-0000-4000-8000-000000007801';
const request = {
  expectedBootstrap: {
    bootstrapId: 'synthetic-owner-bootstrap',
    displayName: 'Synthetic Placeholder',
    email: 'placeholder@example.invalid',
    userId: owner,
  },
  expectedDomainStatus: 'incubator_participant',
  expectedFunctionalGrants: ['platform_administrator'],
  operationId: '00000000-0000-4000-8000-000000007802',
  replacementBootstrap: {
    bootstrapId: 'synthetic-owner-bootstrap',
    displayName: 'Synthetic Owner',
    email: 'owner@example.invalid',
    userId: owner,
  },
};
function docker(args, input) {
  return spawnSync('docker', ['--context', context, ...args], {
    input,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
}
function sql(statement, database = 'fixture', user = 'kovcheg_migrator') {
  const result = docker(
    ['exec', '-i', name, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database],
    statement,
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
function reset() {
  sql(
    'DROP DATABASE IF EXISTS fixture; CREATE DATABASE fixture TEMPLATE kovcheg;',
    'postgres',
    'postgres',
  );
}
const bindArgs = [
  'exec',
  '-i',
  '-e',
  'PGUSER=kovcheg_migrator',
  '-e',
  'PGDATABASE=fixture',
  name,
  'sh',
  '/source/infra/postgres/bind-initial-owner.sh',
];
function bind(input = request) {
  return docker(bindArgs, typeof input === 'string' ? input : JSON.stringify(input));
}
function snapshot() {
  return sql(`SELECT jsonb_build_object(
    'accounts', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM kovcheg.accounts t),
    'profiles', (SELECT jsonb_agg(to_jsonb(t) ORDER BY account_id) FROM kovcheg.account_auth_profiles t),
    'bootstrap', (SELECT jsonb_agg(to_jsonb(t)) FROM kovcheg.auth_administrator_bootstraps t),
    'owner', (SELECT jsonb_agg(to_jsonb(t)) FROM kovcheg.server_owner t),
    'domain', (SELECT jsonb_agg(to_jsonb(t) ORDER BY account_id) FROM kovcheg.account_domain_statuses t),
    'grants', (SELECT jsonb_agg(to_jsonb(t) ORDER BY account_id, role) FROM kovcheg.account_platform_roles t),
    'operatorGrants', (SELECT jsonb_agg(to_jsonb(t) ORDER BY operator_account_id, persona_account_id) FROM kovcheg.system_persona_operator_grants t),
    'memberships', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM kovcheg.chat_memberships t),
    'audit', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM kovcheg.audit_events t)
  );`);
}
function rejected(input = request) {
  const before = snapshot();
  const result = bind(input);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'INITIAL_OWNER_BINDING_UNCONFIRMED\n');
  assert.equal(
    snapshot(),
    before,
    'A rejected transaction must have no profile/identity/audit changes',
  );
}
function bootstrap(email) {
  return docker(
    [
      'exec',
      '-i',
      name,
      'psql',
      '-X',
      '-qAt',
      '-v',
      'ON_ERROR_STOP=1',
      '-U',
      'kovcheg_auth_app',
      '-d',
      'fixture',
    ],
    `SELECT created FROM kovcheg.bootstrap_role_capable_administrator('synthetic-owner-bootstrap', '${owner}', '${email}', 'Synthetic Owner');`,
  );
}

test('initial owner binding on the existing PostgreSQL schema', async (t) => {
  assert.equal(
    docker(['container', 'inspect', name]).status,
    1,
    'Unique container name must be absent',
  );
  let created = false;
  try {
    const start = docker([
      'run',
      '--detach',
      '--name',
      name,
      '--network',
      'none',
      '--cpus',
      '1',
      '--memory',
      '512m',
      '--pids-limit',
      '128',
      '--label',
      `io.kovcheg.test.run-id=${name}`,
      '--label',
      'io.kovcheg.test.purpose=initial-owner-binding',
      '--tmpfs',
      '/var/lib/postgresql/data:rw,size=256m',
      '--tmpfs',
      '/tmp:rw,size=16m',
      '--mount',
      `type=bind,src=${root},dst=/source,readonly`,
      '-e',
      'POSTGRES_HOST_AUTH_METHOD=trust',
      image,
    ]);
    assert.equal(start.status, 0, start.stderr);
    created = true;
    const ready = docker([
      'exec',
      name,
      'sh',
      '-c',
      'i=0; until pg_isready -U postgres; do i=$((i+1)); [ "$i" -lt 60 ] || exit 1; sleep 1; done',
    ]);
    assert.equal(ready.status, 0, ready.stderr);
    sql(
      `CREATE ROLE kovcheg_migration NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      CREATE ROLE kovcheg_runtime NOLOGIN;
      CREATE ROLE kovcheg_auth_runtime NOLOGIN;
      CREATE ROLE kovcheg_audit NOLOGIN;
      CREATE ROLE kovcheg_migrator LOGIN INHERIT IN ROLE kovcheg_migration;
      CREATE ROLE kovcheg_auth_app LOGIN INHERIT IN ROLE kovcheg_auth_runtime;
      CREATE ROLE kovcheg_app LOGIN INHERIT IN ROLE kovcheg_runtime;
      CREATE ROLE kovcheg_audit_writer LOGIN INHERIT IN ROLE kovcheg_audit;
      CREATE DATABASE kovcheg;
      GRANT CONNECT, CREATE, TEMPORARY ON DATABASE kovcheg TO kovcheg_migration;`,
      'postgres',
      'postgres',
    );
    const migrations = docker([
      'exec',
      '-e',
      'PGUSER=kovcheg_migrator',
      '-e',
      'PGDATABASE=kovcheg',
      '-e',
      'KOVCHEG_APP_ENV=development',
      '-e',
      'KOVCHEG_MIGRATION_ROOT=/source/infra/postgres/migrations',
      name,
      'sh',
      '-c',
      "printf 'synthetic-test-only' > /tmp/migration-password; PGPASSWORD_FILE=/tmp/migration-password sh /source/infra/postgres/migrate.sh",
    ]);
    assert.equal(migrations.status, 0, migrations.stderr);
    sql(
      `SELECT created FROM kovcheg.bootstrap_role_capable_administrator('synthetic-owner-bootstrap', '${owner}', 'placeholder@example.invalid', 'Synthetic Placeholder');`,
      'kovcheg',
      'kovcheg_auth_app',
    );

    await t.test(
      'success, exact identity/authorization preservation, one sanitized audit, and safe repeat',
      () => {
        reset();
        const before = JSON.parse(snapshot());
        const result = bind();
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout, 'BOUND\n');
        const after = JSON.parse(snapshot());
        for (const field of [
          'accounts',
          'bootstrap',
          'owner',
          'domain',
          'grants',
          'operatorGrants',
          'memberships',
        ]) {
          assert.deepEqual(after[field], before[field], field);
        }
        assert.equal(after.profiles[0].email, request.replacementBootstrap.email);
        assert.equal(after.profiles[0].display_name, request.replacementBootstrap.displayName);
        assert.equal(after.profiles[0].created_at, before.profiles[0].created_at);
        assert.equal(after.profiles[0].auth_role, before.profiles[0].auth_role);
        assert.equal(after.audit.length, (before.audit?.length ?? 0) + 1);
        const event = after.audit.find(
          (a) => a.correlation_id === `initial-owner-binding:${request.operationId}`,
        );
        assert.equal(event.actor_account_id, null);
        assert.equal(event.action, 'auth.account.updated');
        assert.equal(event.target_type, 'auth_account');
        assert.deepEqual(event.details, {});
        assert.equal(
          sql(
            'SELECT (SELECT count(*) FROM kovcheg.auth_sessions) + (SELECT count(*) FROM kovcheg.auth_email_challenges);',
          ),
          '0',
        );
        assert.equal(bind().stdout, 'ALREADY_BOUND\n');
        assert.deepEqual(JSON.parse(snapshot()), after);
        rejected({ ...request, operationId: '00000000-0000-4000-8000-000000007803' });
      },
    );

    await t.test(
      'existing bootstrap accepts matching input, rejects old input; a file gap stays closed',
      () => {
        reset();
        assert.equal(
          bootstrap(request.replacementBootstrap.email).status,
          3,
          'File changed before DB must not start',
        );
        assert.equal(bind().status, 0);
        assert.equal(
          bootstrap(request.expectedBootstrap.email).status,
          3,
          'DB changed before file must not start',
        );
        const before = snapshot();
        const result = bootstrap(request.replacementBootstrap.email);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), 'f');
        assert.equal(snapshot(), before);
      },
    );

    await t.test(
      'invalid input, wrong exact baseline and inconsistent identity are rejected',
      () => {
        for (const input of [
          'not-json',
          '{}',
          'x'.repeat(17000),
          { ...request, extra: true },
          { ...request, expectedDomainStatus: 'disciple' },
          { ...request, expectedFunctionalGrants: [] },
          {
            ...request,
            expectedBootstrap: { ...request.expectedBootstrap, email: 'wrong@example.invalid' },
          },
          {
            ...request,
            expectedBootstrap: { ...request.expectedBootstrap, displayName: 'Wrong Placeholder' },
          },
          {
            ...request,
            replacementBootstrap: {
              ...request.replacementBootstrap,
              userId: '00000000-0000-4000-8000-000000007899',
            },
          },
          {
            ...request,
            expectedBootstrap: {
              ...request.expectedBootstrap,
              bootstrapId: 'different-bootstrap-binding',
            },
          },
          {
            ...request,
            replacementBootstrap: { ...request.replacementBootstrap, email: 'bad\n\\.\nSELECT 1;' },
          },
        ]) {
          reset();
          rejected(input);
        }
      },
    );

    await t.test(
      'deactivated, changed grants, another profile and duplicate email fail closed',
      () => {
        for (const setup of [
          `UPDATE kovcheg.accounts SET status='deactivated', deactivated_at=clock_timestamp() WHERE id='${owner}';`,
          `DELETE FROM kovcheg.account_platform_roles WHERE account_id='${owner}';`,
          `INSERT INTO kovcheg.accounts(id,kind,status,activated_at) VALUES ('00000000-0000-4000-8000-000000007899','person','active',clock_timestamp()); INSERT INTO kovcheg.account_auth_profiles(account_id,email,display_name,auth_role) VALUES ('00000000-0000-4000-8000-000000007899','owner@example.invalid','Synthetic Duplicate','student');`,
        ]) {
          reset();
          sql(`SET ROLE kovcheg_migration; ${setup}`);
          rejected();
        }
      },
    );

    await t.test('existing and historical usage, unknown OIDC state and prior audit reject', () => {
      for (const setup of [
        `INSERT INTO kovcheg.auth_sessions(id,account_id,token_verifier,issued_at,last_seen_at,idle_lifetime_ms,idle_expires_at,absolute_expires_at) VALUES ('00000000-0000-4000-8000-000000007804','${owner}',repeat('A',43),now()-interval '2 hours',now()-interval '2 hours',60000,now()-interval '119 minutes',now()-interval '1 hour');`,
        `INSERT INTO kovcheg.auth_email_challenges(id,account_id,code_verifier,issued_at,expires_at,max_attempts) VALUES ('00000000-0000-4000-8000-000000007805','${owner}',repeat('B',43),now()-interval '2 hours',now()-interval '1 hour',3);`,
        `INSERT INTO kovcheg.auth_personal_gate_families(id,account_id,code_verifier,issued_at) VALUES ('00000000-0000-4000-8000-000000007806','${owner}',repeat('C',43),now());`,
        `INSERT INTO kovcheg.auth_passkey_credentials(id,account_id,credential_id,public_key,sign_count,aaguid,attestation_format,registered_backup_eligible,registered_backup_state,last_backup_eligible,last_backup_state,registration_correlation_id,created_at) VALUES ('00000000-0000-4000-8000-000000007807','${owner}',decode('01','hex'),decode('02','hex'),0,'00000000-0000-4000-8000-000000007808','none',false,false,false,false,'synthetic-passkey',now());`,
        `INSERT INTO kovcheg.oidc_provider_artifacts(model,artifact_id,payload,expires_at) VALUES ('Session','synthetic-unknown','{}',now()+interval '1 hour');`,
        `SELECT kovcheg.append_audit_event('synthetic-prior-use','0017','${owner}','auth.session.created','auth_account','${owner}','success','{}');`,
        `SELECT kovcheg.append_audit_event('synthetic-unknown-event','0017',NULL,'account.unknown','account','${owner}','success','{}');`,
        `INSERT INTO kovcheg.audit_events(correlation_id,migration_version,actor_account_id,action,target_type,target_id,outcome,details,occurred_at) SELECT correlation_id,migration_version,actor_account_id,action,target_type,target_id,outcome,details,occurred_at FROM kovcheg.audit_events WHERE action='account.provisioned';`,
      ]) {
        reset();
        sql(`SET ROLE kovcheg_migration; ${setup}`);
        rejected();
      }
    });

    await t.test(
      'SQL/audit failure and unexpected trigger changes roll back the complete transaction',
      () => {
        for (const setup of [
          `CREATE FUNCTION kovcheg.test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private body'; END; $$; CREATE TRIGGER test_failure BEFORE INSERT ON kovcheg.audit_events FOR EACH ROW EXECUTE FUNCTION kovcheg.test_failure();`,
          `CREATE FUNCTION kovcheg.test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private body'; END; $$; CREATE TRIGGER test_failure BEFORE UPDATE ON kovcheg.account_auth_profiles FOR EACH ROW EXECUTE FUNCTION kovcheg.test_failure();`,
          `CREATE FUNCTION kovcheg.test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN DELETE FROM kovcheg.account_platform_roles WHERE account_id=NEW.account_id; RETURN NEW; END; $$; CREATE TRIGGER test_failure AFTER UPDATE ON kovcheg.account_auth_profiles FOR EACH ROW EXECUTE FUNCTION kovcheg.test_failure();`,
          `CREATE FUNCTION kovcheg.test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN DELETE FROM kovcheg.account_platform_roles WHERE account_id=NEW.target_id; RETURN NEW; END; $$; CREATE TRIGGER test_failure AFTER INSERT ON kovcheg.audit_events FOR EACH ROW EXECUTE FUNCTION kovcheg.test_failure();`,
        ]) {
          reset();
          sql(`SET ROLE kovcheg_migration; ${setup}`);
          rejected();
        }
      },
    );

    await t.test('concurrent same-operation requests write once', async () => {
      reset();
      const invoke = () =>
        new Promise((resolveResult, rejectResult) => {
          const child = spawn('docker', ['--context', context, ...bindArgs]);
          let stdout = '';
          let stderr = '';
          child.stdout.on('data', (chunk) => {
            stdout += chunk;
          });
          child.stderr.on('data', (chunk) => {
            stderr += chunk;
          });
          child.on('error', rejectResult);
          child.on('close', (status) => resolveResult({ status, stdout, stderr }));
          child.stdin.end(JSON.stringify(request));
        });
      const results = await Promise.all([invoke(), invoke()]);
      assert.deepEqual(
        results.map((r) => r.status),
        [0, 0],
      );
      assert.deepEqual(results.map((r) => r.stdout.trim()).sort(), ['ALREADY_BOUND', 'BOUND']);
      assert.equal(
        sql("SELECT count(*) FROM kovcheg.audit_events WHERE action='auth.account.updated';"),
        '1',
      );
    });

    await t.test('auth runtime has no table DML and logs contain no binding payload', () => {
      reset();
      assert.equal(
        sql(
          "SELECT has_table_privilege('kovcheg_auth_runtime','kovcheg.account_auth_profiles','UPDATE');",
        ),
        'f',
      );
      const previousLogs = docker(['logs', name]);
      assert.equal(bind().status, 0);
      rejected({
        ...request,
        replacementBootstrap: {
          ...request.replacementBootstrap,
          displayName: 'Synthetic Changed Repeat',
        },
      });
      const logs = docker(['logs', name]);
      const delta =
        logs.stdout.slice(previousLogs.stdout.length) +
        logs.stderr.slice(previousLogs.stderr.length);
      for (const value of [
        request.replacementBootstrap.email,
        request.replacementBootstrap.displayName,
        Buffer.from(JSON.stringify(request)).toString('base64'),
      ]) {
        assert.ok(!delta.includes(value));
      }
    });

    await t.test(
      'lost acknowledgement after real commit is UNCONFIRMED, never rollback evidence',
      () => {
        reset();
        const result = docker(
          [
            'exec',
            '-i',
            '-e',
            'PGUSER=kovcheg_migrator',
            '-e',
            'PGDATABASE=fixture',
            name,
            'sh',
            '-c',
            'psql() { command psql "$@" >/dev/null; printf "%s" "$?" > /tmp/lost-ack-status; return 1; }; . "$0"',
            '/source/infra/postgres/bind-initial-owner.sh',
          ],
          JSON.stringify(request),
        );
        assert.equal(result.status, 1);
        assert.equal(result.stdout, '');
        assert.equal(result.stderr, 'INITIAL_OWNER_BINDING_UNCONFIRMED\n');
        assert.equal(
          docker(['exec', name, 'cat', '/tmp/lost-ack-status']).stdout,
          '0',
          'The injection must occur after successful psql completion',
        );
        assert.equal(
          sql("SELECT count(*) FROM kovcheg.audit_events WHERE action='auth.account.updated';"),
          '1',
        );
        assert.equal(
          sql(
            `SELECT email = 'owner@example.invalid' FROM kovcheg.account_auth_profiles WHERE account_id='${owner}';`,
          ),
          't',
        );
      },
    );
  } finally {
    if (created) {
      const mounts = docker(['inspect', '--format', '{{json .Mounts}}', name]);
      assert.equal(mounts.status, 0);
      assert.ok(JSON.parse(mounts.stdout).every((mount) => mount.Type !== 'volume'));
      assert.equal(docker(['rm', '--force', name]).status, 0, 'Owned fixture cleanup must succeed');
      assert.equal(
        docker(['container', 'inspect', name]).status,
        1,
        'Owned fixture must be absent',
      );
      console.log('Owned PostgreSQL fixture removed; no volumes created.');
    }
  }
});
