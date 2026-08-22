SELECT kovcheg.append_audit_event(
  'database-audit-001',
  kovcheg.current_migration_version()::varchar,
  '00000000-0000-4000-8000-000000001001',
  'database.synthetic-check',
  'account',
  '00000000-0000-4000-8000-000000002001',
  'success',
  '{"fixture":"synthetic"}'::jsonb
);

SELECT kovcheg.append_operation_event(
  'database-operation-001',
  kovcheg.current_migration_version()::varchar,
  'database',
  'database.synthetic-check',
  'success',
  '{"fixture":"synthetic"}'::jsonb
);

DO $$
BEGIN
  BEGIN
    EXECUTE 'SELECT count(*) FROM kovcheg.audit_events';
    RAISE EXCEPTION 'audit writer read the protected audit table';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    EXECUTE 'DELETE FROM kovcheg.operation_events';
    RAISE EXCEPTION 'audit writer mutated the protected operation table';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;
