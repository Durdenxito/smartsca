-- Describe the schema after applying migrations, never infer tables from domain classes.
SELECT jsonb_build_object('tables', COALESCE(jsonb_agg(info ORDER BY schema_name, table_name), '[]'::jsonb))
FROM (
  SELECT n.nspname AS schema_name, t.relname AS table_name,
    jsonb_build_object(
      'schema', n.nspname, 'name', t.relname, 'description', obj_description(t.oid),
      'columns', (
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
          'name', a.attname, 'type', format_type(a.atttypid, a.atttypmod),
          'nullable', NOT a.attnotnull,
          'default', pg_get_expr(d.adbin, d.adrelid),
          'description', col_description(t.oid, a.attnum),
          'primary_key', EXISTS (SELECT 1 FROM pg_constraint p WHERE p.conrelid=t.oid AND p.contype='p' AND a.attnum=ANY(p.conkey)),
          'unique', EXISTS (SELECT 1 FROM pg_constraint u WHERE u.conrelid=t.oid AND u.contype='u' AND u.conkey=ARRAY[a.attnum])
        ) ORDER BY a.attnum), '[]'::jsonb)
        FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
        WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
      ),
      'foreign_keys', (
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
          'name', f.conname,
          'columns', (SELECT jsonb_agg(a.attname ORDER BY array_position(f.conkey,a.attnum)) FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum=ANY(f.conkey)),
          'target_schema', rn.nspname, 'target_table', rt.relname,
          'target_columns', (SELECT jsonb_agg(a.attname ORDER BY array_position(f.confkey,a.attnum)) FROM pg_attribute a WHERE a.attrelid=rt.oid AND a.attnum=ANY(f.confkey)),
          'nullable', EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum=ANY(f.conkey) AND NOT a.attnotnull),
          'unique', EXISTS (SELECT 1 FROM pg_constraint u WHERE u.conrelid=t.oid AND u.contype IN ('p','u') AND u.conkey @> f.conkey AND u.conkey <@ f.conkey)
        ) ORDER BY f.conname), '[]'::jsonb)
        FROM pg_constraint f JOIN pg_class rt ON rt.oid=f.confrelid JOIN pg_namespace rn ON rn.oid=rt.relnamespace
        WHERE f.conrelid=t.oid AND f.contype='f'
      )
    ) AS info
  FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
  WHERE t.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema')
    AND n.nspname NOT LIKE 'pg_%' AND t.relname <> 'flyway_schema_history'
) AS tables;
