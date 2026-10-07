ALTER TABLE analyses
    ADD COLUMN project_modules text[] NOT NULL DEFAULT ARRAY['.']::text[],
    ADD COLUMN project_profiles text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN environment_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN dependency_graph jsonb;
CREATE INDEX analyses_pending ON analyses (created_at, id) WHERE status = 'EN_COLA';
COMMENT ON COLUMN analyses.dependency_graph IS 'Instantánea de dependencias resueltas, raíces y relaciones con contexto. NULL significa no resuelto, no un inventario vacío.';
COMMENT ON COLUMN analyses.environment_versions IS 'Versiones fijadas de imagen, JDK, Maven y plugin usadas en la resolución.';
