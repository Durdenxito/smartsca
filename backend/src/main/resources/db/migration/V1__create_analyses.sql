CREATE TABLE analyses (
    id uuid PRIMARY KEY,
    project_id varchar(64) NOT NULL,
    project_name varchar(255) NOT NULL,
    source_reference varchar(255) NOT NULL,
    analyzed_reference varchar(128) NOT NULL,
    modules text[] NOT NULL CHECK (cardinality(modules) BETWEEN 1 AND 32),
    profiles text[] NOT NULL CHECK (cardinality(profiles) <= 32),
    scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 4),
    environment_id varchar(64) NOT NULL,
    declared_deployment varchar(500),
    status varchar(20) NOT NULL CHECK (status IN ('EN_COLA','EN_EJECUCION','COMPLETO','PARCIAL','FALLIDO')),
    current_step varchar(100) NOT NULL,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    engine_version varchar(64) NOT NULL,
    diagnostics text[] NOT NULL
);

COMMENT ON TABLE analyses IS 'Solicitudes e instantáneas de análisis; el proyecto y la configuración se conservan tal como fueron registrados.';
COMMENT ON COLUMN analyses.project_id IS 'Identificador del catálogo, nunca una ruta proporcionada por el usuario.';
COMMENT ON COLUMN analyses.analyzed_reference IS 'Referencia registrada del POM; la resolución y la copia completa del proyecto se incorporan en el siguiente flujo.';
COMMENT ON COLUMN analyses.declared_deployment IS 'Contexto declarado por el usuario, no comprobado por el analizador.';
COMMENT ON COLUMN analyses.status IS 'Estado persistido: EN_COLA, EN_EJECUCION, COMPLETO, PARCIAL o FALLIDO.';
COMMENT ON COLUMN analyses.diagnostics IS 'Diagnósticos publicables; no deben contener secretos ni rutas internas.';
