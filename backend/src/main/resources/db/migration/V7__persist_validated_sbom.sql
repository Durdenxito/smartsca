CREATE TABLE analysis_artifacts (
    analysis_id uuid PRIMARY KEY REFERENCES analyses(id),
    schema_version varchar(16) NOT NULL CHECK (schema_version = '1.6'),
    generated_at timestamptz NOT NULL,
    sha256 varchar(64) NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    content text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 16777216)
);
