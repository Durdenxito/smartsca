ALTER TABLE analyses ADD COLUMN health_assessments jsonb;
COMMENT ON COLUMN analyses.health_assessments IS 'RF-08 repository association evidence and published Scorecard checks by component purl; null for earlier analyses';
