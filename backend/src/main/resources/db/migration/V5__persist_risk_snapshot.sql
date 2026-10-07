ALTER TABLE analyses ADD COLUMN risk_snapshot jsonb;
COMMENT ON COLUMN analyses.risk_snapshot IS 'Política versionada y evaluaciones ordenadas con contribuciones/evidencias. NULL: análisis anterior o prioridad no evaluada; consultar no recalcula.';
