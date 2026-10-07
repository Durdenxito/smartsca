package com.smartsca.domain.analysis;

/** Persisted lifecycle states; registration only creates EN_COLA requests. */
public enum AnalysisStatus {
    EN_COLA, EN_EJECUCION, COMPLETO, PARCIAL, FALLIDO
}
