package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.AnalysisArtifact;
import java.time.Instant;
import java.util.UUID;

/** Read a saved artifact; neither downloading nor checking availability reruns providers. */
public interface ExportAnalysisUseCase {
    record SbomStatus(boolean available, String schemaVersion, Instant generatedAt, String sha256, String diagnostic) {}
    SbomStatus sbomStatus(UUID analysisId);
    AnalysisArtifact downloadSbom(UUID analysisId);
    final class ArtifactUnavailableException extends IllegalStateException {
        public ArtifactUnavailableException() { super("SBOM no disponible: no hay un artefacto validado e íntegro guardado para este análisis. Consulta su diagnóstico."); }
    }
}
