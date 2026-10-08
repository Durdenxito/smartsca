package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.AnalysisArtifact;
import com.smartsca.domain.analysis.Analysis;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Read a saved artifact; neither downloading nor checking availability reruns providers. */
public interface ExportAnalysisUseCase {
    /** Null counts mean unknown; zero is reserved for an observed empty result. */
    record Coverage(Integer available, Integer total) {}
    record JsonExport(String schemaVersion, Analysis analysis, List<String> selectedComponentPurls,
                      Map<String, Coverage> coverage, List<String> sectionsNotObtained, List<String> limitations) {}
    JsonExport downloadJson(UUID analysisId);
    record SbomStatus(boolean available, String schemaVersion, Instant generatedAt, String sha256, String diagnostic) {}
    SbomStatus sbomStatus(UUID analysisId);
    AnalysisArtifact downloadSbom(UUID analysisId);
    final class ArtifactUnavailableException extends IllegalStateException {
        public ArtifactUnavailableException() { super("SBOM no disponible: no hay un artefacto validado e íntegro guardado para este análisis. Consulta su diagnóstico."); }
    }
}
