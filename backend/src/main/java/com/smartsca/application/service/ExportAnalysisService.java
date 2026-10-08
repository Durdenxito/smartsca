package com.smartsca.application.service;

import com.smartsca.application.port.inbound.ExportAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.AnalysisArtifact;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

/** Downloads only stored bytes; preserves unavailable legacy and failed analyses. */
public final class ExportAnalysisService implements ExportAnalysisUseCase {
    private final AnalysisRepository analyses;
    public ExportAnalysisService(AnalysisRepository analyses) { this.analyses = analyses; }
    private Optional<AnalysisArtifact> saved(UUID id) {
        var analysis = analyses.get(id).orElseThrow(NoSuchElementException::new);
        if (analysis.finishedAt() == null || analysis.dependencyGraph() == null) return Optional.empty();
        try { return analyses.readSbom(id); }
        catch (IllegalArgumentException error) { return Optional.empty(); }
    }
    @Override public SbomStatus sbomStatus(UUID id) {
        return saved(id).map(value -> new SbomStatus(true, value.schemaVersion(), value.generatedAt(), value.sha256(), null))
            .orElseGet(() -> new SbomStatus(false, null, null, null, new ArtifactUnavailableException().getMessage()));
    }
    @Override public AnalysisArtifact downloadSbom(UUID id) { return saved(id).orElseThrow(ArtifactUnavailableException::new); }
}
