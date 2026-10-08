package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.Analysis;
import com.smartsca.domain.analysis.AnalysisStatus;
import com.smartsca.domain.analysis.AnalysisArtifact;
import com.smartsca.application.port.inbound.ListAnalysesUseCase;
import com.smartsca.application.port.inbound.GetAnalysisUseCase;
import com.smartsca.domain.health.HealthAssessment;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Storage contract for immutable results, worker lifecycle and history metadata. */
public interface AnalysisRepository {
    void save(Analysis analysis);
    Optional<Analysis> get(UUID analysisId);
    // In-memory adapters may reuse get; persistent adapters select only the requested columns.
    default Optional<GetAnalysisUseCase.Status> readStatus(UUID id) {
        return get(id).map(value -> new GetAnalysisUseCase.Status(value.id(), value.project().name(), value.configuration(), value.status(),
            value.currentStep(), value.createdAt(), value.startedAt(), value.finishedAt(), value.diagnostics(), value.environmentVersions(),
            value.dependencyGraph() != null, value.vulnerabilitySnapshot() != null));
    }
    default Optional<GetAnalysisUseCase.Resolution> readResolution(UUID id) {
        return get(id).map(value -> new GetAnalysisUseCase.Resolution(value.project().name(), value.status(), value.configuration().scopes(), value.dependencyGraph()));
    }
    default Optional<GetAnalysisUseCase.Sources> readSources(UUID id) {
        return get(id).map(value -> new GetAnalysisUseCase.Sources(value.vulnerabilitySnapshot(), value.healthAssessments()));
    }
    record InventorySnapshot(GetAnalysisUseCase.Resolution resolution, Map<String, HealthAssessment> healthAssessments, boolean vulnerabilitiesAvailable) {}
    default Optional<InventorySnapshot> readInventory(UUID id) {
        return get(id).map(value -> new InventorySnapshot(new GetAnalysisUseCase.Resolution(value.project().name(), value.status(),
            value.configuration().scopes(), value.dependencyGraph()), value.healthAssessments(), value.vulnerabilitySnapshot() != null));
    }
    ListAnalysesUseCase.Page list(String projectId, AnalysisStatus status, int offset);
    Optional<Analysis> claimNextPending();
    void updateStep(UUID analysisId, String step);
    /** Store a running job's result; retries leave an existing terminal result unchanged. */
    default void finish(Analysis analysis) { finish(analysis, null); }
    /** Atomically store the terminal snapshot and its optional validated SBOM. */
    void finish(Analysis analysis, AnalysisArtifact sbom);
    Optional<AnalysisArtifact> readSbom(UUID analysisId);
    void failInterrupted();
}
