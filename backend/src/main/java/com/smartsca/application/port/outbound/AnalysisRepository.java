package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.Analysis;
import com.smartsca.domain.analysis.AnalysisStatus;
import com.smartsca.domain.analysis.AnalysisArtifact;
import com.smartsca.application.port.inbound.ListAnalysesUseCase;
import java.util.Optional;
import java.util.UUID;

/** Storage contract for immutable results, worker lifecycle and history metadata. */
public interface AnalysisRepository {
    void save(Analysis analysis);
    Optional<Analysis> get(UUID analysisId);
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
