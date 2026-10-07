package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.Analysis;
import java.util.Optional;
import java.util.UUID;

/** Storage contract for the currently implemented registration and status flow. */
public interface AnalysisRepository {
    void save(Analysis analysis);
    Optional<Analysis> get(UUID analysisId);
    Optional<Analysis> claimNextPending();
    void updateStep(UUID analysisId, String step);
    /** Store a running job's result; retries leave an existing terminal result unchanged. */
    void finish(Analysis analysis);
    void failInterrupted();
}
