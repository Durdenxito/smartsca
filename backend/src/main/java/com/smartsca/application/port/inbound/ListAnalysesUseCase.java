package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.analysis.AnalysisStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Reads saved metadata without loading graphs or contacting analysis providers. */
public interface ListAnalysesUseCase {
    int PAGE_SIZE = 20;
    int MAX_OFFSET = 10000;
    Page list(String projectId, AnalysisStatus status, int offset);

    record Entry(UUID id, String projectId, String projectName, String sourceReference, String analyzedReference,
                 AnalysisConfiguration configuration, AnalysisStatus status, Instant createdAt, Instant startedAt, Instant finishedAt) {}
    record Page(List<Entry> items, int offset, Integer nextOffset, boolean navigationLimited) {
        public Page { items = List.copyOf(items); }
    }
}
