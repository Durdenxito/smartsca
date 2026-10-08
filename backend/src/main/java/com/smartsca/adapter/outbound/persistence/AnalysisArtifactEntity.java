package com.smartsca.adapter.outbound.persistence;

import com.smartsca.domain.analysis.AnalysisArtifact;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/** One immutable validated SBOM per analysis, committed with the terminal result. */
@Entity @Table(name = "analysis_artifacts")
public class AnalysisArtifactEntity {
    @Id @Column(name = "analysis_id") UUID analysisId;
    @Column(nullable = false, length = 16) String schemaVersion;
    @Column(nullable = false) Instant generatedAt;
    @Column(nullable = false, length = 64) String sha256;
    @Column(nullable = false, columnDefinition = "text") String content;
    protected AnalysisArtifactEntity() {}
    static AnalysisArtifactEntity from(UUID id, AnalysisArtifact value) {
        var entity = new AnalysisArtifactEntity();
        entity.analysisId = id; entity.schemaVersion = value.schemaVersion(); entity.generatedAt = value.generatedAt();
        entity.sha256 = value.sha256(); entity.content = value.content();
        return entity;
    }
    AnalysisArtifact toDomain() { return new AnalysisArtifact(schemaVersion, generatedAt, sha256, content); }
}
