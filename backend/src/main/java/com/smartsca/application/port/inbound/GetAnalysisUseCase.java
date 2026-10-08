package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.Analysis;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.analysis.AnalysisStatus;
import com.smartsca.domain.component.DependencyGraph;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.vulnerability.VulnerabilitySnapshot;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Retrieve the persisted snapshot without invoking external tools. */
public interface GetAnalysisUseCase {
    record ComponentItem(com.smartsca.domain.component.Component component,
                         java.util.List<com.smartsca.domain.component.DependencyGraph.Occurrence> contexts) {}
    record Status(UUID id, String projectName, AnalysisConfiguration configuration, AnalysisStatus status,
                  String currentStep, Instant createdAt, Instant startedAt, Instant finishedAt,
                  List<String> diagnostics, Map<String, String> environmentVersions,
                  boolean graphAvailable, boolean vulnerabilitiesAvailable) {
        public Status { diagnostics = List.copyOf(diagnostics); environmentVersions = Map.copyOf(environmentVersions); }
    }
    record Resolution(String projectName, AnalysisStatus status, Set<String> scopes, DependencyGraph dependencyGraph) {
        public Resolution { scopes = Set.copyOf(scopes); }
    }
    record Sources(VulnerabilitySnapshot vulnerabilitySnapshot, Map<String, HealthAssessment> healthAssessments) {
        public Sources { healthAssessments = healthAssessments == null ? null : Map.copyOf(healthAssessments); }
    }
    record Inventory(String projectName, AnalysisStatus status, Set<String> scopes, Map<String, String> rootsByModule,
                     List<ComponentItem> items, Map<String, HealthAssessment> healthAssessments, boolean vulnerabilitiesAvailable) {
        public Inventory { scopes = Set.copyOf(scopes); rootsByModule = Map.copyOf(rootsByModule); items = List.copyOf(items);
            healthAssessments = healthAssessments == null ? null : Map.copyOf(healthAssessments); }
    }
    Analysis get(UUID analysisId);
    Status status(UUID analysisId);
    Resolution resolution(UUID analysisId);
    Sources sources(UUID analysisId);
    Inventory inventory(UUID analysisId);
    java.util.List<ComponentItem> components(UUID analysisId, String search, String module, String scope, Boolean direct);
    com.smartsca.domain.component.DependencyGraph.Neighborhood graph(UUID analysisId, String module, String purl, int offset);
    com.smartsca.domain.component.DependencyGraph.Routes routes(UUID analysisId, String purl, String module, int offset);
}
