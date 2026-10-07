package com.smartsca.domain.analysis;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.Map;
import com.smartsca.domain.component.DependencyGraph;

/** Immutable snapshot of a registered request; execution fields remain absent while queued. */
public record Analysis(UUID id, Project project, AnalysisConfiguration configuration, AnalysisStatus status,
                       String currentStep, Instant createdAt, Instant startedAt, Instant finishedAt,
                       String engineVersion, List<String> diagnostics, Map<String, String> environmentVersions,
                       DependencyGraph dependencyGraph, com.smartsca.domain.vulnerability.VulnerabilitySnapshot vulnerabilitySnapshot,
                       Map<String, com.smartsca.domain.health.HealthAssessment> healthAssessments,
                       com.smartsca.domain.risk.RiskSnapshot riskSnapshot) {
    public Analysis {
        Objects.requireNonNull(id);
        Objects.requireNonNull(project);
        Objects.requireNonNull(configuration);
        Objects.requireNonNull(status);
        Objects.requireNonNull(currentStep);
        Objects.requireNonNull(createdAt);
        Objects.requireNonNull(engineVersion);
        diagnostics = List.copyOf(diagnostics);
        environmentVersions = Map.copyOf(environmentVersions);
        healthAssessments = healthAssessments == null ? null : Map.copyOf(healthAssessments);
    }
    public Analysis finished(AnalysisStatus state, String step, List<String> messages,
                             Map<String, String> versions, DependencyGraph graph,
                             com.smartsca.domain.vulnerability.VulnerabilitySnapshot vulnerabilities,
                             Map<String, com.smartsca.domain.health.HealthAssessment> health,
                             com.smartsca.domain.risk.RiskSnapshot risk) {
        return new Analysis(id, project, configuration, state, step, createdAt, startedAt, Instant.now(),
            engineVersion, messages, versions, graph, vulnerabilities, health, risk);
    }
}
