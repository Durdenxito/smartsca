package com.smartsca.adapter.outbound.persistence;

import com.smartsca.domain.analysis.*;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.Map;
import com.smartsca.domain.component.DependencyGraph;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** JPA representation; snapshot fields prevent later catalog edits from changing old requests. */
@Entity @Table(name = "analyses")
public class AnalysisEntity {
    @Id UUID id;
    @Column(nullable = false, length = 64) String projectId;
    @Column(nullable = false) String projectName;
    @Column(nullable = false) String sourceReference;
    @Column(nullable = false, length = 128) String analyzedReference;
    @Column(nullable = false, columnDefinition = "text[]") String[] modules;
    @Column(nullable = false, columnDefinition = "text[]") String[] profiles;
    @Column(nullable = false, columnDefinition = "text[]") String[] scopes;
    @Column(nullable = false, length = 64) String environmentId;
    @Column(length = 500) String declaredDeployment;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) AnalysisStatus status;
    @Column(nullable = false, length = 100) String currentStep;
    @Column(nullable = false) Instant createdAt;
    Instant startedAt;
    Instant finishedAt;
    @Column(nullable = false, length = 64) String engineVersion;
    @Column(nullable = false, columnDefinition = "text[]") String[] diagnostics;
    @Column(nullable = false, columnDefinition = "text[]") String[] projectModules;
    @Column(nullable = false, columnDefinition = "text[]") String[] projectProfiles;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb") Map<String, String> environmentVersions;
    @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition = "jsonb") DependencyGraph dependencyGraph;
    @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition = "jsonb") com.smartsca.domain.vulnerability.VulnerabilitySnapshot vulnerabilitySnapshot;
    @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition = "jsonb") Map<String, com.smartsca.domain.health.HealthAssessment> healthAssessments;
    @JdbcTypeCode(SqlTypes.JSON) @Column(columnDefinition = "jsonb") com.smartsca.domain.risk.RiskSnapshot riskSnapshot;

    protected AnalysisEntity() {}

    static AnalysisEntity from(Analysis analysis) {
        var entity = new AnalysisEntity();
        entity.id = analysis.id();
        entity.projectId = analysis.project().id();
        entity.projectName = analysis.project().name();
        entity.sourceReference = analysis.project().sourceReference();
        entity.analyzedReference = analysis.project().analyzedReference();
        entity.modules = analysis.configuration().modules().stream().sorted().toArray(String[]::new);
        entity.profiles = analysis.configuration().profiles().stream().sorted().toArray(String[]::new);
        entity.scopes = analysis.configuration().scopes().stream().sorted().toArray(String[]::new);
        entity.environmentId = analysis.configuration().environmentId();
        entity.declaredDeployment = analysis.configuration().declaredDeployment();
        entity.status = analysis.status();
        entity.currentStep = analysis.currentStep();
        entity.createdAt = analysis.createdAt();
        entity.startedAt = analysis.startedAt();
        entity.finishedAt = analysis.finishedAt();
        entity.engineVersion = analysis.engineVersion();
        entity.diagnostics = analysis.diagnostics().toArray(String[]::new);
        entity.projectModules = analysis.project().modules().stream().sorted().toArray(String[]::new);
        entity.projectProfiles = analysis.project().profiles().stream().sorted().toArray(String[]::new);
        entity.environmentVersions = analysis.environmentVersions();
        entity.dependencyGraph = analysis.dependencyGraph();
        entity.vulnerabilitySnapshot = analysis.vulnerabilitySnapshot();
        entity.healthAssessments = analysis.healthAssessments();
        entity.riskSnapshot = analysis.riskSnapshot();
        return entity;
    }

    Analysis toDomain() {
        var project = new Project(projectId, projectName, sourceReference, analyzedReference,
            Set.copyOf(Arrays.asList(projectModules)), Set.copyOf(Arrays.asList(projectProfiles)));
        var configuration = new AnalysisConfiguration(Set.copyOf(Arrays.asList(modules)), Set.copyOf(Arrays.asList(profiles)),
            Set.copyOf(Arrays.asList(scopes)), environmentId, declaredDeployment);
        return new Analysis(id, project, configuration, status, currentStep, createdAt, startedAt, finishedAt,
            engineVersion, List.copyOf(Arrays.asList(diagnostics)), environmentVersions, dependencyGraph, vulnerabilitySnapshot, healthAssessments, riskSnapshot);
    }
}
