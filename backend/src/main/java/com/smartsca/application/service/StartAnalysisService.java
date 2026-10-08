package com.smartsca.application.service;

import com.smartsca.application.port.inbound.StartAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.application.port.outbound.ProjectSource;
import com.smartsca.domain.analysis.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Validates and persists a new queued request without executing Maven. */
public final class StartAnalysisService implements StartAnalysisUseCase {
    private final ProjectSource projects;
    private final AnalysisRepository analyses;
    private final String engineVersion;

    public StartAnalysisService(ProjectSource projects, AnalysisRepository analyses, String engineVersion) {
        this.projects = projects;
        this.analyses = analyses;
        this.engineVersion = engineVersion;
    }

    @Override public List<Project> listProjects() { return projects.listProjects(); }
    @Override public Project importZip(java.io.InputStream input, String filename) { return projects.importZip(input, filename); }
    @Override public Project importGit(String url) { return projects.importGit(url); }

    @Override public UUID start(String projectId, AnalysisConfiguration configuration) {
        var selected = configuration == null ? AnalysisConfiguration.defaults() : configuration;
        var project = projects.validate(projectId, selected);
        var analysis = new Analysis(UUID.randomUUID(), project, selected, AnalysisStatus.EN_COLA,
            "REGISTRADO", Instant.now(), null, null, engineVersion, List.of(), java.util.Map.of(), null, null, null, null);
        analyses.save(analysis);
        return analysis.id();
    }
}
