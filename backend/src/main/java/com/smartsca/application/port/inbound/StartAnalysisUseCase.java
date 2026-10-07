package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.analysis.Project;
import java.util.List;
import java.util.UUID;

/** Catalog and registration operations available to an inbound adapter. */
public interface StartAnalysisUseCase {
    List<Project> listProjects();
    UUID start(String projectId, AnalysisConfiguration configuration);
}
