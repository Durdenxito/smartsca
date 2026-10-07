package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.analysis.Project;
import java.util.List;

/** Resolve authorized catalog identities rather than arbitrary user paths. */
public interface ProjectSource {
    List<Project> listProjects();
    Project validate(String projectId, AnalysisConfiguration configuration);
}
