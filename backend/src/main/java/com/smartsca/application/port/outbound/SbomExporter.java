package com.smartsca.application.port.outbound;

import com.smartsca.domain.analysis.Analysis;
import com.smartsca.domain.analysis.AnalysisArtifact;
import com.smartsca.domain.component.DependencyGraph;

/** Generate and validate from the resolved snapshot, without resolving Maven again. */
public interface SbomExporter {
    AnalysisArtifact generateAndValidate(Analysis analysis, DependencyGraph graph);
}
