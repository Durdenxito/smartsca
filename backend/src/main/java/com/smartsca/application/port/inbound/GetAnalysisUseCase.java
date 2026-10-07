package com.smartsca.application.port.inbound;

import com.smartsca.domain.analysis.Analysis;
import java.util.UUID;

/** Retrieve the persisted snapshot without invoking external tools. */
public interface GetAnalysisUseCase {
    record ComponentItem(com.smartsca.domain.component.Component component,
                         java.util.List<com.smartsca.domain.component.DependencyGraph.Occurrence> contexts) {}
    Analysis get(UUID analysisId);
    java.util.List<ComponentItem> components(UUID analysisId, String search, String module, String scope, Boolean direct);
    com.smartsca.domain.component.DependencyGraph.Neighborhood graph(UUID analysisId, String module, String purl, int offset);
    com.smartsca.domain.component.DependencyGraph.Routes routes(UUID analysisId, String purl, String module, int offset);
}
