package com.smartsca.application.port.outbound;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.DependencyGraph;
public interface DependencyResolver {
    DependencyGraph resolve(Project project, AnalysisConfiguration configuration);
}
