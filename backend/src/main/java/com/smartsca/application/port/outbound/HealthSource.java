package com.smartsca.application.port.outbound;

import com.smartsca.domain.component.Component;
import com.smartsca.domain.health.HealthAssessment;
import java.util.*;

/** Resolve a supported package's evidenced repository and retrieve published health checks. */
public interface HealthSource {
    Map<String, HealthAssessment> assess(List<Component> components);
}
