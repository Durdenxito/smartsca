package com.smartsca.domain.risk;
import java.time.Instant;
import java.util.List;
/** Policy definition and ordered results are stored together; reads never recalculate them. */
public record RiskSnapshot(RiskPolicy.Definition policy, Instant evaluatedAt, List<RiskAssessment> assessments) {
    public RiskSnapshot { assessments = List.copyOf(assessments); }
}
