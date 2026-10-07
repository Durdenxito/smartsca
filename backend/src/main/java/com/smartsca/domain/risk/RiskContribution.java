package com.smartsca.domain.risk;
import com.smartsca.domain.Evidence;
import java.util.List;
/** Points remain absent when a required observation is unavailable; no substitute zero. */
public record RiskContribution(String dimension, double weight, Double points, String rule, List<Evidence<String>> usedEvidence) {
    public RiskContribution { usedEvidence = List.copyOf(usedEvidence); }
}
