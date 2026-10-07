package com.smartsca.domain.health;

import com.smartsca.domain.Evidence;
import com.smartsca.domain.EvidenceStatus;
import java.util.*;

/** Published repository checks, never a certification of the installed artifact. */
public record HealthAssessment(String componentPurl, Evidence<RepositoryAssociation> repository,
                               Evidence<ScorecardReport> scorecard, Map<String, Evidence<Indicator>> indicators,
                               List<Evidence<String>> associationEvidence) {
    public static final List<String> CHECKS = List.of("Maintained", "Security-Policy", "Code-Review", "Dependency-Update-Tool");
    public HealthAssessment {
        Objects.requireNonNull(componentPurl);
        Objects.requireNonNull(repository);
        Objects.requireNonNull(scorecard);
        indicators = Map.copyOf(indicators);
        associationEvidence = List.copyOf(associationEvidence);
        if (!indicators.keySet().equals(Set.copyOf(CHECKS))) throw new IllegalArgumentException("Se requieren los cuatro estados de salud.");
    }
    public record RepositoryAssociation(String id, String method) {}
    public record ScorecardReport(String repository, String repositoryCommit, String toolVersion, String toolCommit,
                                  boolean stale, String freshnessPolicy) {}
    public record Indicator(String name, int score, String reason, List<String> details, String documentationUrl) {
        public Indicator {
            if (!CHECKS.contains(name) || score < 0 || score > 10) throw new IllegalArgumentException("Indicador Scorecard inválido.");
            details = List.copyOf(details);
        }
    }
    public static HealthAssessment unavailable(String purl, String source, EvidenceStatus status, String reason) {
        Map<String, Evidence<Indicator>> checks = new LinkedHashMap<>();
        CHECKS.forEach(name -> checks.put(name, Evidence.absent(source, status, reason)));
        return new HealthAssessment(purl, Evidence.absent(source, status, reason), Evidence.absent(source, status, reason), checks, List.of());
    }
}
