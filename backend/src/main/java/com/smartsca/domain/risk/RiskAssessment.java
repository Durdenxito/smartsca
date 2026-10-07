package com.smartsca.domain.risk;
import com.smartsca.domain.vulnerability.Finding;
import java.util.List;
/** One finding's immutable explanation, including known KEV even when its numerical evaluation is pending. */
public record RiskAssessment(Finding finding, String policyVersion, RiskEvaluationStatus status, Double score,
        PriorityLevel level, boolean knownExploited, List<RiskContribution> contributions, List<String> explanation, List<String> limits) {
    public RiskAssessment {
        contributions = List.copyOf(contributions); explanation = List.copyOf(explanation); limits = List.copyOf(limits);
        if ((status == RiskEvaluationStatus.EVALUADO) != (score != null && level != null)
                || (status == RiskEvaluationStatus.PENDIENTE_REVISION && (score != null || level != null))
                || (score != null && (!Double.isFinite(score) || score < 0 || score > 100)))
            throw new IllegalArgumentException("Evaluación de prioridad inconsistente.");
    }
}
