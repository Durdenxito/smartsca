package com.smartsca.application.service;

import com.smartsca.application.port.inbound.ExportAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.AnalysisArtifact;
import com.smartsca.domain.Evidence;
import com.smartsca.domain.EvidenceStatus;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.risk.RiskAssessment;
import com.smartsca.domain.risk.RiskEvaluationStatus;
import com.smartsca.domain.vulnerability.Advisory;
import com.smartsca.domain.vulnerability.Finding;
import java.util.*;

/** Downloads only stored bytes; preserves unavailable legacy and failed analyses. */
public final class ExportAnalysisService implements ExportAnalysisUseCase {
    private final AnalysisRepository analyses;
    public ExportAnalysisService(AnalysisRepository analyses) { this.analyses = analyses; }
    /** One repository read: no providers, policy evaluation, freshness checks or artifact generation. */
    @Override public JsonExport downloadJson(UUID id) {
        var analysis = analyses.get(id).orElseThrow(NoSuchElementException::new);
        var graph = analysis.dependencyGraph();
        var vulnerabilities = analysis.vulnerabilitySnapshot();
        var health = analysis.healthAssessments();
        var risk = analysis.riskSnapshot();
        var selected = graph == null ? null : graph.componentsInScopes(analysis.configuration().scopes())
            .stream().map(component -> component.purl()).toList();
        var findings = vulnerabilities == null ? null : new HashSet<>(vulnerabilities.findings());
        var advisories = new HashMap<String, Evidence<Advisory>>();
        if (vulnerabilities != null) vulnerabilities.vulnerabilities().forEach(value -> advisories.putAll(value.advisories()));
        var assessments = new HashMap<Finding, RiskAssessment>();
        if (risk != null) risk.assessments().forEach(value -> assessments.put(value.finding(), value));
        Integer evaluated = findings == null ? null : (int) findings.stream().filter(finding -> {
            var value = assessments.get(finding);
            return value != null && value.status() == RiskEvaluationStatus.EVALUADO && value.score() != null && value.level() != null;
        }).count();
        Integer osvAvailable = selected == null || vulnerabilities == null ? null : (int) selected.stream()
            .filter(purl -> available(vulnerabilities.componentQueries().get(purl))).count();
        Integer healthAvailable = selected == null || health == null ? null : (int) selected.stream().filter(purl -> {
            var value = health.get(purl);
            return value != null && available(value.repository()) && available(value.scorecard()) && !value.scorecard().value().stale()
                && HealthAssessment.CHECKS.stream().allMatch(name -> available(value.indicators().get(name)));
        }).count();
        var coverage = Map.of(
            "osvComponentQueries", new Coverage(osvAvailable, selected == null ? null : selected.size()),
            "osvAdvisoryDetails", new Coverage(vulnerabilities == null ? null : (int) advisories.values().stream().filter(ExportAnalysisService::available).count(), vulnerabilities == null ? null : advisories.size()),
            "health", new Coverage(healthAvailable, selected == null ? null : selected.size()),
            "evaluatedFindings", new Coverage(evaluated, findings == null ? null : findings.size()));
        var missing = new ArrayList<String>();
        if (graph == null) missing.add("dependencyGraph");
        if (vulnerabilities == null) missing.add("vulnerabilitySnapshot");
        if (health == null) missing.add("healthAssessments");
        if (risk == null) missing.add("riskSnapshot");
        return new JsonExport("1.0", analysis, selected, coverage, List.copyOf(missing), List.of(
            "La cobertura cuenta observaciones guardadas: no certifica seguridad ni mide progreso. Cero hallazgos no demuestra ausencia de vulnerabilidades.",
            "El grafo conserva raíces y relaciones resueltas; selectedComponentPurls identifica el inventario de los scopes seleccionados, sin contar raíces sin ocurrencias de dependencia.",
            "Alcanzabilidad no analizada; despliegue declarado no demuestra exposición real.",
            "Los pesos de prioridad son decisiones iniciales del prototipo; evaluación académica pendiente.",
            "Fechas, fallos y antigüedad son los de la instantánea; no se consultan proveedores ni se reevalúa su vigencia al exportar.",
            "Las secciones guardadas pueden contener evidencias parciales o fallidas. Las secciones no obtenidas y las señales desconocidas conservan null y su estado; no se sustituyen por cero."));
    }
    private static boolean available(Evidence<?> evidence) { return evidence != null && evidence.status() == EvidenceStatus.DISPONIBLE; }
    private Optional<AnalysisArtifact> saved(UUID id) {
        var status = analyses.readStatus(id).orElseThrow(NoSuchElementException::new);
        if (status.finishedAt() == null || !status.graphAvailable()) return Optional.empty();
        try { return analyses.readSbom(id); }
        catch (IllegalArgumentException error) { return Optional.empty(); }
    }
    @Override public SbomStatus sbomStatus(UUID id) {
        return saved(id).map(value -> new SbomStatus(true, value.schemaVersion(), value.generatedAt(), value.sha256(), null))
            .orElseGet(() -> new SbomStatus(false, null, null, null, new ArtifactUnavailableException().getMessage()));
    }
    @Override public AnalysisArtifact downloadSbom(UUID id) { return saved(id).orElseThrow(ArtifactUnavailableException::new); }
}
