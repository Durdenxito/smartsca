package com.smartsca.domain.risk;

import com.smartsca.domain.*;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.component.*;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.vulnerability.*;
import java.time.Instant;
import java.util.*;

/** Prototype policy: decisions are explicit, persisted and reproducible, not an academically validated risk model. */
public final class RiskPolicy {
    public static final String VERSION = "smartsca-priority-v1";
    public record Definition(String version, Map<String, Double> weights, Map<String, Double> thresholds,
            String formula, List<String> missingEvidenceRules, List<String> tieBreakRules, String cvssSelection, String calculator) {
        public Definition {
            weights = Map.copyOf(weights); thresholds = Map.copyOf(thresholds);
            missingEvidenceRules = List.copyOf(missingEvidenceRules); tieBreakRules = List.copyOf(tieBreakRules);
        }
    }
    public static Definition definition() {
        return new Definition(VERSION, Map.of("CVSS", 50d, "EPSS", 20d, "CONTEXTO", 20d, "SALUD", 10d),
            Map.of("CRITICA", 90d, "ALTA", 70d, "MEDIA", 40d, "BAJA", 0d),
            "100 × suma(puntos) / suma(pesos aplicables); redondeo a una décima; KEV confirmado impone mínimo 90 si evaluable.",
            List.of("OSV de componente y detalles completos, CVSS válido y contexto son esenciales.",
                "Con CVE se requieren todas las señales EPSS y KEV; sin CVE solo NO_APLICABLE excluye EPSS del denominador.",
                "Salud requiere asociación, informe no antiguo y cuatro indicadores disponibles; ausencias dejan puntuación/nivel nulos.",
                "KEV confirmado conserva precedencia aunque otra señal deje el hallazgo pendiente."),
            List.of("KEV confirmado primero", "Pendientes antes que evaluados dentro de cada grupo KEV", "Puntuación descendente", "PURL ascendente", "ID de vulnerabilidad ascendente"),
            "Por aviso: CVSS del paquete Maven exacto si está disponible; global solo si no hay CVSS específico. Mayor versión (4.0 > 3.1 > 3.0 > 2.0), luego máximo base. Vector específico erróneo no usa global como reemplazo.",
            "us.springett:cvss-calculator:1.5.1; solo métricas base, escala 0–10");
    }
    public RiskSnapshot evaluate(VulnerabilitySnapshot snapshot, DependencyGraph graph, AnalysisConfiguration configuration,
            Map<String, HealthAssessment> health) {
        var vulnerabilities = new HashMap<String, Vulnerability>();
        snapshot.vulnerabilities().forEach(value -> vulnerabilities.put(value.id(), value));
        var contexts = graph.contextsByComponent();
        var results = new LinkedHashMap<Finding, RiskAssessment>();
        Instant time = Instant.now();
        for (var finding : snapshot.findings()) {
            results.computeIfAbsent(finding, key -> assess(key, vulnerabilities.get(key.vulnerabilityId()), graph.components().get(key.componentPurl()),
                contexts.getOrDefault(key.componentPurl(), Set.of()), configuration, health.get(key.componentPurl()), snapshot.componentQueries().get(key.componentPurl()), time));
        }
        return new RiskSnapshot(definition(), time, results.values().stream().sorted(order()).toList());
    }
    public static Comparator<RiskAssessment> order() {
        return Comparator.comparing(RiskAssessment::knownExploited).reversed()
            .thenComparing(value -> value.status() == RiskEvaluationStatus.PENDIENTE_REVISION ? 0 : 1)
            .thenComparing(value -> value.score() == null ? 0d : -value.score())
            .thenComparing(value -> value.finding().componentPurl()).thenComparing(value -> value.finding().vulnerabilityId());
    }
    private RiskAssessment assess(Finding finding, Vulnerability vulnerability, Component component,
            Set<DependencyGraph.Occurrence> contexts, AnalysisConfiguration config, HealthAssessment health,
            Evidence<List<String>> query, Instant time) {
        var explanation = new ArrayList<String>();
        var contributions = new ArrayList<RiskContribution>();
        var cvssEvidence = new ArrayList<Evidence<String>>();
        var candidates = new ArrayList<Advisory.CvssScore>();
        boolean complete = query != null && query.status() == EvidenceStatus.DISPONIBLE && vulnerability != null && component != null;
        if (query != null) cvssEvidence.add(text(query));
        if (vulnerability != null) for (var evidence : vulnerability.advisories().values()) {
            cvssEvidence.add(new Evidence<>(evidence.source(), evidence.collectedAt(), evidence.sourceDate(), evidence.status(),
                evidence.value() == null ? null : evidence.value().id(), evidence.diagnostic()));
            if (evidence.status() != EvidenceStatus.DISPONIBLE) { complete = false; continue; }
            var specific = evidence.value().affected().stream().filter(value -> value.ecosystem().equals("Maven") && value.name().equals(component == null ? "" : component.name()))
                .map(Advisory.AffectedPackage::cvss).toList();
            boolean hasSpecific = specific.stream().anyMatch(value -> value.status() == EvidenceStatus.DISPONIBLE || value.status() == EvidenceStatus.ERROR);
            var chosen = hasSpecific ? specific : List.of(evidence.value().cvss());
            for (var value : chosen) {
                cvssEvidence.add(text(value));
                if (value.status() == EvidenceStatus.ERROR) complete = false;
                if (value.value() != null) candidates.addAll(value.value());
            }
        }
        Double base = null;
        try {
            // All relevant published vectors must be valid, even when a newer version wins the selection.
            var scored = new HashMap<Advisory.CvssScore, Double>();
            for (var candidate : candidates) scored.put(candidate, CvssBase.score(candidate));
            var selected = candidates.stream().sorted(Comparator.comparingDouble((Advisory.CvssScore value) -> Double.parseDouble(value.version())).reversed()
                .thenComparing(value -> -scored.get(value)).thenComparing(Advisory.CvssScore::vector).thenComparing(Advisory.CvssScore::source)).findFirst();
            if (complete && selected.isPresent()) {
                base = scored.get(selected.get());
                explanation.add("CVSS base elegido: " + base + " / 10; versión " + selected.get().version() + "; vector " + selected.get().vector() + "; fuente " + selected.get().source());
            }
        } catch (RuntimeException error) { explanation.add("Vector CVSS inválido, incompleto o no soportado; no se sustituye por cero."); }
        if (base == null) explanation.add("Se requiere OSV completo y una severidad CVSS válida aplicable al componente.");
        contributions.add(new RiskContribution("CVSS", 50, base == null ? null : base * 5, "CVSS base / 10 × 50; prioridad de versión y ámbito según la política.", cvssEvidence));

        Set<String> cves = vulnerability == null ? Set.of() : new TreeSet<>(vulnerability.aliases().stream().filter(value -> value.matches("CVE-[0-9]{4}-[0-9]{4,20}")).toList());
        var epss = vulnerability == null ? null : vulnerability.epssByCve();
        var kev = vulnerability == null ? null : vulnerability.kevByCve();
        var epssValues = epss == null || epss.value() == null ? Map.<String, Evidence<Vulnerability.Epss>>of() : epss.value();
        var kevValues = kev == null || kev.value() == null ? Map.<String, Evidence<Boolean>>of() : kev.value();
        boolean known = cves.stream().anyMatch(cve -> kevValues.containsKey(cve) && Boolean.TRUE.equals(kevValues.get(cve).value()));
        boolean noCve = cves.isEmpty() && epss != null && kev != null && epss.status() == EvidenceStatus.NO_APLICABLE && kev.status() == EvidenceStatus.NO_APLICABLE;
        boolean epssComplete = !cves.isEmpty() && cves.stream().allMatch(cve -> epssValues.containsKey(cve) && epssValues.get(cve).status() == EvidenceStatus.DISPONIBLE);
        boolean kevComplete = !cves.isEmpty() && cves.stream().allMatch(cve -> kevValues.containsKey(cve) && kevValues.get(cve).status() == EvidenceStatus.DISPONIBLE);
        double epssWeight = noCve ? 0 : 20;
        Double epssPoints = null;
        if (noCve) epssPoints = 0d;
        else if (epssComplete) epssPoints = cves.stream().mapToDouble(cve -> epssValues.get(cve).value().probability()).max().orElseThrow() * 20;
        var epssUsed = new ArrayList<Evidence<String>>();
        if (epss != null) epssUsed.add(text(epss));
        epssValues.forEach((cve, value) -> epssUsed.add(text(value)));
        contributions.add(new RiskContribution("EPSS", epssWeight, epssPoints, noCve ? "NO_APLICABLE: peso excluido, no dato desconocido convertido en cero." : "Máxima probabilidad EPSS de los CVE correlacionados × 20.", epssUsed));
        var kevUsed = new ArrayList<Evidence<String>>();
        if (kev != null) kevUsed.add(text(kev));
        kevValues.forEach((cve, value) -> kevUsed.add(text(value)));
        Double kevRule = known ? 90d : null;
        if (!known && kevComplete) kevRule = 0d;
        contributions.add(new RiskContribution("KEV", 0, kevRule, "No se suma: KEV confirmado precede en orden e impone mínimo 90 cuando la evaluación es completa; cero indica ausencia confirmada, no catálogo desconocido.", kevUsed));
        if (!(noCve || (epssComplete && kevComplete))) explanation.add("EPSS/KEV incompletos para los CVE aplicables; pendiente de revisión.");
        if (known) explanation.add("Explotación conocida confirmada en KEV: atender primero, incluso con puntuación pendiente.");

        var selectedContexts = contexts.stream().filter(value -> config.scopes().contains(value.scope())).sorted(Comparator.comparing(DependencyGraph.Occurrence::module).thenComparing(DependencyGraph.Occurrence::scope)).toList();
        Double contextPoints = selectedContexts.isEmpty() ? null : selectedContexts.stream().anyMatch(value -> !value.scope().equals("test")) ? 20d : 10d;
        contributions.add(new RiskContribution("CONTEXTO", 20, contextPoints, "Máximo por contexto: test 10, compile/runtime/provided 20; no descuento por transitividad ni declaración de despliegue.",
            List.of(Evidence.available("Instantánea Maven/configuración del análisis", time, null, selectedContexts.toString()))));
        if (contextPoints == null) explanation.add("Sin contexto Maven seleccionado; no se supone despliegue ni alcanzabilidad.");

        var healthUsed = new ArrayList<Evidence<String>>();
        Double healthPoints = null;
        if (health != null) {
            healthUsed.add(text(health.repository())); healthUsed.add(text(health.scorecard()));
            HealthAssessment.CHECKS.forEach(name -> healthUsed.add(text(health.indicators().get(name))));
            if (health.repository().status() == EvidenceStatus.DISPONIBLE && health.scorecard().status() == EvidenceStatus.DISPONIBLE && !health.scorecard().value().stale()
                    && HealthAssessment.CHECKS.stream().allMatch(name -> health.indicators().get(name).status() == EvidenceStatus.DISPONIBLE))
                healthPoints = 10 - HealthAssessment.CHECKS.stream().mapToInt(name -> health.indicators().get(name).value().score()).average().orElseThrow();
        }
        contributions.add(new RiskContribution("SALUD", 10, healthPoints, "10 − media de cuatro checks (0–10); requiere asociación e informe vigente según advertencia guardada.", healthUsed));
        if (healthPoints == null) explanation.add("Salud incompleta, asociación no comprobada o informe antiguo; no se inventa una media.");
        boolean evaluable = base != null && epssPoints != null && (noCve || kevComplete) && contextPoints != null && healthPoints != null;
        Double score = evaluable ? Math.round(100 * (base * 5 + epssPoints + contextPoints + healthPoints) / (80 + epssWeight) * 10) / 10d : null;
        if (score != null && known) score = Math.max(90, score);
        PriorityLevel level = score == null ? null : score >= 90 ? PriorityLevel.CRITICA : score >= 70 ? PriorityLevel.ALTA : score >= 40 ? PriorityLevel.MEDIA : PriorityLevel.BAJA;
        return new RiskAssessment(finding, VERSION, evaluable ? RiskEvaluationStatus.EVALUADO : RiskEvaluationStatus.PENDIENTE_REVISION, score, level, known,
            contributions, explanation, List.of("Índice del prototipo, no probabilidad de ataque ni modelo validado académicamente.", "Alcanzabilidad no analizada.",
                "Despliegue declarado no acredita exposición real; transitividad no reduce prioridad.", "Scorecard describe el repositorio, no certifica el artefacto instalado.", "Fechas y respuestas pertenecen a esta instantánea; no describen necesariamente el estado actual."));
    }
    private static Evidence<String> text(Evidence<?> value) {
        return new Evidence<>(value.source(), value.collectedAt(), value.sourceDate(), value.status(), value.value() == null ? null : value.value().toString(), value.diagnostic());
    }
}
