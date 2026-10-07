package com.smartsca.application.service;
import com.smartsca.application.port.inbound.RunPendingAnalysesUseCase;
import com.smartsca.application.port.outbound.*;
import com.smartsca.domain.analysis.*;
import java.util.*;
import java.util.concurrent.*;

/** Claims only free executor slots; PostgreSQL remains the queue's source of truth. */
public final class RunAnalysisService implements RunPendingAnalysesUseCase, AutoCloseable {
    private final AnalysisRepository analyses;
    private final DependencyResolver resolver;
    private final EnrichAnalysisService enrichment;
    private final HealthSource healthSource;
    private final ExecutorService executor;
    private final Semaphore slots;
    private final Map<String, String> versions;
    // ponytail: retain at most concurrency results in this process; restart recovery remains PostgreSQL-backed.
    private final Map<UUID, Analysis> pendingResults = new HashMap<>();
    public RunAnalysisService(AnalysisRepository analyses, DependencyResolver resolver, EnrichAnalysisService enrichment, HealthSource healthSource, int concurrency, Map<String, String> versions) {
        if (concurrency < 1 || concurrency > 4) throw new IllegalArgumentException("Concurrencia admitida: 1 a 4.");
        this.analyses = analyses;
        this.resolver = resolver;
        this.enrichment = enrichment;
        this.healthSource = healthSource;
        this.versions = Map.copyOf(versions);
        this.slots = new Semaphore(concurrency);
        this.executor = Executors.newFixedThreadPool(concurrency);
    }
    @Override public synchronized void runPending(int maxConcurrent) {
        persistCompleted();
        for (int i = 0; i < maxConcurrent && slots.tryAcquire(); i++) {
            try {
                var next = analyses.claimNextPending();
                if (next.isEmpty()) { slots.release(); break; }
                executor.submit(() -> run(next.get()));
            } catch (RuntimeException error) { slots.release(); throw error; }
        }
    }
    private void run(Analysis analysis) {
        boolean retained = false;
        try {
            Analysis result;
            try {
                var graph = resolver.resolve(analysis.project(), analysis.configuration());
                analyses.updateStep(analysis.id(), "CONSULTANDO_EVIDENCIAS_EXTERNAS");
                var snapshot = enrichment.enrich(graph, analysis.configuration());
                analyses.updateStep(analysis.id(), "CONSULTANDO_SALUD_REPOSITORIOS");
                var components = graph.componentsInScopes(analysis.configuration().scopes());
                Map<String, com.smartsca.domain.health.HealthAssessment> observed;
                try { observed = healthSource.assess(components); }
                catch (RuntimeException error) { observed = Map.of(); }
                var health = new TreeMap<String, com.smartsca.domain.health.HealthAssessment>();
                for (var component : components) health.put(component.purl(), observed.getOrDefault(component.purl(),
                    com.smartsca.domain.health.HealthAssessment.unavailable(component.purl(), "Salud", com.smartsca.domain.EvidenceStatus.ERROR, "Consulta de salud no completada.")));
                long failed = snapshot.componentQueries().values().stream().filter(value -> value.status() != com.smartsca.domain.EvidenceStatus.DISPONIBLE).count();
                analyses.updateStep(analysis.id(), "EVALUANDO_PRIORIDAD");
                var risk = new com.smartsca.domain.risk.RiskPolicy().evaluate(snapshot, graph, analysis.configuration(), health);
                result = analysis.finished(AnalysisStatus.PARCIAL, "INVENTARIO_Y_EVIDENCIAS_DISPONIBLES",
                    List.of("Resolución Maven completada. " + snapshot.findings().size() + " hallazgos identificados; " + failed + " consultas OSV incompletas.",
                        "Salud consultada para " + health.size() + " componentes. Prioridad evaluada con " + risk.policy().version() +
                        "; " + risk.assessments().stream().filter(value -> value.score() == null).count() + " hallazgos pendientes de revisión. SBOM aún no generado."), versions, graph, snapshot, health, risk);
            } catch (RuntimeException error) {
                String message = error instanceof IllegalArgumentException && error.getMessage() != null
                    ? error.getMessage() : "No se pudo completar la resolución Maven.";
                result = analysis.finished(AnalysisStatus.FALLIDO, "RESOLUCION_FALLIDA", List.of(message), versions, null, null, null, null);
            }
            synchronized (this) {
                pendingResults.put(result.id(), result);
                retained = true;
                persistCompleted();
            }
        } catch (RuntimeException error) {
            System.getLogger(RunAnalysisService.class.getName()).log(System.Logger.Level.ERROR,
                "No se pudo persistir el resultado del análisis " + analysis.id(), error);
        } finally { if (!retained) slots.release(); }
    }
    /** Called under this worker's monitor; a failed write keeps both the snapshot and its executor slot. */
    private void persistCompleted() {
        var pending = pendingResults.values().iterator();
        while (pending.hasNext()) {
            var result = pending.next();
            try {
                analyses.finish(result);
                pending.remove();
                slots.release();
            } catch (RuntimeException error) {
                System.getLogger(RunAnalysisService.class.getName()).log(System.Logger.Level.ERROR,
                    "Resultado pendiente de persistir; se reintentará para " + result.id(), error);
            }
        }
    }
    @Override public void failInterrupted() { analyses.failInterrupted(); }
    @Override public void close() {
        executor.shutdownNow();
        try { executor.awaitTermination(30, TimeUnit.SECONDS); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
    }
}
