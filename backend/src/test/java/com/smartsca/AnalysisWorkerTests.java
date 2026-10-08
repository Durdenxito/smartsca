package com.smartsca;

import com.smartsca.application.port.outbound.*;
import com.smartsca.application.service.*;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.DependencyGraph;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic worker recovery checks; provider/storage failures are injected, without Docker or a database. */
class AnalysisWorkerTests {
    private static final String ROOT = "pkg:maven/demo/sample@1";
    private static final DependencyGraph GRAPH = new DependencyGraph(Map.of(".", ROOT), Map.of(ROOT,
        new com.smartsca.domain.component.Component(ROOT, "maven", "demo:sample", "1", Map.of())), Set.of());
    private static final class MemoryRepository implements AnalysisRepository {
        final Map<UUID, Analysis> records = new ConcurrentHashMap<>();
        final Queue<Analysis> queue = new ConcurrentLinkedQueue<>();
        final List<Analysis> attempts = new CopyOnWriteArrayList<>();
        final List<AnalysisArtifact> artifactAttempts = new CopyOnWriteArrayList<>();
        final Map<UUID, AnalysisArtifact> artifacts = new ConcurrentHashMap<>();
        final AtomicInteger failingWrites = new AtomicInteger();
        UUID enqueue() {
            var request = new Analysis(UUID.randomUUID(), new Project("sample", "Sample", "catalog:sample", "fixture:test", Set.of("."), Set.of()),
                AnalysisConfiguration.defaults(), AnalysisStatus.EN_COLA, "REGISTRADO", Instant.now(), null, null,
                "test", List.of(), Map.of(), null, null, null, null);
            save(request); queue.add(request); return request.id();
        }
        public void save(Analysis value) { records.put(value.id(), value); }
        public Optional<Analysis> get(UUID id) { return Optional.ofNullable(records.get(id)); }
        public com.smartsca.application.port.inbound.ListAnalysesUseCase.Page list(String project, AnalysisStatus status, int offset) { throw new UnsupportedOperationException(); }
        public Optional<Analysis> claimNextPending() {
            var request = queue.poll();
            if (request == null) return Optional.empty();
            var running = new Analysis(request.id(), request.project(), request.configuration(), AnalysisStatus.EN_EJECUCION,
                "RESOLVIENDO_MAVEN", request.createdAt(), Instant.now(), null, request.engineVersion(), List.of(), Map.of(), null, null, null, null);
            save(running); return Optional.of(running);
        }
        public void updateStep(UUID id, String step) { }
        public Optional<AnalysisArtifact> readSbom(UUID id) { return Optional.ofNullable(artifacts.get(id)); }
        public void finish(Analysis value, AnalysisArtifact sbom) {
            attempts.add(value);
            artifactAttempts.add(sbom);
            if (failingWrites.getAndUpdate(count -> Math.max(0, count - 1)) > 0) throw new IllegalStateException("Temporary storage failure");
            if (sbom != null) artifacts.put(value.id(), sbom);
            save(value);
        }
        public void failInterrupted() { }
    }
    private RunAnalysisService worker(MemoryRepository repository, DependencyResolver resolver) {
        return worker(repository, resolver, new com.smartsca.adapter.outbound.sbom.CycloneDxSbomExporter());
    }
    private RunAnalysisService worker(MemoryRepository repository, DependencyResolver resolver, SbomExporter sbom) {
        var signals = new ExploitSignalsSource() {
            public Map<String, com.smartsca.domain.Evidence<com.smartsca.domain.vulnerability.Vulnerability.Epss>> epss(Set<String> cves) { return Map.of(); }
            public Map<String, com.smartsca.domain.Evidence<Boolean>> kev(Set<String> cves) { return Map.of(); }
        };
        var enrichment = new EnrichAnalysisService(components -> new VulnerabilitySource.Result(Map.of(), Map.of(), Map.of()), signals);
        return new RunAnalysisService(repository, resolver, enrichment, components -> Map.of(), sbom, 1, Map.of("maven", "test"));
    }
    private void await(BooleanSupplier condition) {
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> { while (!condition.getAsBoolean()) Thread.sleep(10); });
    }

    @Test void resolverTimeoutIsVisibleAsFailedAndTheNextJobCanUseTheSlot() {
        var repository = new MemoryRepository();
        UUID first = repository.enqueue(), second = repository.enqueue();
        var resolutions = new AtomicInteger();
        try (var worker = worker(repository, (project, configuration) -> {
            if (resolutions.incrementAndGet() == 1) throw new IllegalArgumentException("Se agotó el tiempo de resolución Maven.");
            return GRAPH;
        })) {
            worker.runPending(1);
            await(() -> repository.get(first).orElseThrow().status() == AnalysisStatus.FALLIDO);
            var failed = repository.get(first).orElseThrow();
            assertEquals("RESOLUCION_FALLIDA", failed.currentStep());
            assertEquals(List.of("Se agotó el tiempo de resolución Maven."), failed.diagnostics());
            assertNotNull(failed.startedAt()); assertNotNull(failed.finishedAt());
            assertNull(failed.dependencyGraph());
            await(() -> { worker.runPending(1); return repository.get(second).orElseThrow().status() == AnalysisStatus.PARCIAL; });
            assertEquals(2, resolutions.get());
        }
    }

    @Test void failedFinalWritesRetainTheSameSnapshotAndSlotUntilStorageRecovers() {
        var repository = new MemoryRepository();
        UUID first = repository.enqueue(), second = repository.enqueue();
        repository.failingWrites.set(2);
        var resolutions = new AtomicInteger();
        try (var worker = worker(repository, (project, configuration) -> { resolutions.incrementAndGet(); return GRAPH; })) {
            worker.runPending(1);
            await(() -> repository.attempts.size() == 1);
            worker.runPending(1);
            assertEquals(2, repository.attempts.size());
            assertEquals(AnalysisStatus.EN_EJECUCION, repository.get(first).orElseThrow().status());
            assertEquals(AnalysisStatus.EN_COLA, repository.get(second).orElseThrow().status());
            assertEquals(1, resolutions.get());
            worker.runPending(1);
            await(() -> repository.get(second).orElseThrow().status() == AnalysisStatus.PARCIAL);
            assertSame(repository.attempts.get(0), repository.attempts.get(1));
            assertSame(repository.attempts.get(0), repository.attempts.get(2));
            assertSame(repository.attempts.get(0), repository.get(first).orElseThrow());
            assertNotNull(repository.artifactAttempts.get(0));
            assertSame(repository.artifactAttempts.get(0), repository.artifactAttempts.get(1));
            assertSame(repository.artifactAttempts.get(0), repository.artifactAttempts.get(2));
            assertSame(repository.artifactAttempts.get(0), repository.readSbom(first).orElseThrow());
            assertEquals(2, resolutions.get());
            assertEquals(4, repository.attempts.size());
        }
    }
    @Test void sbomValidationFailureKeepsTheResolvedResultsPartialAndReleasesTheSlot() {
        var repository = new MemoryRepository();
        UUID first = repository.enqueue(), second = repository.enqueue();
        try (var worker = worker(repository, (project, configuration) -> GRAPH, (analysis, graph) -> {
            throw new IllegalArgumentException("invalid schema with internal path not disclosed");
        })) {
            worker.runPending(1);
            await(() -> repository.get(first).orElseThrow().status() == AnalysisStatus.PARCIAL);
            var result = repository.get(first).orElseThrow();
            assertEquals(GRAPH, result.dependencyGraph());
            assertNotNull(result.vulnerabilitySnapshot()); assertNotNull(result.healthAssessments()); assertNotNull(result.riskSnapshot());
            assertTrue(result.diagnostics().stream().anyMatch(value -> value.startsWith("SBOM no disponible:")));
            assertFalse(result.diagnostics().toString().contains("internal path"));
            assertTrue(repository.readSbom(first).isEmpty());
            await(() -> { worker.runPending(1); return repository.get(second).orElseThrow().status() == AnalysisStatus.PARCIAL; });
        }
    }
}
