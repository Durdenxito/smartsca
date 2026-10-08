package com.smartsca;

import com.smartsca.application.port.inbound.StartAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.*;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.DependencyGraph;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.risk.*;
import com.smartsca.domain.vulnerability.*;
import java.net.URI;
import java.net.http.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Real HTTP/PostgreSQL: unknown sections, observed zeros and failed/legacy snapshots stay distinct. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
class AnalysisExportTests {
    private final JsonMapper json = JsonMapper.builder().build();
    private HttpResponse<String> get(ConfigurableApplicationContext server, String path) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
            server.getEnvironment().getProperty("local.server.port") + "/api/analyses/" + path)).build(), HttpResponse.BodyHandlers.ofString());
    }
    private Analysis claim(AnalysisRepository repository, UUID id) {
        var running = repository.claimNextPending().orElseThrow();
        while (!running.id().equals(id)) {
            repository.finish(running.finished(AnalysisStatus.FALLIDO, "TEST", List.of(), Map.of(), null, null, null, null));
            running = repository.claimNextPending().orElseThrow();
        }
        return running;
    }
    @Test void exportsStoredEvidenceCoverageAndDiagnosticsWithoutReplacingUnknownWithZero() throws Exception {
        try (var server = SpringApplication.run(SmartScaApplication.class, "--server.port=0", "--smartsca.worker.enabled=false", "--smartsca.enrichment.enabled=false",
                "--logging.level.root=WARN", "--spring.main.banner-mode=off", "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"),
                "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"), "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"))) {
            var repository = server.getBean(AnalysisRepository.class);
            var start = server.getBean(StartAnalysisUseCase.class);
            UUID id = start.start("maven-basic", null);
            var queued = json.readTree(get(server, id + "/export").body());
            assertEquals("EN_COLA", queued.path("analysis").path("status").asString());
            assertEquals(4, queued.path("sectionsNotObtained").size());
            assertTrue(queued.path("selectedComponentPurls").isNull());
            assertTrue(queued.path("coverage").path("evaluatedFindings").path("available").isNull());
            assertTrue(queued.path("coverage").path("osvComponentQueries").path("total").isNull());
            assertEquals(404, get(server, UUID.randomUUID() + "/export").statusCode());
            assertEquals(400, get(server, "invalid/export").statusCode());
            var running = claim(repository, id);
            var graph = VulnerabilityEnrichmentTests.graph();
            String a = VulnerabilityEnrichmentTests.A.purl(), b = VulnerabilityEnrichmentTests.B.purl(), cve = "CVE-2026-1111";
            var first = new Finding(a, cve); var second = new Finding(b, cve);
            var time = Instant.parse("2020-01-01T00:00:00Z");
            var vulnerability = new Vulnerability(cve, Set.of(cve, "GHSA-reference"), Map.of("GHSA-reference", new Evidence<Advisory>("https://reference.test/advisory", time, "2019-12-01", EvidenceStatus.ERROR, null, "Detalle OSV fallido")),
                new Evidence<>("https://reference.test/epss", time, null, EvidenceStatus.NO_APLICABLE, null, "No aplicable"),
                new Evidence<>("https://reference.test/kev", time, null, EvidenceStatus.NO_DISPONIBLE, null, "Sin catálogo"));
            var snapshot = new VulnerabilitySnapshot(List.of(first, second, first), List.of(vulnerability, vulnerability), Map.of(
                a, Evidence.available("https://reference.test/osv", time, "2019-12-01", List.of("GHSA-reference")),
                b, new Evidence<>("https://reference.test/osv", time, null, EvidenceStatus.ERROR, null, "Consulta OSV fallida")));
            var indicators = new HashMap<String, Evidence<HealthAssessment.Indicator>>();
            HealthAssessment.CHECKS.forEach(name -> indicators.put(name, Evidence.available("https://reference.test/scorecard", time, null,
                new HealthAssessment.Indicator(name, 0, "Cero publicado", List.of(), "https://reference.test/check"))));
            var stale = new HealthAssessment(a, Evidence.available("https://reference.test/scm", time, null, new HealthAssessment.RepositoryAssociation("github.com/demo/library", "reference")),
                Evidence.available("https://reference.test/scorecard", time, null, new HealthAssessment.ScorecardReport("github.com/demo/library", "abc", "v5", "def", true, "scorecard-age-v1-90d")), indicators, List.of());
            var risk = new RiskSnapshot(RiskPolicy.definition(), time, List.of(
                new RiskAssessment(first, "smartsca-priority-v1", RiskEvaluationStatus.EVALUADO, 0d, PriorityLevel.BAJA, false, List.of(), List.of("Cero evaluado guardado"), List.of()),
                new RiskAssessment(second, "smartsca-priority-v1", RiskEvaluationStatus.PENDIENTE_REVISION, null, null, false, List.of(), List.of("Faltan datos"), List.of("Sin evaluación"))));
            var failed = running.finished(AnalysisStatus.FALLIDO, "REFERENCIA_FALLIDA", List.of("Diagnóstico conservado: <script>texto</script>"), Map.of("java", "21"), graph, snapshot,
                Map.of(a, stale, b, HealthAssessment.unavailable(b, "https://reference.test/scorecard", EvidenceStatus.NO_DISPONIBLE, "Sin informe")), risk);
            repository.finish(failed);
            var response = get(server, id + "/export");
            assertEquals(200, response.statusCode(), response.body());
            assertEquals("application/json", response.headers().firstValue("Content-Type").orElseThrow());
            assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("attachment; filename=\"smartsca-" + id + "-analysis-v1.json\"", response.headers().firstValue("Content-Disposition").orElseThrow());
            var exported = json.readTree(response.body());
            assertEquals("1.0", exported.path("schemaVersion").asString());
            assertEquals(json.readTree(get(server, id.toString()).body()), exported.path("analysis"));
            assertEquals(json.readTree("[\"" + a + "\",\"" + b + "\"]"), exported.path("selectedComponentPurls"));
            assertEquals(json.readTree("{\"osvComponentQueries\":{\"available\":1,\"total\":2},\"osvAdvisoryDetails\":{\"available\":0,\"total\":1},\"health\":{\"available\":0,\"total\":2},\"evaluatedFindings\":{\"available\":1,\"total\":2}}"), exported.path("coverage"));
            assertTrue(exported.path("sectionsNotObtained").isEmpty());
            assertFalse(exported.path("limitations").isEmpty());
            assertEquals(0d, exported.path("analysis").path("riskSnapshot").path("assessments").get(0).path("score").asDouble());
            assertTrue(exported.path("analysis").path("riskSnapshot").path("assessments").get(1).path("score").isNull());
            assertTrue(exported.path("analysis").path("healthAssessments").path(a).path("scorecard").path("value").path("stale").asBoolean());
            assertEquals(exported, json.readTree(get(server, id + "/export").body()));
            assertTrue(repository.readSbom(id).isEmpty(), "JSON export must not create an SBOM or rewrite the snapshot");
            UUID legacyId = start.start("maven-basic", null);
            repository.finish(claim(repository, legacyId).finished(AnalysisStatus.PARCIAL, "LEGACY", List.of(), Map.of(), graph, null, null, null));
            var legacy = json.readTree(get(server, legacyId + "/export").body());
            assertEquals(3, legacy.path("sectionsNotObtained").size());
            assertTrue(legacy.path("coverage").path("osvComponentQueries").path("available").isNull());
            assertEquals(2, legacy.path("coverage").path("osvComponentQueries").path("total").asInt());
            UUID emptyId = start.start("maven-basic", null);
            String root = graph.rootsByModule().get(".");
            repository.finish(claim(repository, emptyId).finished(AnalysisStatus.PARCIAL, "VACIO", List.of(), Map.of(), new DependencyGraph(Map.of(".", root), Map.of(root, graph.components().get(root)), Set.of()),
                new VulnerabilitySnapshot(List.of(), List.of(), Map.of()), Map.of(), new RiskSnapshot(RiskPolicy.definition(), time, List.of())));
            var empty = json.readTree(get(server, emptyId + "/export").body());
            assertEquals(0, empty.path("selectedComponentPurls").size());
            for (var section : empty.path("coverage")) {
                assertTrue(section.path("available").isNumber()); assertEquals(0, section.path("available").asInt());
                assertTrue(section.path("total").isNumber()); assertEquals(0, section.path("total").asInt());
            }
        }
    }
}
