package com.smartsca;

import com.smartsca.adapter.outbound.sbom.CycloneDxSbomExporter;
import com.smartsca.application.port.inbound.StartAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.*;
import java.net.URI;
import java.net.http.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Disposable PostgreSQL: atomic artifact/snapshot writes, byte-stable downloads and restart/legacy handling. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
class SbomPersistenceTests {
    private final HttpClient client = HttpClient.newHttpClient();
    private final JsonMapper json = JsonMapper.builder().build();
    private ConfigurableApplicationContext start() {
        return SpringApplication.run(SmartScaApplication.class, "--server.port=0", "--smartsca.worker.enabled=false", "--smartsca.enrichment.enabled=false",
            "--logging.level.root=WARN", "--spring.main.banner-mode=off", "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"),
            "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"), "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"));
    }
    private HttpResponse<String> get(ConfigurableApplicationContext server, UUID id, String suffix) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getEnvironment().getProperty("local.server.port") + "/api/analyses/" + id + suffix)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
    @Test void downloadsOnlyThePersistedValidatedArtifactAndCommitsItAtomicallyWithTheSnapshot() throws Exception {
        UUID id; String content; String record;
        try (var server = start()) {
            var repository = server.getBean(AnalysisRepository.class);
            id = server.getBean(StartAnalysisUseCase.class).start("maven-basic", null);
            assertEquals(409, get(server, id, "/sbom").statusCode());
            assertFalse(json.readTree(get(server, id, "/sbom/status").body()).path("available").asBoolean());
            assertEquals(404, get(server, UUID.randomUUID(), "/sbom").statusCode());
            var running = repository.claimNextPending().orElseThrow();
            // Other tests may leave queued jobs: claim the request made by this test explicitly.
            while (!running.id().equals(id)) {
                repository.finish(running.finished(AnalysisStatus.FALLIDO, "TEST", List.of(), Map.of(), null, null, null, null));
                running = repository.claimNextPending().orElseThrow();
            }
            String root = "pkg:maven/demo/basic@1";
            var graph = new DependencyGraph(Map.of(".", root), Map.of(root, new Component(root, "maven", "demo:basic", "1", Map.of())), Set.of());
            var artifact = new CycloneDxSbomExporter().generateAndValidate(running, graph);
            var completed = running.finished(AnalysisStatus.PARCIAL, "INVENTARIO_Y_EVIDENCIAS_DISPONIBLES", List.of("SBOM validado; evaluación académica pendiente."), Map.of(), graph, null, null, null);
            var jdbc = new JdbcTemplate(server.getBean(javax.sql.DataSource.class));
            jdbc.update("INSERT INTO analysis_artifacts (analysis_id,schema_version,generated_at,sha256,content) VALUES (?,'1.6',CURRENT_TIMESTAMP,?,?)", id, artifact.sha256(), artifact.content());
            assertThrows(org.springframework.dao.DataAccessException.class, () -> repository.finish(completed, artifact));
            assertEquals(AnalysisStatus.EN_EJECUCION, repository.get(id).orElseThrow().status(), "Failed artifact insert must roll back the terminal snapshot");
            jdbc.update("DELETE FROM analysis_artifacts WHERE analysis_id=?", id);
            repository.finish(completed, artifact);
            var response = get(server, id, "/sbom");
            assertEquals(200, response.statusCode(), response.body());
            assertEquals("application/vnd.cyclonedx+json", response.headers().firstValue("Content-Type").orElseThrow());
            assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("attachment; filename=\"smartsca-" + id + "-cyclonedx-1.6.json\"", response.headers().firstValue("Content-Disposition").orElseThrow());
            content = response.body();
            assertEquals(artifact.content(), content);
            assertEquals(artifact.sha256(), json.readTree(get(server, id, "/sbom/status").body()).path("sha256").asString());
            record = get(server, id, "").body();
            assertFalse(record.contains("bomFormat"), "Normal analysis queries must not serialize artifact bytes");
            repository.finish(completed, new CycloneDxSbomExporter().generateAndValidate(running, graph));
            assertEquals(content, get(server, id, "/sbom").body(), "A repeated finish must not overwrite the original artifact");
            var legacyId = server.getBean(StartAnalysisUseCase.class).start("maven-basic", null);
            var legacy = repository.claimNextPending().orElseThrow();
            assertEquals(legacyId, legacy.id());
            repository.finish(legacy.finished(AnalysisStatus.PARCIAL, "TEST", List.of(), Map.of(), graph, null, null, null));
            assertEquals(409, get(server, legacyId, "/sbom").statusCode());
        }
        try (var restarted = start()) {
            assertEquals(content, get(restarted, id, "/sbom").body());
            assertEquals(json.readTree(record), json.readTree(get(restarted, id, "").body()));
            assertTrue(json.readTree(get(restarted, id, "/sbom/status").body()).path("available").asBoolean());
            var jdbc = new JdbcTemplate(restarted.getBean(javax.sql.DataSource.class));
            jdbc.update("UPDATE analysis_artifacts SET content='{}' WHERE analysis_id=?", id);
            assertEquals(409, get(restarted, id, "/sbom").statusCode(), "Damaged bytes must never be delivered as valid");
            assertFalse(json.readTree(get(restarted, id, "/sbom/status").body()).path("available").asBoolean());
        }
    }
}
