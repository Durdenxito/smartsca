package com.smartsca;

import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.risk.*;
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

/** Real history queries, ordering, boundary validation and restart persistence in a disposable database. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
class AnalysisHistoryTests {
    private final JsonMapper json = JsonMapper.builder().build();
    private final HttpClient client = HttpClient.newHttpClient();
    private ConfigurableApplicationContext start() {
        return SpringApplication.run(SmartScaApplication.class, "--server.port=0", "--smartsca.worker.enabled=false",
            "--smartsca.enrichment.enabled=false", "--logging.level.root=WARN", "--spring.main.banner-mode=off",
            "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"),
            "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"),
            "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"));
    }
    private HttpResponse<String> get(ConfigurableApplicationContext server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getEnvironment().getProperty("local.server.port") + path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
    @Test void filtersAndPaginatesMetadataWithoutReplacingSavedResultsAfterRestart() throws Exception {
        String projectId = "history-" + UUID.randomUUID();
        var project = new Project(projectId, "Proyecto retirado del catálogo", "catalog:retired", "fixture:original", Set.of("."), Set.of());
        Instant time = Instant.parse("2026-01-01T00:00:00Z");
        var policy = new RiskPolicy.Definition("original-policy", Map.of(), Map.of(), "original", List.of(), List.of(), "original", "original");
        UUID firstId = UUID.randomUUID();
        String original;
        try (var server = start()) {
            var repository = server.getBean(AnalysisRepository.class);
            var ids = new ArrayList<UUID>();
            for (int i = 0; i < 22; i++) {
                UUID id = i == 0 ? firstId : UUID.randomUUID(); ids.add(id);
                var status = i == 0 ? AnalysisStatus.FALLIDO : i == 1 ? AnalysisStatus.EN_COLA : AnalysisStatus.PARCIAL;
                repository.save(new Analysis(id, project, new AnalysisConfiguration(Set.of("."), Set.of(), Set.of("test"), "java-21", "Contexto original"),
                    status, "GUARDADO", time, status == AnalysisStatus.EN_COLA ? null : time, status == AnalysisStatus.EN_COLA ? null : time.plusSeconds(12),
                    "original-engine", List.of("Diagnóstico original"), Map.of(), null, null, null, new RiskSnapshot(policy, time, List.of())));
            }
            original = get(server, "/api/analyses/" + firstId).body();
            var response = get(server, "/api/analyses?projectId=" + projectId);
            assertEquals(200, response.statusCode(), response.body());
            var page = json.readTree(response.body());
            assertEquals(20, page.path("items").size());
            assertEquals(20, page.path("nextOffset").asInt());
            assertFalse(page.path("navigationLimited").asBoolean());
            // PostgreSQL UUID ordering is unsigned; textual canonical UUIDs have the same order.
            var expected = ids.stream().map(UUID::toString).sorted(Comparator.reverseOrder()).toList();
            for (int i = 0; i < 20; i++) assertEquals(expected.get(i), page.path("items").get(i).path("id").asString());
            var entry = page.path("items").get(0);
            assertFalse(entry.has("riskSnapshot")); assertFalse(entry.has("dependencyGraph")); assertFalse(entry.has("vulnerabilitySnapshot"));
            assertEquals("test", entry.path("configuration").path("scopes").get(0).asString());
            assertEquals("fixture:original", entry.path("analyzedReference").asString());
            var second = json.readTree(get(server, "/api/analyses?projectId=" + projectId + "&offset=20").body());
            assertEquals(2, second.path("items").size()); assertTrue(second.path("nextOffset").isNull());
            assertEquals(expected.get(20), second.path("items").get(0).path("id").asString());
            for (String state : List.of("FALLIDO", "PARCIAL", "EN_COLA", "EN_EJECUCION", "COMPLETO")) {
                var filtered = get(server, "/api/analyses?projectId=" + projectId + "&status=" + state);
                assertEquals(200, filtered.statusCode(), filtered.body());
                for (var item : json.readTree(filtered.body()).path("items")) assertEquals(state, item.path("status").asString());
            }
            assertEquals(1, json.readTree(get(server, "/api/analyses?projectId=" + projectId + "&status=FALLIDO").body()).path("items").size());
            assertEquals(0, json.readTree(get(server, "/api/analyses?projectId=absent-history-project").body()).path("items").size());
            assertEquals(200, get(server, "/api/analyses?status=PARCIAL&offset=10000").statusCode());
            for (String invalid : List.of("offset=-1", "offset=10001", "offset=x", "status=UNKNOWN", "projectId=..%2Foutside", "projectId=a%27%20OR%201%3D1"))
                assertEquals(400, get(server, "/api/analyses?" + invalid).statusCode(), invalid);
            assertEquals(json.readTree(original), json.readTree(get(server, "/api/analyses/" + firstId).body()));
        }
        try (var server = start()) {
            assertEquals(json.readTree(original), json.readTree(get(server, "/api/analyses/" + firstId).body()));
            var failed = json.readTree(get(server, "/api/analyses?projectId=" + projectId + "&status=FALLIDO").body());
            assertEquals(firstId.toString(), failed.path("items").get(0).path("id").asString());
            assertEquals("original-policy", json.readTree(get(server, "/api/analyses/" + firstId).body()).path("riskSnapshot").path("policy").path("version").asString());
        }
    }
}
