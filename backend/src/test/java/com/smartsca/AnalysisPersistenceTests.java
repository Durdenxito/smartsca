package com.smartsca;

import java.net.URI;
import java.net.http.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Runs against an explicitly supplied disposable PostgreSQL database, including a server restart. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
class AnalysisPersistenceTests {
    private final HttpClient client = HttpClient.newHttpClient();
    private final JsonMapper json = JsonMapper.builder().build();

    private ConfigurableApplicationContext start() {
        return SpringApplication.run(SmartScaApplication.class, "--server.port=0",
            "--smartsca.worker.enabled=false",
            "--smartsca.enrichment.enabled=false",
            "--debug=false", "--logging.level.root=WARN", "--spring.main.banner-mode=off",
            "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"),
            "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"),
            "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"));
    }

    private HttpResponse<String> call(ConfigurableApplicationContext server, String path, String body) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getEnvironment().getProperty("local.server.port") + path));
        if (body == null) request.GET();
        else request.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test void apiPersistsConfigurationAndReturnsTheSameRecordAfterRestart() throws Exception {
        String location;
        String persisted;
        try (var server = start()) {
            var catalog = call(server, "/api/projects", null);
            assertEquals(200, catalog.statusCode());
            assertEquals(10, json.readTree(catalog.body()).path("projects").size());
            for (String invalid : new String[] {
                "{}", "{\"projectId\":\"../outside\"}", "{\"projectId\":\"absent\"}",
                "{\"projectId\":\"maven-basic\",\"configuration\":{\"modules\":[\".\"],\"profiles\":[],\"scopes\":[],\"environmentId\":\"java-21\"}}",
                "{\"projectId\":\"maven-basic\",\"configuration\":{\"modules\":[\".\"],\"profiles\":[\"unknown\"],\"scopes\":[\"test\"],\"environmentId\":\"java-21\"}}"
            }) assertEquals(400, call(server, "/api/analyses", invalid).statusCode());
            var accepted = call(server, "/api/analyses", """
                {"projectId":"maven-basic","configuration":{"modules":["."],"profiles":[],"scopes":["test"],
                "environmentId":"java-21","declaredDeployment":"  laboratorio  "}}
                """);
            assertEquals(202, accepted.statusCode(), accepted.body());
            var result = json.readTree(accepted.body());
            UUID.fromString(result.path("id").asString());
            assertEquals("EN_COLA", result.path("status").asString());
            location = accepted.headers().firstValue("Location").orElseThrow();
            assertEquals("/api/analyses/" + result.path("id").asString(), location);
            var response = call(server, location, null);
            assertEquals(200, response.statusCode());
            persisted = response.body();
            var analysis = json.readTree(persisted);
            assertEquals("laboratorio", analysis.path("configuration").path("declaredDeployment").asString());
            assertEquals("test", analysis.path("configuration").path("scopes").get(0).asString());
            assertTrue(analysis.path("startedAt").isNull());
            assertTrue(analysis.path("finishedAt").isNull());
            assertEquals(400, call(server, location + "/graph?module=.", null).statusCode());
            assertEquals(400, call(server, location + "/routes?purl=missing", null).statusCode());
            assertEquals(0, analysis.path("diagnostics").size());
            assertEquals(404, call(server, "/api/analyses/" + UUID.randomUUID(), null).statusCode());
            assertEquals(400, call(server, "/api/analyses/not-a-uuid", null).statusCode());
            var second = call(server, "/api/analyses", "{\"projectId\":\"maven-basic\"}");
            assertEquals(202, second.statusCode());
            assertNotEquals(result.path("id").asString(), json.readTree(second.body()).path("id").asString());
        }
        try (var restarted = start()) {
            var response = call(restarted, location, null);
            assertEquals(200, response.statusCode());
            assertEquals(json.readTree(persisted), json.readTree(response.body()));
        }
    }

    @Test void claimsAtomicallyRecoversInterruptedJobsAndPersistsResolvedInventory() throws Exception {
        String location;
        String graph;
        try (var server = start()) {
            var repository = server.getBean(com.smartsca.application.port.outbound.AnalysisRepository.class);
            var useCase = server.getBean(com.smartsca.application.port.inbound.StartAnalysisUseCase.class);
            useCase.start("maven-basic", null);
            useCase.start("maven-basic", null);
            try (var pool = java.util.concurrent.Executors.newFixedThreadPool(2)) {
                var a = pool.submit(() -> repository.claimNextPending().orElseThrow());
                var b = pool.submit(() -> repository.claimNextPending().orElseThrow());
                var first = a.get(20, java.util.concurrent.TimeUnit.SECONDS);
                var second = b.get(20, java.util.concurrent.TimeUnit.SECONDS);
                assertNotEquals(first.id(), second.id());
                assertEquals(com.smartsca.domain.analysis.AnalysisStatus.EN_EJECUCION, first.status());
                assertNotNull(first.startedAt());
                repository.failInterrupted();
                assertEquals(com.smartsca.domain.analysis.AnalysisStatus.FALLIDO, repository.get(first.id()).orElseThrow().status());
                assertEquals("INTERRUMPIDO", repository.get(second.id()).orElseThrow().currentStep());
            }
            if (!"true".equals(System.getenv("SMARTSCA_TEST_DOCKER"))) return;
            var accepted = call(server, "/api/analyses", "{\"projectId\":\"maven-multimodule\"}");
            assertEquals(202, accepted.statusCode());
            location = accepted.headers().firstValue("Location").orElseThrow();
            var runner = server.getBean(com.smartsca.application.port.inbound.RunPendingAnalysesUseCase.class);
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(180).toNanos();
            tools.jackson.databind.JsonNode record;
            do {
                runner.runPending(4);
                record = json.readTree(call(server, location, null).body());
                if (record.path("status").asString().equals("FALLIDO")) fail(record.toString());
                if (record.path("status").asString().equals("PARCIAL")) break;
                Thread.sleep(200);
            } while (System.nanoTime() < deadline);
            assertEquals("PARCIAL", record.path("status").asString());
            assertEquals("INVENTARIO_Y_EVIDENCIAS_DISPONIBLES", record.path("currentStep").asString());
            assertTrue(record.path("vulnerabilitySnapshot").path("componentQueries").size() > 0);
            assertEquals("3.9.9", record.path("environmentVersions").path("maven").asString());
            assertEquals(3, record.path("dependencyGraph").path("rootsByModule").size());
            graph = record.path("dependencyGraph").toString();
            assertEquals(1, json.readTree(call(server, location + "/components?search=commons-lang3&module=lib&direct=true", null).body()).size());
            assertEquals(0, json.readTree(call(server, location + "/components?search=commons-lang3&module=app&direct=true", null).body()).size());
            assertEquals(1, json.readTree(call(server, location + "/components?search=commons-lang3&module=app&direct=false", null).body()).size());
            assertEquals(1, json.readTree(call(server, location + "/components?search=commons-lang3&scope=compile", null).body()).size());
            assertEquals(0, json.readTree(call(server, location + "/components?search=commons-lang3&scope=runtime", null).body()).size());
            var completed = repository.get(UUID.fromString(record.path("id").asString())).orElseThrow();
            repository.finish(completed);
            assertEquals(completed, repository.get(completed.id()).orElseThrow());
            assertGraphQueries(server, location);
        }
        try (var restarted = start()) {
            var record = json.readTree(call(restarted, location, null).body());
            assertEquals("PARCIAL", record.path("status").asString());
            assertEquals(json.readTree(graph), record.path("dependencyGraph"));
            assertEquals(3, json.readTree(call(restarted, location + "/components", null).body()).size());
            assertGraphQueries(restarted, location);
        }
    }
    private void assertGraphQueries(ConfigurableApplicationContext server, String location) throws Exception {
        String purl = java.net.URLEncoder.encode("pkg:maven/org.apache.commons/commons-lang3@3.14.0", java.nio.charset.StandardCharsets.UTF_8);
        var routes = call(server, location + "/routes?purl=" + purl, null);
        assertEquals(200, routes.statusCode(), routes.body());
        var result = json.readTree(routes.body());
        assertEquals(3, result.path("routes").size());
        assertEquals("app", result.path("routes").get(0).path("module").asString());
        assertEquals(2, result.path("routes").get(0).path("steps").size());
        assertEquals("app", result.path("routes").get(1).path("module").asString());
        assertEquals(2, result.path("routes").get(1).path("steps").size());
        assertEquals("lib", result.path("routes").get(2).path("module").asString());
        assertEquals(1, result.path("routes").get(2).path("steps").size());
        assertFalse(result.path("searchLimited").asBoolean());
        assertTrue(result.path("nextOffset").isNull());
        var neighborhood = call(server, location + "/graph?module=app&purl=" + purl, null);
        assertEquals(200, neighborhood.statusCode(), neighborhood.body());
        assertEquals(2, json.readTree(neighborhood.body()).path("neighbors").size());
        assertEquals(400, call(server, location + "/graph?module=missing", null).statusCode());
        assertEquals(400, call(server, location + "/graph", null).statusCode());
        assertEquals(400, call(server, location + "/routes", null).statusCode());
        assertEquals(400, call(server, location + "/graph?module=app&offset=-1", null).statusCode());
        assertEquals(400, call(server, location + "/routes?purl=missing", null).statusCode());
        assertEquals(400, call(server, location + "/routes?purl=" + purl + "&offset=1001", null).statusCode());
    }
}
