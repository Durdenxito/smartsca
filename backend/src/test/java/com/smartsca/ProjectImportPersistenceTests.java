package com.smartsca;

import com.smartsca.application.port.inbound.*;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Real multipart, PostgreSQL, Docker resolution and restart retain an imported project's original provenance. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DOCKER", matches = "true")
class ProjectImportPersistenceTests {
    @TempDir Path root;
    private final JsonMapper json = JsonMapper.builder().build();
    private final HttpClient http = HttpClient.newHttpClient();
    private ConfigurableApplicationContext start() {
        return SpringApplication.run(SmartScaApplication.class, "--server.port=0", "--smartsca.worker.enabled=false", "--smartsca.enrichment.enabled=false",
            "--smartsca.imports-root=" + root.resolve("imports"), "--logging.level.root=WARN", "--spring.main.banner-mode=off",
            "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"), "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"),
            "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"));
    }
    private URI uri(ConfigurableApplicationContext server, String path) { return URI.create("http://127.0.0.1:" + server.getEnvironment().getProperty("local.server.port") + "/api/" + path); }
    private HttpResponse<String> upload(ConfigurableApplicationContext server, byte[] bytes) throws Exception {
        String boundary = "smartsca-" + UUID.randomUUID();
        return http.send(HttpRequest.newBuilder(uri(server, "projects/import/zip")).header("Content-Type", "multipart/form-data; boundary=" + boundary)
            .POST(HttpRequest.BodyPublishers.concat(HttpRequest.BodyPublishers.ofString("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + "p".repeat(251) + ".zip\"\r\nContent-Type: application/zip\r\n\r\n"),
                HttpRequest.BodyPublishers.ofByteArray(bytes), HttpRequest.BodyPublishers.ofString("\r\n--" + boundary + "--\r\n"))).build(), HttpResponse.BodyHandlers.ofString());
    }
    private String get(ConfigurableApplicationContext server, String path) throws Exception { return http.send(HttpRequest.newBuilder(uri(server, path)).build(), HttpResponse.BodyHandlers.ofString()).body(); }
    @Test void importedProjectCanBeConfiguredResolvedExportedAndQueriedAfterRestart() throws Exception {
        UUID analysisId; String projectId, reference, persisted;
        try (var server = start()) {
            assertEquals(400, upload(server, "not zip".getBytes(StandardCharsets.UTF_8)).statusCode());
            assertEquals(413, upload(server, new byte[10 * 1024 * 1024 + 1]).statusCode());
            var invalidGit = http.send(HttpRequest.newBuilder(uri(server, "projects/import/git")).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"url\":\"https://127.0.0.1/private\"}")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, invalidGit.statusCode());
            var response = upload(server, ProjectImportTests.archive(Map.of("pom.xml", ProjectImportTests.POM)));
            assertEquals(201, response.statusCode(), response.body());
            var project = json.readTree(response.body()); projectId = project.path("id").asString(); reference = project.path("sourceReference").asString();
            assertTrue(reference.length() > 255, "Full archive filename plus SHA must persist without truncation");
            assertEquals(11, json.readTree(get(server, "projects")).path("projects").size());
            var repository = server.getBean(AnalysisRepository.class);
            while (repository.claimNextPending().isPresent()) repository.failInterrupted();
            var accepted = http.send(HttpRequest.newBuilder(uri(server, "analyses")).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("projectId", projectId, "configuration", AnalysisConfiguration.defaults())))).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(202, accepted.statusCode(), accepted.body()); analysisId = UUID.fromString(json.readTree(accepted.body()).path("id").asString());
            server.getBean(RunPendingAnalysesUseCase.class).runPending(1);
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(120).toNanos();
            while (repository.get(analysisId).orElseThrow().finishedAt() == null && System.nanoTime() < deadline) Thread.sleep(100);
            var result = repository.get(analysisId).orElseThrow();
            assertEquals(AnalysisStatus.PARCIAL, result.status(), result.diagnostics().toString());
            assertEquals(reference, result.project().sourceReference());
            assertTrue(result.dependencyGraph().components().containsKey("pkg:maven/org.apache.commons/commons-lang3@3.14.0"));
            assertTrue(json.readTree(get(server, "analyses/" + analysisId + "/sbom/status")).path("available").asBoolean());
            persisted = get(server, "analyses/" + analysisId);
            assertEquals(json.readTree(persisted), json.readTree(get(server, "analyses/" + analysisId + "/export")).path("analysis"));
        }
        try (var restarted = start()) {
            assertEquals(json.readTree(persisted), json.readTree(get(restarted, "analyses/" + analysisId)));
            var source = restarted.getBean(com.smartsca.application.port.outbound.ProjectSource.class);
            assertEquals(reference, source.validate(projectId, AnalysisConfiguration.defaults()).sourceReference());
            assertEquals(11, json.readTree(get(restarted, "projects")).path("projects").size());
        }
    }
}
