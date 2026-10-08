package com.smartsca;

import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.*;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.*;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.vulnerability.VulnerabilitySnapshot;
import java.net.URI;
import java.net.http.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Real PostgreSQL/HTTP: verify projected SQL, payload size and unchanged snapshot semantics. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DB_URL", matches = ".+")
class AnalysisReadProjectionTests {
    public static class Queries implements StatementInspector {
        static final List<String> statements = new CopyOnWriteArrayList<>();
        public String inspect(String sql) { statements.add(sql); return sql; }
    }
    private final JsonMapper json = JsonMapper.builder().build();
    private HttpResponse<String> get(ConfigurableApplicationContext server, UUID id, String suffix) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
            server.getEnvironment().getProperty("local.server.port") + "/api/analyses/" + id + suffix)).build(), HttpResponse.BodyHandlers.ofString());
    }
    private String columns() {
        var statements = Queries.statements.stream().map(String::toLowerCase).filter(sql -> sql.contains(" from analyses ")).toList();
        assertEquals(1, statements.size(), statements.toString());
        var sql = statements.getFirst();
        return sql.substring(0, sql.indexOf(" from analyses "))
            .replaceAll("\\w+\\.(dependency_graph|vulnerability_snapshot)\\s+is\\s+not\\s+null", "presence");
    }
    @Test void readsOnlyNeededColumnsAndPreservesScopesEvidenceMissingDataAndFullExport() throws Exception {
        try (var server = SpringApplication.run(SmartScaApplication.class, "--server.port=0", "--smartsca.worker.enabled=false",
            "--smartsca.enrichment.enabled=false", "--logging.level.root=WARN", "--spring.main.banner-mode=off",
            "--spring.datasource.url=" + System.getenv("SMARTSCA_TEST_DB_URL"),
            "--spring.datasource.username=" + System.getenv("SMARTSCA_DB_USER"), "--spring.datasource.password=" + System.getenv("SMARTSCA_DB_PASSWORD"),
            "--spring.jpa.properties.hibernate.session_factory.statement_inspector=" + Queries.class.getName())) {
            var repository = server.getBean(AnalysisRepository.class);
            var id = UUID.randomUUID();
            var now = Instant.now();
            String root = "pkg:maven/demo/root@1", compile = "pkg:maven/demo/compile@1", runtime = "pkg:maven/demo/runtime@1";
            var components = new HashMap<String, Component>();
            for (String purl : List.of(root, compile, runtime)) components.put(purl, new Component(purl, "maven", purl, "1", Map.of()));
            var graph = new DependencyGraph(Map.of(".", root), components, Set.of(
                new DependencyEdge(root, compile, new DependencyContext(".", "compile", "compile")),
                new DependencyEdge(root, runtime, new DependencyContext(".", "runtime", "runtime"))));
            var absent = HealthAssessment.unavailable(runtime, "https://example.org/report", EvidenceStatus.NO_DISPONIBLE, "Informe no publicado.");
            var health = new HealthAssessment(runtime, absent.repository(), absent.scorecard(), absent.indicators(),
                List.of(Evidence.available("https://example.org/pom", now, null, "x".repeat(65536))));
            var vulnerabilities = new VulnerabilitySnapshot(List.of(), List.of(), Map.of(runtime, Evidence.available("https://example.org/osv", now, null, List.of())));
            var config = new AnalysisConfiguration(Set.of("."), Set.of(), Set.of("runtime"), "java-21", "Laboratorio");
            var analysis = new Analysis(id, new Project("read-fixture", "Lecturas selectivas", "catalog:read-fixture", "fixture:test", Set.of("."), Set.of()),
                config, AnalysisStatus.PARCIAL, "TEST", now, now, now, "test", List.of("Diagnóstico guardado"), Map.of("maven", "test"),
                graph, vulnerabilities, Map.of(runtime, health), null);
            repository.save(analysis);
            var full = get(server, id, "");
            assertEquals(200, full.statusCode());

            Queries.statements.clear();
            var statusResponse = get(server, id, "/status");
            assertEquals(200, statusResponse.statusCode(), statusResponse.body());
            var status = json.readTree(statusResponse.body());
            assertEquals("Lecturas selectivas", status.path("projectName").asString());
            assertEquals("runtime", status.path("configuration").path("scopes").get(0).asString());
            assertTrue(status.path("graphAvailable").asBoolean());
            assertTrue(status.path("vulnerabilitiesAvailable").asBoolean());
            assertFalse(status.has("dependencyGraph"));
            assertFalse(status.has("healthAssessments"));
            assertTrue(statusResponse.body().length() < full.body().length() / 10);
            String selected = columns();
            for (String column : List.of("dependency_graph", "vulnerability_snapshot", "health_assessments", "risk_snapshot")) assertFalse(selected.contains(column), selected);

            Queries.statements.clear();
            var resolution = get(server, id, "/resolution");
            assertEquals(200, resolution.statusCode(), resolution.body());
            assertEquals(json.readTree(full.body()).path("dependencyGraph"), json.readTree(resolution.body()).path("dependencyGraph"));
            selected = columns();
            assertTrue(selected.contains("dependency_graph"));
            for (String column : List.of("vulnerability_snapshot", "health_assessments", "risk_snapshot")) assertFalse(selected.contains(column), selected);

            Queries.statements.clear();
            var inventory = get(server, id, "/inventory");
            assertEquals(200, inventory.statusCode(), inventory.body());
            var view = json.readTree(inventory.body());
            assertEquals(1, view.path("items").size());
            assertEquals(runtime, view.path("items").get(0).path("component").path("purl").asString());
            assertEquals("NO_DISPONIBLE", view.path("healthAssessments").path(runtime).path("scorecard").path("status").asString());
            assertTrue(view.path("vulnerabilitiesAvailable").asBoolean());
            selected = columns();
            assertTrue(selected.contains("health_assessments"));
            assertFalse(selected.contains("risk_snapshot"));
            assertFalse(selected.contains("vulnerability_snapshot"));

            Queries.statements.clear();
            var sources = get(server, id, "/sources");
            assertEquals(200, sources.statusCode(), sources.body());
            assertEquals(json.readTree(full.body()).path("vulnerabilitySnapshot"), json.readTree(sources.body()).path("vulnerabilitySnapshot"));
            assertEquals(json.readTree(full.body()).path("healthAssessments"), json.readTree(sources.body()).path("healthAssessments"));
            selected = columns();
            assertFalse(selected.contains("dependency_graph"));
            assertFalse(selected.contains("risk_snapshot"));

            for (String suffix : List.of("/components", "/graph?module=.", "/routes?purl=" + runtime)) {
                Queries.statements.clear();
                assertEquals(200, get(server, id, suffix).statusCode());
                selected = columns();
                for (String column : List.of("health_assessments", "vulnerability_snapshot", "risk_snapshot")) assertFalse(selected.contains(column), selected);
            }
            assertEquals(json.readTree(full.body()), json.readTree(get(server, id, "/export").body()).path("analysis"));
            assertEquals(json.readTree(full.body()), json.readTree(get(server, id, "").body()));

            UUID legacy = UUID.randomUUID();
            repository.save(new Analysis(legacy, analysis.project(), config, AnalysisStatus.EN_COLA, "REGISTRADO", now, null, null, "test", List.of(), Map.of(), null, null, null, null));
            assertFalse(json.readTree(get(server, legacy, "/status").body()).path("graphAvailable").asBoolean());
            assertTrue(json.readTree(get(server, legacy, "/sources").body()).path("vulnerabilitySnapshot").isNull());
            assertTrue(json.readTree(get(server, legacy, "/resolution").body()).path("dependencyGraph").isNull());
            assertEquals(400, get(server, legacy, "/inventory").statusCode());
            for (String suffix : List.of("/status", "/sources", "/resolution", "/inventory")) assertEquals(404, get(server, UUID.randomUUID(), suffix).statusCode());
        }
    }
}
