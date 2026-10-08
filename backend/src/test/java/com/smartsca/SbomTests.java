package com.smartsca;

import com.smartsca.adapter.outbound.sbom.CycloneDxSbomExporter;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** Schema validation and contrast are separate: a schema-valid changed inventory must still fail. */
class SbomTests {
    private final CycloneDxSbomExporter exporter = new CycloneDxSbomExporter();
    private final JsonMapper json = JsonMapper.builder().build();
    private static final String ROOT = "pkg:maven/demo/app@1", PARENT = "pkg:maven/demo/parent@2", LIB = "pkg:maven/demo/lib@3?classifier=tests", TEST = "pkg:maven/demo/test@4";
    static Analysis request(Project project, AnalysisConfiguration config) {
        return new Analysis(UUID.randomUUID(), project, config, AnalysisStatus.EN_EJECUCION, "RESOLVIENDO_MAVEN", Instant.now(), Instant.now(), null,
            "test", List.of(), Map.of(), null, null, null, null);
    }
    private Analysis analysis() {
        return request(new Project("sample", "Sample", "catalog:sample", "fixture:test", Set.of("."), Set.of("extra")),
            new AnalysisConfiguration(Set.of("."), Set.of("extra"), Set.of("runtime"), "java-21", null));
    }
    private Component component(String purl, String name, String version) { return new Component(purl, "maven", "demo:" + name, version, Map.of()); }
    private DependencyGraph graph() {
        return new DependencyGraph(Map.of(".", ROOT), Map.of(ROOT, component(ROOT, "app", "1"), PARENT, component(PARENT, "parent", "2"),
            LIB, component(LIB, "lib", "3"), TEST, component(TEST, "test", "4")), Set.of(
                new DependencyEdge(ROOT, PARENT, new DependencyContext(".", "compile", "compile")),
                new DependencyEdge(PARENT, LIB, new DependencyContext(".", "runtime", "runtime")),
                new DependencyEdge(ROOT, LIB, new DependencyContext(".", "runtime", "runtime")),
                new DependencyEdge(ROOT, TEST, new DependencyContext(".", "test", "test"))));
    }
    @Test void preservesSelectedInventoryQualifiersAlternateParentsAndLabelledConnectors() {
        var analysis = analysis(); var graph = graph();
        var artifact = exporter.generateAndValidate(analysis, graph);
        var document = json.readTree(artifact.content());
        assertEquals("1.6", document.path("specVersion").asString());
        assertEquals("urn:uuid:" + analysis.id(), document.path("serialNumber").asString());
        assertEquals(3, document.path("components").size());
        assertFalse(artifact.content().contains(TEST));
        assertTrue(artifact.content().contains(LIB));
        assertTrue(artifact.content().contains("connector"));
        assertEquals(3, document.path("dependencies").size());
        assertEquals(artifact.sha256(), AnalysisArtifact.digest(artifact.content()));
        var contexts = json.readTree(document.path("properties").get(0).path("value").asString());
        assertEquals(3, contexts.size());
        assertTrue(artifact.content().contains("extra"));
        assertDoesNotThrow(() -> exporter.validate(analysis, graph, artifact.content()));
    }
    @Test void rejectsInvalidSchemaAndSchemaValidChangesToInventoryOrSelection() {
        var analysis = analysis(); var graph = graph();
        String content = exporter.generateAndValidate(analysis, graph).content();
        for (String invalid : List.of("", "{}", "not json", content.replace("\"version\":\"3\"", "\"version\":\"999\""),
                content.replace("runtime", "test"), content.replace("classifier=tests", "classifier=other"),
                content.replace(analysis.id().toString(), UUID.randomUUID().toString()), content.replace("\"type\":\"library\"", "\"type\":\"invalid\"")))
            assertThrows(IllegalArgumentException.class, () -> exporter.validate(analysis, graph, invalid));
        assertThrows(IllegalArgumentException.class, () -> new AnalysisArtifact("1.6", Instant.now(), "0".repeat(64), content));
        assertThrows(IllegalArgumentException.class, () -> new AnalysisArtifact("1.6", Instant.now(), AnalysisArtifact.digest(""), ""));
    }
    @Test void aProjectWithoutSelectedDependenciesStillHasAValidModuleRootButMissingResolutionCannotExport() {
        var analysis = analysis();
        var graph = new DependencyGraph(Map.of(".", ROOT), Map.of(ROOT, component(ROOT, "app", "1")), Set.of());
        var artifact = exporter.generateAndValidate(analysis, graph);
        assertEquals(1, json.readTree(artifact.content()).path("components").size());
        assertDoesNotThrow(() -> exporter.validate(analysis, graph, artifact.content()));
        assertThrows(IllegalArgumentException.class, () -> exporter.generateAndValidate(analysis, null));
        assertThrows(IllegalArgumentException.class, () -> exporter.generateAndValidate(analysis, new DependencyGraph(Map.of(), Map.of(), Set.of())));
    }
    @Test void preservesMultipleModuleContextsAndRejectsModulesOutsideTheRecordedSelection() {
        var analysis = request(new Project("sample", "Sample", "catalog:sample", "fixture:test", Set.of("app", "lib"), Set.of()),
            AnalysisConfiguration.defaults());
        var graph = new DependencyGraph(Map.of("app", ROOT, "lib", PARENT), Map.of(ROOT, component(ROOT, "app", "1"), PARENT, component(PARENT, "parent", "2"), LIB, component(LIB, "lib", "3")),
            Set.of(new DependencyEdge(ROOT, LIB, new DependencyContext("app", "compile", "compile")), new DependencyEdge(PARENT, LIB, new DependencyContext("lib", "compile", "compile"))));
        var document = exporter.generateAndValidate(analysis, graph).content();
        assertTrue(document.contains("app")); assertTrue(document.contains("lib"));
        var contexts = json.readTree(json.readTree(document).path("properties").get(0).path("value").asString());
        assertEquals(2, contexts.size());
        var subset = request(analysis.project(), new AnalysisConfiguration(Set.of("app"), Set.of(), Set.of("compile"), "java-21", null));
        assertThrows(IllegalArgumentException.class, () -> exporter.generateAndValidate(subset, graph));
    }
}
