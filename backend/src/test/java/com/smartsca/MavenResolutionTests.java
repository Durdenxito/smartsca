package com.smartsca;

import com.smartsca.adapter.outbound.maven.*;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import static org.junit.jupiter.api.Assertions.*;

/** Ten real Maven fixtures, including mediation, classifier, scope, profile and multiple modules/parents. */
@EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_DOCKER", matches = "true")
class MavenResolutionTests {
    @Test void resolvesAllFixturesAndPreservesContextAndMediatedVersions() throws Exception {
        var source = new FixtureProjectSource(Path.of("../fixtures"));
        var resolver = new MavenDependencyResolver(source, Duration.ofSeconds(180));
        var graphs = new HashMap<String, DependencyGraph>();
        assertEquals(10, source.listProjects().size());
        for (var project : source.listProjects()) {
            var config = new AnalysisConfiguration(Set.of("."), project.profiles(), AnalysisConfiguration.SUPPORTED_SCOPES, "java-21", null);
            var graph = resolver.resolve(project, config);
            graphs.put(project.id(), graph);
            assertReference(project.id(), graph);
            var sbom = new com.smartsca.adapter.outbound.sbom.CycloneDxSbomExporter().generateAndValidate(SbomTests.request(project, config), graph);
            assertEquals("1.6", sbom.schemaVersion());
            assertFalse(sbom.content().isBlank());
            assertEquals(project.modules(), graph.rootsByModule().keySet());
            assertTrue(graph.components().values().stream().allMatch(component -> component.purl().startsWith("pkg:maven/") && !component.version().isBlank()));
        }
        assertEquals(Set.of(), names(graphs.get("maven-basic")));
        assertEquals(Set.of("org.apache.commons:commons-lang3"), names(graphs.get("maven-direct")));
        assertEquals(Set.of("com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-core",
            "com.fasterxml.jackson.core:jackson-annotations", "net.bytebuddy:byte-buddy"), names(graphs.get("maven-transitive")));
        assertEquals(Set.of("org.apache.commons:commons-lang3", "commons-codec:commons-codec", "org.slf4j:slf4j-api", "junit:junit", "org.hamcrest:hamcrest-core"), names(graphs.get("maven-scopes")));
        assertEquals(Set.of("org.apache.commons:commons-lang3", "org.apache.commons:commons-text", "org.apache.commons:commons-configuration2", "commons-logging:commons-logging"), names(graphs.get("maven-diamond")));
        assertEquals(Set.of("org.apache.commons:commons-lang3", "commons-codec:commons-codec"), names(graphs.get("maven-profiles")));
        assertEquals(Set.of("org.apache.commons:commons-lang3", "org.apache.commons:commons-text"), names(graphs.get("maven-managed")));
        assertFalse(names(graphs.get("maven-exclusions")).contains("com.fasterxml.jackson.core:jackson-core"));
        var classifier = graphs.get("maven-classifier");
        assertEquals(2, classifier.components().values().stream().filter(component -> component.name().equals("org.slf4j:slf4j-api")).count());
        assertTrue(classifier.components().keySet().stream().anyMatch(purl -> purl.endsWith("?classifier=sources")));
        var diamond = graphs.get("maven-diamond");
        var lang = purl(diamond, "org.apache.commons:commons-lang3");
        assertTrue(diamond.edges().stream().filter(edge -> edge.childPurl().equals(lang)).map(DependencyEdge::parentPurl).distinct().count() >= 2);
        assertTrue(diamond.components().values().stream().filter(component -> component.name().equals("org.apache.commons:commons-text")).allMatch(component -> component.version().equals("1.12.0")));
        var multi = graphs.get("maven-multimodule");
        assertEquals(Set.of("com.smartsca.fixtures:lib", "org.apache.commons:commons-lang3", "org.apache.commons:commons-text"), names(multi));
        var occurrences = multi.contextsOf(purl(multi, "org.apache.commons:commons-lang3"));
        assertTrue(occurrences.stream().anyMatch(context -> context.module().equals("lib") && context.direct()));
        assertTrue(occurrences.stream().anyMatch(context -> context.module().equals("app") && !context.direct()));
        var testScope = graphs.get("maven-scopes");
        assertTrue(testScope.contextsOf(purl(testScope, "org.hamcrest:hamcrest-core")).stream().allMatch(context -> context.scope().equals("test") && !context.direct()));
        var noProfile = resolver.resolve(source.validate("maven-profiles", AnalysisConfiguration.defaults()), AnalysisConfiguration.defaults());
        assertFalse(names(noProfile).contains("commons-codec:commons-codec"));
        var appOnly = new AnalysisConfiguration(Set.of("app"), Set.of(), AnalysisConfiguration.SUPPORTED_SCOPES, "java-21", null);
        assertEquals(Set.of("app"), resolver.resolve(source.validate("maven-multimodule", appOnly), appOnly).rootsByModule().keySet());
        var shortResolver = new MavenDependencyResolver(source, Duration.ofMillis(100));
        assertThrows(IllegalArgumentException.class, () -> shortResolver.resolve(source.validate("maven-direct", AnalysisConfiguration.defaults()), AnalysisConfiguration.defaults()));
    }
    private static void assertReference(String fixture, DependencyGraph graph) throws Exception {
        var roots = new TreeMap<String, String>();
        var components = new HashSet<String>();
        var edges = new HashSet<DependencyEdge>();
        for (String row : java.nio.file.Files.readAllLines(Path.of("src/test/resources/maven-references.tsv"))) {
            if (row.startsWith("#")) continue;
            String[] fields = row.split("\t");
            if (!fields[0].equals(fixture)) continue;
            components.add(fields[3]);
            if (fields[2].equals("-")) roots.put(fields[1], fields[3]);
            else {
                components.add(fields[4]);
                edges.add(new DependencyEdge(fields[3], fields[4], new DependencyContext(fields[1], fields[2], fields[2])));
            }
        }
        assertEquals(roots, graph.rootsByModule(), fixture + " roots");
        assertEquals(components, graph.components().keySet(), fixture + " identities/versions");
        assertEquals(edges, graph.edges(), fixture + " relationships/contexts");
    }
    private static Set<String> names(DependencyGraph graph) {
        var result = new HashSet<String>();
        for (var component : graph.components().values()) if (!graph.contextsOf(component.purl()).isEmpty()) result.add(component.name());
        return result;
    }
    private static String purl(DependencyGraph graph, String name) {
        return graph.components().values().stream().filter(component -> component.name().equals(name)).findFirst().orElseThrow().purl();
    }
}
