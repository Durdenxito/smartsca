package com.smartsca;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.adapter.outbound.scorecard.ScorecardHealthAdapter;
import com.smartsca.domain.*;
import com.smartsca.domain.component.Component;
import com.smartsca.domain.health.HealthAssessment;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

/** HTTP reference contracts cover identity binding, provenance, degradation and immutable snapshots. */
class HealthEnrichmentTests {
    static final Component A = new Component("pkg:maven/demo/library@1", "maven", "demo:library", "1", Map.of());
    static final class Providers implements AutoCloseable {
        final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        final JsonMapper json = JsonMapper.builder().build();
        final AtomicInteger calls = new AtomicInteger();
        boolean ambiguous, conflicting, missingScm, maliciousPom, badIdentity, badReport, missingReport, degraded, duplicate, failProject;
        String pomEncoding = "UTF-8";
        boolean nulPom;
        byte[] lastPom;
        Providers() throws Exception {
            server.createContext("/", exchange -> {
                calls.incrementAndGet();
                String path = exchange.getRequestURI().getPath(), body; int status = 200;
                if (path.startsWith("/systems/maven/")) {
                    String name = path.substring(path.indexOf("/packages/") + 10, path.indexOf("/versions/"));
                    String version = path.substring(path.indexOf("/versions/") + 10);
                    var related = new ArrayList<Object>();
                    related.add(Map.of("projectKey", Map.of("id", "github.com/demo/library"), "relationType", "SOURCE_REPO", "relationProvenance", "UNVERIFIED_METADATA"));
                    related.add(Map.of("projectKey", Map.of("id", "github.com/other/tracker"), "relationType", "ISSUE_TRACKER"));
                    if (ambiguous) related.add(Map.of("projectKey", Map.of("id", "github.com/other/source"), "relationType", "SOURCE_REPO"));
                    body = json.writeValueAsString(Map.of("versionKey", Map.of("system", "MAVEN", "name", badIdentity ? "demo:other" : name, "version", version), "relatedProjects", related));
                } else if (path.endsWith(".pom")) {
                    String[] pieces = path.substring(1).split("/");
                    String version = pieces[pieces.length - 2], artifact = pieces[pieces.length - 3];
                    String group = String.join(".", Arrays.copyOf(pieces, pieces.length - 3));
                    body = "<?xml version='1.0' encoding='" + pomEncoding + "'?><project xmlns='http://maven.apache.org/POM/4.0.0'><modelVersion>4.0.0</modelVersion><name>Résumé</name><groupId>" + group + "</groupId><artifactId>" + artifact + "</artifactId><version>" + version + "</version>" +
                        (missingScm ? "" : "<scm><url>https://github.com/demo/library</url><connection>scm:git:git://github.com/" + (conflicting ? "other/source" : "demo/library") + ".git</connection></scm>") + "</project>";
                    if (maliciousPom) body = body.replace("?><project", "?><!DOCTYPE project [<!ENTITY x SYSTEM 'http://127.0.0.1:" + server.getAddress().getPort() + "/secret'>]><project")
                        .replace("demo/library</url>", "demo/library&x;</url>");
                    if (nulPom) body = body.replace("Résumé", "Résumé\0");
                } else if (path.startsWith("/projects/")) {
                    var checks = new ArrayList<Map<String, Object>>();
                    for (String name : HealthAssessment.CHECKS) {
                        if (degraded && name.equals("Dependency-Update-Tool")) continue;
                        checks.add(Map.of("name", name, "score", degraded && name.equals("Security-Policy") ? -1 : name.equals("Maintained") ? 0 : 10,
                            "reason", "Resultado publicado", "details", List.of("Detalle conservado"), "documentation", Map.of("url", "javascript:alert(1)")));
                    }
                    if (duplicate) checks.add(checks.getFirst());
                    var project = new HashMap<String, Object>();
                    project.put("projectKey", Map.of("id", "github.com/demo/library"));
                    if (!missingReport) project.put("scorecard", Map.of("date", "2026-01-01T00:00:00Z",
                        "repository", Map.of("name", badReport ? "github.com/other/source" : "github.com/demo/library", "commit", "abc123"),
                        "scorecard", Map.of("version", "v5", "commit", "tool123"), "checks", checks));
                    body = json.writeValueAsString(project);
                    if (failProject) status = 503;
                } else { body = "{}"; status = 404; }
                byte[] bytes = body.getBytes(path.endsWith(".pom") ? java.nio.charset.Charset.forName(pomEncoding) : StandardCharsets.UTF_8);
                if (path.endsWith(".pom")) lastPom = bytes.clone();
                exchange.sendResponseHeaders(status, bytes.length); exchange.getResponseBody().write(bytes); exchange.close();
            });
            server.start();
        }
        ScorecardHealthAdapter adapter() {
            var endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
            return new ScorecardHealthAdapter(new ExternalJsonClient(true), endpoint, endpoint);
        }
        @Override public void close() { server.stop(0); }
    }
    @Test void bindsExactVersionScmAndPublishedRepositoryAndPreservesCacheDatesAndImmutableEvidence() throws Exception {
        try (var reference = new Providers()) {
            var adapter = reference.adapter();
            var first = adapter.assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.DISPONIBLE, first.repository().status());
            assertEquals("github.com/demo/library", first.repository().value().id());
            assertTrue(first.scorecard().value().stale());
            assertEquals("scorecard-age-v1-90d", first.scorecard().value().freshnessPolicy());
            assertEquals(4, first.indicators().size());
            assertEquals(0, first.indicators().get("Maintained").value().score()); // Published zero is available.
            assertEquals(3, first.associationEvidence().size());
            assertTrue(first.associationEvidence().getFirst().value().contains("UNVERIFIED_METADATA"));
            assertThrows(UnsupportedOperationException.class, () -> first.indicators().clear());
            assertThrows(UnsupportedOperationException.class, () -> first.associationEvidence().clear());
            var again = adapter.assess(List.of(A)).get(A.purl());
            assertEquals(3, reference.calls.get());
            assertEquals(first, again);
            var restored = reference.json.readValue(reference.json.writeValueAsString(first), HealthAssessment.class);
            assertEquals(first, restored);
            assertThrows(UnsupportedOperationException.class, () -> restored.indicators().clear());
        }
    }
    @Test void rejectsAmbiguousContradictoryMissingScmIdentityAndXmlExternalResourcesWithoutAssigningHealth() throws Exception {
        try (var reference = new Providers()) {
            reference.ambiguous = true;
            assertEquals(EvidenceStatus.NO_DISPONIBLE, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
            assertEquals(1, reference.calls.get()); // Do not fetch a guessed repository.
            reference.ambiguous = false; reference.conflicting = true;
            assertEquals(EvidenceStatus.NO_DISPONIBLE, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
            reference.conflicting = false; reference.missingScm = true;
            assertEquals(EvidenceStatus.NO_DISPONIBLE, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
            reference.missingScm = false; reference.maliciousPom = true;
            int beforeXml = reference.calls.get();
            assertEquals(EvidenceStatus.ERROR, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
            assertEquals(beforeXml + 2, reference.calls.get()); // Metadata + POM only; no external-entity request.
            reference.maliciousPom = false; reference.badIdentity = true;
            assertEquals(EvidenceStatus.ERROR, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
            var invalid = new Component("pkg:maven/demo/bad@1", "maven", "../escape:bad", "1", Map.of());
            int before = reference.calls.get();
            assertEquals(EvidenceStatus.NO_DISPONIBLE, reference.adapter().assess(List.of(invalid)).get(invalid.purl()).repository().status());
            assertEquals(before, reference.calls.get());
        }
    }
    @Test void retainsAssociationWhileDistinguishingMissingFailedDuplicateAndWrongRepositoryChecks() throws Exception {
        try (var reference = new Providers()) {
            reference.degraded = true;
            var result = reference.adapter().assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.DISPONIBLE, result.repository().status());
            assertEquals(EvidenceStatus.NO_DISPONIBLE, result.indicators().get("Security-Policy").status());
            assertNull(result.indicators().get("Security-Policy").value());
            assertEquals(EvidenceStatus.NO_DISPONIBLE, result.indicators().get("Dependency-Update-Tool").status());
            reference.degraded = false; reference.duplicate = true;
            result = reference.adapter().assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.ERROR, result.indicators().get("Maintained").status());
            assertEquals(EvidenceStatus.DISPONIBLE, result.indicators().get("Code-Review").status());
            reference.duplicate = false; reference.badReport = true;
            result = reference.adapter().assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.DISPONIBLE, result.repository().status());
            assertEquals(EvidenceStatus.ERROR, result.scorecard().status());
            reference.badReport = false; reference.missingReport = true;
            result = reference.adapter().assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.NO_DISPONIBLE, result.scorecard().status());
            assertEquals(3, result.associationEvidence().size());
            reference.missingReport = false; reference.failProject = true;
            assertEquals(EvidenceStatus.ERROR, reference.adapter().assess(List.of(A)).get(A.purl()).repository().status());
        }
    }
    @Test void disabledSourcesAndComponentLimitProduceStatesInsteadOfFabricatedZeroScores() {
        var components = java.util.stream.IntStream.range(0, 1002).mapToObj(i -> new Component(A.purl() + i, "maven", A.name(), A.version(), Map.of())).toList();
        var result = new ScorecardHealthAdapter(new ExternalJsonClient(false)).assess(components);
        assertEquals(1002, result.size());
        assertTrue(result.values().stream().allMatch(value -> value.indicators().values().stream().allMatch(check -> check.status() == EvidenceStatus.ERROR && check.value() == null)));
        assertTrue(result.get(components.getLast().purl()).repository().diagnostic().contains("limitada"));
        var selected = VulnerabilityEnrichmentTests.graph().componentsInScopes(Set.of("compile"));
        assertEquals(2, selected.size());
        assertTrue(VulnerabilityEnrichmentTests.graph().componentsInScopes(Set.of("test")).isEmpty());
    }
    @Test void preservesLatin1Utf16AndInvalidXmlBytesWithoutJsonbNulCharacters() throws Exception {
        try (var reference = new Providers()) {
            for (String encoding : List.of("ISO-8859-1", "UTF-16")) {
                reference.pomEncoding = encoding;
                var result = reference.adapter().assess(List.of(A)).get(A.purl());
                assertEquals(EvidenceStatus.DISPONIBLE, result.repository().status(), result.repository().diagnostic());
                String pom = result.associationEvidence().get(1).value();
                assertTrue(pom.contains("Résumé"));
                assertFalse(pom.contains("\0"));
                assertArrayEquals(reference.lastPom, pom.getBytes(java.nio.charset.Charset.forName(encoding)));
                assertEquals(result, reference.json.readValue(reference.json.writeValueAsString(result), HealthAssessment.class));
            }
            reference.nulPom = true;
            var result = reference.adapter().assess(List.of(A)).get(A.purl());
            assertEquals(EvidenceStatus.ERROR, result.repository().status());
            String backup = result.associationEvidence().get(1).value();
            assertTrue(backup.startsWith("BASE64:"));
            assertFalse(backup.contains("\0"));
            assertArrayEquals(reference.lastPom, Base64.getDecoder().decode(backup.substring(7)));
        }
    }
    @Test @EnabledIfEnvironmentVariable(named = "SMARTSCA_TEST_EXTERNAL", matches = "true")
    void readsPublishedJUnitRepositoryAndScorecardFromRealPublicSources() {
        var component = new Component("pkg:maven/junit/junit@4.13.2", "maven", "junit:junit", "4.13.2", Map.of());
        var result = new ScorecardHealthAdapter(new ExternalJsonClient(true)).assess(List.of(component)).get(component.purl());
        assertEquals(EvidenceStatus.DISPONIBLE, result.repository().status(), result.repository().diagnostic());
        assertEquals("github.com/junit-team/junit4", result.repository().value().id());
        assertEquals(EvidenceStatus.DISPONIBLE, result.scorecard().status(), result.scorecard().diagnostic());
        assertEquals(4, result.indicators().size());
        assertTrue(result.indicators().values().stream().anyMatch(check -> check.status() == EvidenceStatus.DISPONIBLE));
        assertTrue(result.associationEvidence().stream().allMatch(value -> value.source().startsWith("https://")));
    }
}
