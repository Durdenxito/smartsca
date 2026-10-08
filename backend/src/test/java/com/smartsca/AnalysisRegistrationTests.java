package com.smartsca;

import com.smartsca.adapter.outbound.maven.FixtureProjectSource;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.application.service.*;
import com.smartsca.domain.analysis.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class AnalysisRegistrationTests {
    @TempDir Path root;

    @Test void validatesCatalogAndConfigurationBeforeSavingAnImmutableQueuedRequest() throws Exception {
        Path folder = Files.createDirectory(root.resolve("sample"));
        Path pom = folder.resolve("pom.xml");
        Files.writeString(pom, "<project xmlns='http://maven.apache.org/POM/4.0.0'><artifactId>sample</artifactId><name>Sample</name></project>");
        var source = new FixtureProjectSource(root);
        var saved = new HashMap<UUID, Analysis>();
        var repository = new AnalysisRepository() {
            public void save(Analysis value) { saved.put(value.id(), value); }
            public Optional<Analysis> get(UUID id) { return Optional.ofNullable(saved.get(id)); }
            public com.smartsca.application.port.inbound.ListAnalysesUseCase.Page list(String project, AnalysisStatus status, int offset) { throw new UnsupportedOperationException(); }
            public Optional<Analysis> claimNextPending() { return Optional.empty(); }
            public void updateStep(UUID id, String step) { }
            public void finish(Analysis value, AnalysisArtifact sbom) { saved.put(value.id(), value); }
            public Optional<AnalysisArtifact> readSbom(UUID id) { return Optional.empty(); }
            public void failInterrupted() { }
        };
        var start = new StartAnalysisService(source, repository, "test");
        var query = new QueryAnalysisService(repository);
        assertThrows(IllegalArgumentException.class, () -> query.list("../sample", null, 0));
        assertThrows(IllegalArgumentException.class, () -> query.list("x".repeat(65), null, 0));
        assertThrows(IllegalArgumentException.class, () -> query.list(null, null, -1));
        assertThrows(IllegalArgumentException.class, () -> query.list(null, null, 10001));
        var defaults = AnalysisConfiguration.defaults();
        assertEquals("Sample", start.listProjects().getFirst().name());
        assertThrows(IllegalArgumentException.class, () -> start.start("../sample", defaults));
        assertThrows(IllegalArgumentException.class, () -> start.start("absent", defaults));
        assertThrows(IllegalArgumentException.class, () -> start.start("sample",
            new AnalysisConfiguration(Set.of("other"), Set.of(), defaults.scopes(), "java-21", null)));
        assertThrows(IllegalArgumentException.class, () -> new AnalysisConfiguration(Set.of("."), Set.of(), Set.of(), "java-21", null));
        assertThrows(IllegalArgumentException.class, () -> new AnalysisConfiguration(Set.of("."), Set.of(), Set.of("system"), "java-21", null));
        assertThrows(IllegalArgumentException.class, () -> new AnalysisConfiguration(Set.of("."), Set.of(), defaults.scopes(), "java-21", "x".repeat(501)));
        assertTrue(saved.isEmpty());
        UUID id = start.start("sample", null);
        Analysis analysis = query.get(id);
        assertEquals(AnalysisStatus.EN_COLA, analysis.status());
        assertEquals(defaults, analysis.configuration());
        assertEquals("REGISTRADO", analysis.currentStep());
        assertNull(analysis.startedAt());
        assertNull(analysis.finishedAt());
        assertTrue(analysis.diagnostics().isEmpty());
        assertTrue(analysis.project().analyzedReference().matches("fixture-sha256:[a-f0-9]{64}"));
        assertThrows(UnsupportedOperationException.class, () -> analysis.configuration().scopes().add("test"));
        assertNotEquals(id, start.start("sample", defaults));
        assertThrows(NoSuchElementException.class, () -> query.get(UUID.randomUUID()));
        Files.writeString(folder.resolve("Source.java"), "class Source {}\n");
        assertNotEquals(analysis.project().analyzedReference(), source.validate("sample", defaults).analyzedReference());
        assertThrows(IllegalArgumentException.class, () -> source.snapshot(analysis.project(), defaults, root.resolve("snapshot")));
        Files.writeString(pom, "<!DOCTYPE project [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><project><artifactId>&secret;</artifactId></project>");
        assertThrows(IllegalArgumentException.class, () -> start.start("sample", defaults));
        assertEquals(2, saved.size());
        assertEquals("Sample", query.get(id).project().name());
        Files.writeString(pom, "x".repeat(1_048_577));
        assertThrows(IllegalArgumentException.class, () -> source.validate("sample", defaults));
    }
}
