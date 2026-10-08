package com.smartsca;

import com.smartsca.adapter.outbound.maven.*;
import com.smartsca.domain.analysis.*;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.compress.archivers.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Portable ZIP boundary checks, immutable copies and real anonymous HTTP reference contracts. */
class ProjectImportTests {
    @TempDir Path temporary;
    static final String POM = "<project xmlns='http://maven.apache.org/POM/4.0.0'><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>imported</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>";
    static byte[] archive(Map<String, String> files) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new java.util.zip.ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            for (var file : files.entrySet()) {
                var entry = new java.util.zip.ZipEntry(file.getKey());
                zip.putNextEntry(entry); zip.write(file.getValue().getBytes(StandardCharsets.UTF_8)); zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private ImportedProjectSource source() { return new ImportedProjectSource(Path.of("../fixtures"), temporary.resolve("managed")); }
    @Test void importsPortableRootOrSingleFolderAndPreservesFingerprintAfterRestartAndSnapshot() throws Exception {
        var source = source();
        var project = source.importZip(new ByteArrayInputStream(archive(Map.of("sample/pom.xml", POM, "sample/src/App.java", "class App {}"))), "my-project.zip");
        assertTrue(project.id().matches("import-[a-f0-9]{32}"));
        assertTrue(project.sourceReference().matches("zip:my-project.zip;sha256:[a-f0-9]{64}"));
        assertTrue(project.analyzedReference().matches("fixture-sha256:[a-f0-9]{64}"));
        assertEquals(Set.of("."), project.modules());
        assertEquals(project, source().validate(project.id(), AnalysisConfiguration.defaults()));
        assertEquals(11, source.listProjects().size());
        Path copy = Files.createDirectory(temporary.resolve("snapshot"));
        source.snapshot(project, AnalysisConfiguration.defaults(), copy);
        assertEquals(POM, Files.readString(copy.resolve("pom.xml")));
        Files.writeString(temporary.resolve("managed").resolve(project.id()).resolve("pom.xml"), POM.replace("<version>1</version>", "<version>2</version>"));
        assertThrows(IllegalArgumentException.class, () -> source.snapshot(project, AnalysisConfiguration.defaults(), Files.createDirectory(temporary.resolve("changed"))));
        try (var files = Files.list(temporary.resolve("managed"))) { assertTrue(files.noneMatch(path -> path.getFileName().toString().startsWith(".pending-"))); }
    }
    @Test void rejectsTraversalSecretsMavenOptionsLinksBombsDuplicatesAndInvalidPomWithoutPublishing() throws Exception {
        var source = source();
        var invalid = List.of("../escape", "C:/escape", "a\\escape", "/escape", "CON", "a./file", "a?/file", ".env", ".git/config", ".gitmodules", "target/file", "node_modules/file", ".mvn/extensions.xml", ".mvn/jvm.config");
        for (var name : invalid) assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", POM, name, "x"))), "bad.zip"), name);
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("POM.xml", POM, "pom.xml", POM))), "duplicate.zip"));
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", "<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///secret'>]><project><artifactId>&x;</artifactId></project>"))), "xxe.zip"));
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", POM.replace("</project>", "<build><extensions><extension><artifactId>false</artifactId></extension></extensions></build></project>")))), "extension.zip"));
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", POM, "huge.txt", "a".repeat(25 * 1024 * 1024 + 1)))), "bomb.zip"));
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipArchiveOutputStream(bytes)) {
            zip.setUseZip64(Zip64Mode.Never);
            var link = new ZipArchiveEntry("pom.xml"); link.setUnixMode(0120777);
            zip.putArchiveEntry(link); zip.write("/secret".getBytes(StandardCharsets.UTF_8)); zip.closeArchiveEntry();
        }
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(bytes.toByteArray()), "link.zip"));
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(new byte[0]), "empty.zip"));
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream("text".getBytes()), "invalid.zip"));
        assertEquals(10, source.listProjects().size());
        assertFalse(Files.exists(temporary.resolve("escape")));
        try (var files = Files.list(temporary.resolve("managed"))) { assertEquals(0, files.count()); }
    }
    @Test void acceptsStaticReactorProfilesAndLocalParentsButRejectsNonPortableParentPaths() throws Exception {
        var source = source();
        String parent = "<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging><modules><module>app</module></modules><profiles><profile><id>development</id></profile></profiles></project>";
        String child = "<project><modelVersion>4.0.0</modelVersion><parent><groupId>demo</groupId><artifactId>parent</artifactId><version>1</version><relativePath>../pom.xml</relativePath></parent><artifactId>app</artifactId></project>";
        var project = source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", parent, "app/pom.xml", child))), "reactor.zip");
        assertEquals(Set.of(".", "app"), project.modules()); assertEquals(Set.of("development"), project.profiles());
        for (String path : List.of("..\\pom.xml", "C:/pom.xml", "../../pom.xml", "/pom.xml"))
            assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(Map.of("pom.xml", parent, "app/pom.xml", child.replace("../pom.xml", path)))), "invalid-parent.zip"));
        assertEquals(11, source.listProjects().size());
    }
    @Test void pinsPublicGitCommitToFixedEndpointsAndRejectsCredentialsRedirectsPrivateOrArbitraryHosts() throws Exception {
        var calls = new AtomicInteger(); String sha = "a".repeat(40);
        byte[] zip = archive(Map.of("repo-" + sha + "/pom.xml", POM));
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            server.createContext("/", exchange -> {
                calls.incrementAndGet();
                assertNull(exchange.getRequestHeaders().getFirst("Authorization"));
                String path = exchange.getRequestURI().getPath(); int status = 200;
                byte[] body = path.startsWith("/repos/") ? ("{\"sha\":\"" + sha + "\"}").getBytes(StandardCharsets.UTF_8) : zip;
                if (path.contains("private")) { status = 404; body = "{}".getBytes(); }
                if (path.contains("redirect")) { status = 302; exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + server.getAddress().getPort() + "/secret"); }
                exchange.sendResponseHeaders(status, body.length); exchange.getResponseBody().write(body); exchange.close();
            });
            server.start(); var endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
            var source = new ImportedProjectSource(Path.of("../fixtures"), temporary.resolve("managed"), endpoint, endpoint);
            var project = source.importGit("https://github.com/demo/repository.git");
            assertEquals("git+https://github.com/demo/repository@" + sha, project.sourceReference()); assertEquals(2, calls.get());
            for (String invalid : List.of("http://github.com/a/b", "https://127.0.0.1/a/b", "https://github.com.evil.test/a/b", "https://token@github.com/a/b", "https://github.com:443/a/b", "https://github.com/a/b/tree/main", "https://github.com/a/b?secret=x", "https://github.com/a/%2e%2e"))
                assertThrows(IllegalArgumentException.class, () -> source.importGit(invalid));
            assertEquals(2, calls.get(), "Invalid URLs must not initiate HTTP");
            assertThrows(IllegalArgumentException.class, () -> source.importGit("https://github.com/demo/private"));
            assertThrows(IllegalArgumentException.class, () -> source.importGit("https://github.com/demo/redirect"));
            assertEquals(4, calls.get(), "Redirect target must never be contacted");
            assertEquals(11, source.listProjects().size());
        } finally { server.stop(0); }
    }
    @Test void boundsEntriesCapacityAndConcurrentImportsWithoutDeletingOriginalProjects() throws Exception {
        var source = source();
        var entries = new LinkedHashMap<String, String>(); entries.put("pom.xml", POM);
        for (int i = 0; i < 2048; i++) entries.put("files/f" + i, "");
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(archive(entries)), "entries.zip"));
        byte[] bytes = archive(Map.of("pom.xml", POM));
        var entered = new java.util.concurrent.CountDownLatch(1); var released = new java.util.concurrent.CountDownLatch(1);
        var slow = new ByteArrayInputStream(bytes) {
            @Override public synchronized int read(byte[] buffer, int offset, int length) {
                entered.countDown();
                try { if (!released.await(5, java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("Test timeout"); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new IllegalStateException(error); }
                return super.read(buffer, offset, length);
            }
        };
        var running = java.util.concurrent.CompletableFuture.supplyAsync(() -> source.importZip(slow, "slow.zip"));
        try {
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
            assertThrows(com.smartsca.application.port.outbound.ProjectSource.ImportBusyException.class, () -> source.importZip(new ByteArrayInputStream(bytes), "busy.zip"));
        } finally { released.countDown(); }
        var original = running.get(5, java.util.concurrent.TimeUnit.SECONDS);
        for (int i = 1; i < 20; i++) source.importZip(new ByteArrayInputStream(bytes), "project.zip");
        assertThrows(IllegalArgumentException.class, () -> source.importZip(new ByteArrayInputStream(bytes), "full.zip"));
        assertEquals(original, source.validate(original.id(), AnalysisConfiguration.defaults()));
        assertEquals(30, source.listProjects().size());
    }
}
