package com.smartsca.adapter.outbound.maven;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.application.port.outbound.ProjectSource;
import com.smartsca.domain.analysis.*;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Semaphore;
import org.apache.commons.compress.archivers.zip.ZipFile;
import tools.jackson.databind.json.JsonMapper;

/** Immutable managed imports reuse the existing bounded Maven catalog and snapshot checks. */
public final class ImportedProjectSource implements ProjectSource {
    private static final long MAX_ARCHIVE = 10 * 1024 * 1024, MAX_CONTENT = 25 * 1024 * 1024;
    private static final int MAX_ENTRIES = 2048, MAX_PROJECTS = 20;
    private final FixtureProjectSource fixtures, imports;
    private final Path root;
    private final URI api, archives;
    private final Semaphore importing = new Semaphore(1);
    private final JsonMapper json = JsonMapper.builder().build();
    public ImportedProjectSource(Path fixtures, Path imports) {
        this(fixtures, imports, URI.create("https://api.github.com/"), URI.create("https://codeload.github.com/"));
    }
    /** Alternate endpoints are supplied only by deterministic HTTP contract tests. */
    public ImportedProjectSource(Path fixtures, Path imports, URI api, URI archives) {
        this.fixtures = new FixtureProjectSource(fixtures);
        root = imports.toAbsolutePath().normalize();
        Path fixtureRoot = fixtures.toAbsolutePath().normalize();
        if (root.startsWith(fixtureRoot) || fixtureRoot.startsWith(root)) throw new IllegalArgumentException("Almacenamiento de importaciones separado del catálogo inicial.");
        this.imports = new FixtureProjectSource(root);
        this.api = api; this.archives = archives;
        try { Files.createDirectories(root); if (Files.isSymbolicLink(root)) throw new ImportStorageException(); }
        catch (IOException error) { throw new ImportStorageException(); }
    }
    private boolean imported(String id) { return id != null && id.matches("import-[a-f0-9]{32}"); }
    private Project origin(Project project) {
        try {
            var metadata = json.readTree(Files.readString(root.resolve(project.id() + ".json")));
            String reference = metadata.path("sourceReference").asString();
            if (reference.isBlank() || reference.length() > 512) throw new ImportStorageException();
            return new Project(project.id(), project.name(), reference, project.analyzedReference(), project.modules(), project.profiles());
        } catch (IOException | RuntimeException error) { throw new ImportStorageException(); }
    }
    @Override public List<Project> listProjects() {
        var projects = new ArrayList<>(fixtures.listProjects());
        // ponytail: at most twenty imports are fingerprinted; cache metadata if the catalog grows.
        for (var project : imports.listProjects()) if (imported(project.id())) projects.add(origin(project));
        return List.copyOf(projects);
    }
    @Override public Project validate(String id, AnalysisConfiguration configuration) {
        return imported(id) ? origin(imports.validate(id, configuration)) : fixtures.validate(id, configuration);
    }
    @Override public void snapshot(Project expected, AnalysisConfiguration configuration, Path destination) {
        (imported(expected.id()) ? imports : fixtures).snapshot(expected, configuration, destination);
    }
    @Override public Project importZip(InputStream input, String filename) {
        if (filename == null || filename.length() > 255 || !filename.toLowerCase(Locale.ROOT).endsWith(".zip")
                || filename.chars().anyMatch(value -> value < 32 || value == 127 || value == '/' || value == '\\' || value == ':'))
            throw new IllegalArgumentException("Selecciona un archivo .zip con un nombre válido.");
        if (!importing.tryAcquire()) throw new ImportBusyException();
        try { return importArchive(input, "zip:" + filename); }
        finally { importing.release(); }
    }
    @Override public Project importGit(String url) {
        var repository = githubRepository(url);
        if (!importing.tryAcquire()) throw new ImportBusyException();
        try {
            // Anonymous requests to fixed hosts: no Git CLI, credentials, user-controlled endpoints or redirects.
            var client = new ExternalJsonClient(true);
            long deadline = ExternalJsonClient.deadline();
            String sha = client.request(api.resolve("repos/" + repository + "/commits/HEAD"), null, deadline).json().path("sha").asString();
            if (!sha.matches("[a-f0-9]{40}")) throw new IllegalArgumentException("GitHub no devolvió un commit válido del repositorio público.");
            byte[] bytes = client.document(archives.resolve(repository + "/zip/" + sha), null, deadline).bytes();
            return importArchive(new ByteArrayInputStream(bytes), "git+https://github.com/" + repository + "@" + sha);
        } finally { importing.release(); }
    }
    public static String githubRepository(String value) {
        try {
            if (value == null || value.length() > 255) throw new IllegalArgumentException();
            URI uri = URI.create(value.strip());
            if (!"https".equals(uri.getScheme()) || !"github.com".equalsIgnoreCase(uri.getHost()) || uri.getPort() != -1
                    || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) throw new IllegalArgumentException();
            String path = uri.getRawPath();
            if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
            if (path.endsWith(".git")) path = path.substring(0, path.length() - 4);
            if (!path.matches("/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}")) throw new IllegalArgumentException();
            return path.substring(1);
        } catch (IllegalArgumentException error) { throw new IllegalArgumentException("Usa una URL HTTPS de un repositorio público: https://github.com/propietario/repositorio, sin credenciales, rama ni parámetros."); }
    }
    private Project importArchive(InputStream input, String source) {
        Path pending = null, metadata = null;
        boolean published = false;
        try {
            capacity();
            pending = Files.createTempDirectory(root, ".pending-");
            Path archive = pending.resolve("input.zip"), content = Files.createDirectory(pending.resolve("content"));
            var digest = MessageDigest.getInstance("SHA-256");
            try (var output = Files.newOutputStream(archive)) {
                long size = 0; byte[] buffer = new byte[8192];
                for (int count; (count = input.read(buffer)) != -1;) {
                    if ((size += count) > MAX_ARCHIVE) throw new IllegalArgumentException("El ZIP supera 10 MiB.");
                    digest.update(buffer, 0, count); output.write(buffer, 0, count);
                }
                if (size == 0) throw new IllegalArgumentException("El ZIP está vacío.");
            }
            extract(archive, content);
            Path projectRoot = findProject(content);
            String id = "import-" + UUID.randomUUID().toString().replace("-", "");
            Path candidateCatalog = Files.createDirectory(pending.resolve("catalog"));
            Files.move(projectRoot, candidateCatalog.resolve(id));
            var candidate = new FixtureProjectSource(candidateCatalog).validate(id, AnalysisConfiguration.defaults());
            validateParents(candidateCatalog.resolve(id));
            String reference = source.startsWith("zip:") ? source + ";sha256:" + HexFormat.of().formatHex(digest.digest()) : source;
            metadata = root.resolve(id + ".json");
            Files.writeString(metadata, json.writeValueAsString(Map.of("sourceReference", reference)), StandardOpenOption.CREATE_NEW);
            Files.move(candidateCatalog.resolve(id), root.resolve(id), StandardCopyOption.ATOMIC_MOVE);
            published = true;
            return new Project(id, candidate.name(), reference, candidate.analyzedReference(), candidate.modules(), candidate.profiles());
        } catch (IllegalArgumentException error) { throw error; }
        catch (java.util.zip.ZipException error) { throw new IllegalArgumentException("El archivo no es un ZIP válido."); }
        catch (IOException error) { throw new ImportStorageException(); }
        catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
        finally {
            if (!published && metadata != null) try { Files.deleteIfExists(metadata); } catch (IOException ignored) { }
            if (pending != null) deletePending(pending);
        }
    }
    private void capacity() throws IOException {
        try (var paths = Files.list(root)) {
            if (paths.filter(path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)).count() >= MAX_PROJECTS)
                throw new IllegalArgumentException("El catálogo admite hasta veinte importaciones; no se borran proyectos ni análisis anteriores automáticamente.");
        }
    }
    private static void extract(Path archive, Path destination) throws IOException {
        // Bound the central directory before Commons allocates entry objects; ZIP64/spanned files are unnecessary under these limits.
        byte[] bytes = Files.readAllBytes(archive);
        int end = -1;
        for (int i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 5 && bytes[i + 3] == 6
                    && i + 22 + Short.toUnsignedInt(ByteBuffer.wrap(bytes, i + 20, 2).order(ByteOrder.LITTLE_ENDIAN).getShort()) == bytes.length) { end = i; break; }
        }
        if (end < 0) throw new IllegalArgumentException("ZIP truncado o inválido.");
        var header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int count = Short.toUnsignedInt(header.getShort(end + 10));
        if (header.getShort(end + 4) != 0 || header.getShort(end + 6) != 0 || count > MAX_ENTRIES
                || count != Short.toUnsignedInt(header.getShort(end + 8))
                || Integer.toUnsignedLong(header.getInt(end + 12)) > MAX_ARCHIVE
                || Integer.toUnsignedLong(header.getInt(end + 16)) > bytes.length)
            throw new IllegalArgumentException("ZIP dividido, ZIP64 o demasiadas entradas no admitidos.");
        try (var nativeZip = new java.util.zip.ZipFile(archive.toFile())) {
            if (nativeZip.size() != count) throw new IllegalArgumentException("Directorio ZIP inconsistente.");
            // Check original names too: Commons normalizes backslashes on FAT entries.
            for (var entries = nativeZip.entries(); entries.hasMoreElements();) {
                var entry = entries.nextElement();
                validPath(entry.isDirectory() ? entry.getName().substring(0, entry.getName().length() - 1) : entry.getName());
            }
        }
        try (var zip = ZipFile.builder().setPath(archive).get()) {
            var seen = new HashSet<String>();
            long total = 0; int actualCount = 0;
            for (var entries = zip.getEntries(); entries.hasMoreElements();) {
                var entry = entries.nextElement();
                if (++actualCount > MAX_ENTRIES) throw new IllegalArgumentException("Demasiadas entradas en el ZIP.");
                String name = entry.getName();
                String normalized = entry.isDirectory() && name.endsWith("/") ? name.substring(0, name.length() - 1) : name;
                validPath(normalized);
                int type = entry.getUnixMode() & 0170000;
                if (entry.isUnixSymlink() || (type != 0 && type != 0100000 && type != 0040000) || !zip.canReadEntryData(entry)
                        || (entry.getMethod() != 0 && entry.getMethod() != 8) || !seen.add(normalized.toLowerCase(Locale.ROOT)))
                    throw new IllegalArgumentException("ZIP con enlaces, archivos especiales, cifrado o rutas duplicadas no admitido.");
                if (entry.getSize() < 0 || entry.getSize() > MAX_CONTENT || total + entry.getSize() > MAX_CONTENT)
                    throw new IllegalArgumentException("El contenido del ZIP supera 25 MiB.");
                Path target = destination.resolve(normalized).normalize();
                if (!target.startsWith(destination)) throw new IllegalArgumentException("Ruta ZIP fuera del proyecto.");
                if (entry.isDirectory()) { Files.createDirectories(target); continue; }
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("Rutas ZIP incompatibles.");
                Files.createDirectories(target.getParent());
                long size = 0; var crc = new java.util.zip.CRC32();
                try (var input = zip.getInputStream(entry); var output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
                    byte[] buffer = new byte[8192];
                    for (int n; (n = input.read(buffer)) != -1;) {
                        if ((size += n) > MAX_CONTENT || (total += n) > MAX_CONTENT) throw new IllegalArgumentException("El contenido del ZIP supera 25 MiB.");
                        crc.update(buffer, 0, n); output.write(buffer, 0, n);
                    }
                }
                if (size != entry.getSize() || crc.getValue() != entry.getCrc()) throw new IllegalArgumentException("Contenido ZIP truncado o con CRC inválido.");
            }
        }
    }
    private static void validPath(String name) {
        if (name.isEmpty() || name.length() > 512 || name.startsWith("/") || name.indexOf('\\') >= 0 || name.indexOf(':') >= 0
                || name.chars().anyMatch(value -> value < 32 || value == 127 || "<>\"|?*".indexOf(value) >= 0)) throw new IllegalArgumentException("Ruta ZIP no admitida.");
        for (String segment : name.split("/", -1)) {
            String base = segment.split("\\.", 2)[0].toUpperCase(Locale.ROOT);
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || segment.length() > 128
                    || segment.endsWith(".") || segment.endsWith(" ") || base.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]"))
                throw new IllegalArgumentException("Ruta ZIP no portátil o fuera del proyecto.");
            if (Set.of(".git", ".gitmodules", "target", "node_modules").contains(segment) || segment.startsWith(".env")
                    || Set.of("id_rsa", "id_ed25519", "credentials").contains(segment))
                throw new IllegalArgumentException("Prepara el ZIP sin .git, target, node_modules ni archivos de secretos.");
        }
        var segments = name.split("/");
        for (int i = 0; i + 1 < segments.length; i++) if (segments[i].equals(".mvn") && !segments[i + 1].equals("wrapper"))
            throw new IllegalArgumentException("No se admiten extensiones ni opciones Maven/JVM del proyecto en .mvn.");
    }
    private static void validateParents(Path project) throws IOException {
        var http = new ExternalJsonClient(true);
        long deadline = ExternalJsonClient.deadline();
        var seen = new HashSet<String>();
        class Parents {
            void check(org.w3c.dom.Element pom, Path file, int depth) {
                if (depth > 16 || seen.size() > 64) throw new IllegalArgumentException("Demasiados POM padre en el proyecto.");
                var parent = FixtureProjectSource.child(pom, "parent");
                if (parent == null) return;
                String group = FixtureProjectSource.text(parent, "groupId"), artifact = FixtureProjectSource.text(parent, "artifactId"), version = FixtureProjectSource.text(parent, "version");
                if (!group.matches("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*") || group.length() > 128
                        || !artifact.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}") || !version.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}"))
                    throw new IllegalArgumentException("La importación admite coordenadas literales de padres Maven; no propiedades ni rutas remotas.");
                var relative = FixtureProjectSource.child(parent, "relativePath");
                String path = relative == null ? "../pom.xml" : relative.getTextContent().strip();
                if (path.startsWith("/") || path.indexOf('\\') >= 0 || path.indexOf(':') >= 0)
                    throw new IllegalArgumentException("La ruta del POM padre debe ser relativa y portátil entre servidor y entorno Maven.");
                if (file != null && !path.isEmpty()) {
                    Path local = file.getParent().resolve(path).normalize();
                    if (!local.startsWith(project)) {
                        if (relative != null) throw new IllegalArgumentException("El POM padre local debe estar dentro del proyecto importado.");
                    } else {
                        if (Files.isDirectory(local)) local = local.resolve("pom.xml");
                        if (Files.isRegularFile(local, LinkOption.NOFOLLOW_LINKS)) {
                            try {
                                var localPom = FixtureProjectSource.pom(local);
                                var localParent = FixtureProjectSource.child(localPom, "parent");
                                String localGroup = FixtureProjectSource.text(localPom, "groupId"), localVersion = FixtureProjectSource.text(localPom, "version");
                                if (localGroup.isBlank()) localGroup = FixtureProjectSource.text(localParent, "groupId");
                                if (localVersion.isBlank()) localVersion = FixtureProjectSource.text(localParent, "version");
                                if (group.equals(localGroup) && artifact.equals(FixtureProjectSource.text(localPom, "artifactId")) && version.equals(localVersion)) {
                                    if (!seen.add("file:" + local)) return;
                                    check(localPom, local, depth + 1); return;
                                }
                            } catch (IllegalArgumentException error) { throw error; }
                            catch (Exception error) { throw new IllegalArgumentException("POM padre local no válido."); }
                        }
                    }
                }
                String coordinate = group + ":" + artifact + ":" + version;
                if (!seen.add(coordinate)) return;
                byte[] bytes = http.document(URI.create("https://repo.maven.apache.org/maven2/" + group.replace('.', '/') + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"), null, deadline).bytes();
                try { check(FixtureProjectSource.pom(bytes), null, depth + 1); }
                catch (IllegalArgumentException error) { throw error; }
                catch (Exception error) { throw new IllegalArgumentException("POM padre de Maven Central no válido."); }
            }
        }
        var parents = new Parents();
        try (var files = Files.walk(project)) {
            for (Path file : files.filter(path -> path.getFileName().toString().equals("pom.xml")).toList()) {
                try { parents.check(FixtureProjectSource.pom(file), file, 0); }
                catch (IllegalArgumentException error) { throw error; }
                catch (Exception error) { throw new IllegalArgumentException("POM importado no válido."); }
            }
        }
    }
    private static Path findProject(Path content) throws IOException {
        if (Files.isRegularFile(content.resolve("pom.xml"))) return content;
        try (var paths = Files.list(content)) {
            var children = paths.toList();
            if (children.size() == 1 && Files.isDirectory(children.getFirst()) && Files.isRegularFile(children.getFirst().resolve("pom.xml"))) return children.getFirst();
        }
        throw new IllegalArgumentException("El ZIP debe contener pom.xml en la raíz o dentro de una única carpeta de proyecto.");
    }
    private void deletePending(Path path) {
        if (!path.normalize().startsWith(root) || !path.getFileName().toString().startsWith(".pending-")) throw new IllegalStateException("Destino temporal no válido.");
        try (var paths = Files.walk(path)) { for (Path entry : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(entry); }
        catch (IOException error) { System.getLogger(getClass().getName()).log(System.Logger.Level.WARNING, "No se completó la limpieza de una importación temporal."); }
    }
}
