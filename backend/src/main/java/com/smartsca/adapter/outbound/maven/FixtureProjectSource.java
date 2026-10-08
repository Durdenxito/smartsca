package com.smartsca.adapter.outbound.maven;

import com.smartsca.application.port.outbound.ProjectSource;
import com.smartsca.domain.analysis.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Bounded, fingerprinted catalog. No user paths, symlinks or XML external resources. */
public final class FixtureProjectSource implements ProjectSource {
    private final Path root;
    public FixtureProjectSource(Path root) { this.root = root.toAbsolutePath().normalize(); }
    @Override public List<Project> listProjects() {
        try (var paths = Files.list(root)) {
            return paths.filter(p -> p.getFileName().toString().matches("[a-z0-9][a-z0-9-]{0,63}"))
                .filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS))
                .filter(p -> Files.isRegularFile(p.resolve("pom.xml"), LinkOption.NOFOLLOW_LINKS))
                .sorted().map(this::readProject).toList();
        } catch (java.io.IOException error) { throw new IllegalStateException("Catálogo no disponible.", error); }
    }
    @Override public Project validate(String id, AnalysisConfiguration configuration) {
        Project project = readProject(folder(id));
        if (!project.modules().containsAll(configuration.modules()) || !project.profiles().containsAll(configuration.profiles())
                || !configuration.environmentId().equals("java-21"))
            throw new IllegalArgumentException("Selecciona módulos, perfiles y entorno admitidos por el catálogo.");
        if (configuration.modules().contains(".") && configuration.modules().size() != 1)
            throw new IllegalArgumentException("El módulo raíz ya incluye el reactor completo.");
        return project;
    }
    @Override public void snapshot(Project expected, AnalysisConfiguration configuration, Path destination) {
        Project current = validate(expected.id(), configuration);
        if (expected.analyzedReference().startsWith("pom-sha256:"))
            throw new IllegalArgumentException("La solicitud usa una referencia anterior del catálogo. Registra un nuevo análisis.");
        if (!current.analyzedReference().equals(expected.analyzedReference()))
            throw new IllegalArgumentException("El proyecto cambió desde el registro. Inicia un nuevo análisis.");
        try {
            Path source = folder(expected.id());
            for (Path file : files(source)) {
                Path target = destination.resolve(source.relativize(file));
                Files.createDirectories(target.getParent());
                Files.copy(file, target, LinkOption.NOFOLLOW_LINKS);
            }
            if (!fingerprint(destination).equals(expected.analyzedReference()))
                throw new IllegalArgumentException("El proyecto cambió al preparar su copia. Inicia un nuevo análisis.");
        } catch (IllegalArgumentException error) { throw error; }
        catch (Exception error) { throw new IllegalArgumentException("No se pudo preparar la copia del proyecto."); }
    }
    private Path folder(String id) {
        if (id == null || !id.matches("[a-z0-9][a-z0-9-]{0,63}")) throw new IllegalArgumentException("Selecciona un proyecto del catálogo.");
        Path folder = root.resolve(id);
        if (!Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS) || !Files.isRegularFile(folder.resolve("pom.xml"), LinkOption.NOFOLLOW_LINKS))
            throw new IllegalArgumentException("El proyecto no está disponible en el catálogo.");
        return folder;
    }
    private Project readProject(Path folder) {
        try {
            var modules = new TreeSet<String>();
            var profiles = new TreeSet<String>();
            Element project = pom(folder.resolve("pom.xml"));
            collect(folder, ".", modules, profiles);
            String name = text(project, "name");
            if (name.isBlank()) name = text(project, "artifactId");
            if (name.length() > 255) throw new IllegalArgumentException("Nombre de proyecto demasiado largo.");
            String id = folder.getFileName().toString();
            return new Project(id, name, "catalog:" + id, fingerprint(folder), modules, profiles);
        } catch (IllegalArgumentException error) { throw error; }
        catch (Exception error) { throw new IllegalArgumentException("El proyecto no tiene un POM Maven válido."); }
    }
    private static void collect(Path root, String module, Set<String> modules, Set<String> profiles) throws Exception {
        if (!modules.add(module) || modules.size() > 32) throw new IllegalArgumentException("Reactor cíclico o demasiado grande.");
        Path directory = root.resolve(module).normalize();
        if (!directory.startsWith(root) || Files.isSymbolicLink(directory)) throw new IllegalArgumentException("Módulo no admitido.");
        Element project = pom(directory.resolve("pom.xml"));
        for (Element profile : children(child(project, "profiles"), "profile")) {
            String id = text(profile, "id");
            if (!id.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}") || profiles.size() >= 32 || child(profile, "modules") != null)
                throw new IllegalArgumentException("Perfil no admitido por el catálogo.");
            profiles.add(id);
        }
        // ponytail: static modules only; effective-POM discovery when profile/property-generated reactors are needed.
        for (Element entry : children(child(project, "modules"), "module")) {
            String relative = entry.getTextContent().strip();
            if (!relative.matches("[A-Za-z0-9][A-Za-z0-9_/-]{0,127}") || Arrays.asList(relative.split("/")).contains(".."))
                throw new IllegalArgumentException("Ruta de módulo no admitida.");
            collect(root, root.relativize(directory.resolve(relative).normalize()).toString().replace('\\', '/'), modules, profiles);
        }
    }
    static Element pom(Path path) throws Exception {
        byte[] bytes;
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { bytes = input.readNBytes(1_048_577); }
        return pom(bytes);
    }
    static Element pom(byte[] bytes) throws Exception {
        if (bytes.length > 1_048_576) throw new IllegalArgumentException("El POM supera el tamaño admitido.");
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Element project = factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(bytes)).getDocumentElement();
        if (!"project".equals(project.getLocalName()) || text(project, "artifactId").isBlank()) throw new IllegalArgumentException("POM Maven no válido.");
        var extensions = project.getElementsByTagNameNS("*", "extensions");
        for (int i = 0; i < extensions.getLength(); i++) {
            var extension = extensions.item(i);
            if (!(extension.getParentNode() instanceof Element owner) || !Set.of("build", "plugin").contains(owner.getLocalName())) continue;
            boolean structured = false;
            for (var node = extension.getFirstChild(); node != null; node = node.getNextSibling()) if (node instanceof Element) structured = true;
            String value = extension.getTextContent().strip();
            if (structured || (!value.isEmpty() && !value.equalsIgnoreCase("false"))) throw new IllegalArgumentException("No se admiten extensiones de compilación Maven ni plugins con extensions=true.");
        }
        return project;
    }
    private static List<Path> files(Path folder) throws java.io.IOException {
        var files = new ArrayList<Path>();
        Files.walkFileTree(folder, new SimpleFileVisitor<>() {
            int count;
            long size;
            @Override public FileVisitResult preVisitDirectory(Path path, java.nio.file.attribute.BasicFileAttributes attrs) {
                if (!path.equals(folder) && Set.of("target", ".git", "node_modules").contains(path.getFileName().toString())) return FileVisitResult.SKIP_SUBTREE;
                check(path, attrs);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path path, java.nio.file.attribute.BasicFileAttributes attrs) {
                check(path, attrs);
                if (!attrs.isRegularFile()) throw new IllegalArgumentException("Tipo de archivo no admitido.");
                files.add(path);
                return FileVisitResult.CONTINUE;
            }
            private void check(Path path, java.nio.file.attribute.BasicFileAttributes attrs) {
                if (++count > 2048 || attrs.isSymbolicLink() || path.getFileName().toString().startsWith(".env"))
                    throw new IllegalArgumentException("El fixture contiene enlaces, secretos o demasiados archivos.");
                if (attrs.isRegularFile()) size += attrs.size();
                if (size > 25 * 1024 * 1024) throw new IllegalArgumentException("El fixture supera 25 MiB.");
            }
        });
        return files.stream().sorted(Comparator.comparing(path -> folder.relativize(path).toString().replace('\\', '/'))).toList();
    }
    private static String fingerprint(Path folder) throws Exception {
        var hash = MessageDigest.getInstance("SHA-256");
        for (Path file : files(folder)) {
            byte[] bytes;
            try (var input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) { bytes = input.readNBytes(25 * 1024 * 1024 + 1); }
            if (bytes.length > 25 * 1024 * 1024) throw new IllegalArgumentException("Archivo demasiado grande.");
            hash.update(folder.relativize(file).toString().replace('\\', '/').getBytes(java.nio.charset.StandardCharsets.UTF_8));
            hash.update((byte) 0);
            hash.update(java.nio.ByteBuffer.allocate(8).putLong(bytes.length).array());
            hash.update(bytes);
        }
        return "fixture-sha256:" + HexFormat.of().formatHex(hash.digest());
    }
    private static List<Element> children(Element parent, String name) {
        var result = new ArrayList<Element>();
        if (parent != null) for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element && name.equals(element.getLocalName())) result.add(element);
        return result;
    }
    static Element child(Element parent, String name) { return children(parent, name).stream().findFirst().orElse(null); }
    static String text(Element parent, String name) { Element found = child(parent, name); return found == null ? "" : found.getTextContent().strip(); }
}
