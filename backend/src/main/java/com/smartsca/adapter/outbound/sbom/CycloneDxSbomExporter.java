package com.smartsca.adapter.outbound.sbom;

import com.smartsca.application.port.outbound.SbomExporter;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.*;
import java.time.Instant;
import java.util.*;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import tools.jackson.databind.json.JsonMapper;

/** Fixed CycloneDX 1.6 JSON schema, bundled by the library; no plugin, shell or network execution. */
public final class CycloneDxSbomExporter implements SbomExporter {
    private final JsonMapper json = JsonMapper.builder().build();
    @Override public AnalysisArtifact generateAndValidate(Analysis analysis, DependencyGraph graph) {
        var generatedAt = Instant.now();
        String content = json.writeValueAsString(document(analysis, graph, generatedAt));
        validate(analysis, graph, content);
        return new AnalysisArtifact("1.6", generatedAt, AnalysisArtifact.digest(content), content);
    }
    /** Schema plus exact inventory, relationships and recorded selection, including Maven qualifiers. */
    public void validate(Analysis analysis, DependencyGraph graph, String content) {
        try {
            if (content == null || content.isBlank() || content.length() > AnalysisArtifact.MAX_BYTES
                    || content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > AnalysisArtifact.MAX_BYTES
                    || !new JsonParser().validate(content, Version.VERSION_16).isEmpty())
                throw new IllegalArgumentException("El SBOM no cumple el esquema CycloneDX 1.6.");
            var actual = json.readTree(content);
            var expected = json.valueToTree(document(analysis, graph, Instant.EPOCH));
            for (String field : List.of("bomFormat", "specVersion", "serialNumber", "version", "components", "dependencies", "properties"))
                if (!expected.path(field).equals(actual.path(field))) throw new IllegalArgumentException("El SBOM no coincide con la resolución registrada.");
            if (!expected.path("metadata").path("properties").equals(actual.path("metadata").path("properties")))
                throw new IllegalArgumentException("El SBOM no coincide con la configuración registrada.");
        } catch (IllegalArgumentException error) { throw error; }
        catch (Exception error) { throw new IllegalArgumentException("No se pudo validar el SBOM CycloneDX."); }
    }
    private Map<String, Object> document(Analysis analysis, DependencyGraph graph, Instant generatedAt) {
        if (graph == null || graph.rootsByModule().isEmpty()) throw new IllegalArgumentException("No hay resolución disponible para generar SBOM.");
        Set<String> modules = analysis.configuration().modules().contains(".") ? analysis.project().modules() : analysis.configuration().modules();
        if (!modules.equals(graph.rootsByModule().keySet())) throw new IllegalArgumentException("Módulos del SBOM no coinciden con la resolución.");
        Set<String> scopes = analysis.configuration().scopes();
        var selected = new TreeSet<String>();
        graph.componentsInScopes(scopes).forEach(component -> selected.add(component.purl()));
        var included = new TreeSet<>(graph.rootsByModule().values());
        included.addAll(selected);
        var retained = new HashSet<DependencyEdge>();
        // Preserve introducing paths even when an ancestor is outside the selected scopes; label it as a connector.
        for (String module : new TreeSet<>(modules)) {
            var incoming = new HashMap<String, List<DependencyEdge>>();
            for (var edge : graph.edges()) if (edge.context().module().equals(module))
                incoming.computeIfAbsent(edge.childPurl(), ignored -> new ArrayList<>()).add(edge);
            var queue = new ArrayDeque<String>();
            for (var edge : graph.edges()) if (edge.context().module().equals(module) && scopes.contains(edge.context().normalizedContext())) queue.add(edge.childPurl());
            var seen = new HashSet<String>();
            while (!queue.isEmpty()) {
                String child = queue.removeFirst();
                if (!seen.add(child)) continue;
                for (var edge : incoming.getOrDefault(child, List.of())) {
                    retained.add(edge); included.add(edge.parentPurl()); queue.add(edge.parentPurl());
                }
            }
        }
        var roots = new HashSet<>(graph.rootsByModule().values());
        var components = included.stream().map(purl -> {
            Component value = graph.components().get(purl);
            if (value == null || !purl.equals(value.purl()) || !"maven".equals(value.ecosystem()) || value.version() == null || value.version().isBlank())
                throw new IllegalArgumentException("Componente Maven del SBOM incompleto.");
            String[] name = value.name().split(":", -1);
            if (name.length != 2 || name[0].isBlank() || name[1].isBlank()) throw new IllegalArgumentException("Identidad Maven del SBOM no válida.");
            return Map.of("type", "library", "bom-ref", purl, "group", name[0], "name", name[1], "version", value.version(), "purl", purl,
                "properties", List.of(property("role", selected.contains(purl) ? "selected-dependency" : roots.contains(purl) ? "module-root" : "connector")));
        }).toList();
        var children = new TreeMap<String, Set<String>>();
        included.forEach(purl -> children.put(purl, new TreeSet<>()));
        retained.forEach(edge -> children.get(edge.parentPurl()).add(edge.childPurl()));
        var dependencies = children.entrySet().stream().map(entry -> Map.of("ref", entry.getKey(), "dependsOn", entry.getValue())).toList();
        var contexts = retained.stream().sorted(Comparator.comparing((DependencyEdge edge) -> edge.context().module())
            .thenComparing(DependencyEdge::parentPurl).thenComparing(DependencyEdge::childPurl)
            .thenComparing(edge -> edge.context().normalizedContext()).thenComparing(edge -> edge.context().originalScope())).toList();
        var config = analysis.configuration();
        var metadata = List.of(property("analysis-id", analysis.id().toString()), property("project-id", analysis.project().id()),
            property("analyzed-reference", analysis.project().analyzedReference()), property("engine-version", analysis.engineVersion()),
            property("configuration", json.writeValueAsString(Map.of("modules", new TreeSet<>(config.modules()), "profiles", new TreeSet<>(config.profiles()),
                "scopes", new TreeSet<>(scopes), "environmentId", config.environmentId()))),
            property("roots-by-module", json.writeValueAsString(new TreeMap<>(graph.rootsByModule()))));
        return Map.of("bomFormat", "CycloneDX", "specVersion", "1.6", "serialNumber", "urn:uuid:" + analysis.id(), "version", 1,
            "metadata", Map.of("timestamp", generatedAt.toString(), "properties", metadata), "components", components, "dependencies", dependencies,
            "properties", List.of(property("dependency-contexts", json.writeValueAsString(contexts)),
                property("coverage", "Resolved Maven snapshot: selected dependencies, module roots and labelled introducing connectors. No binaries, hashes, licenses or reachability were inspected.")));
    }
    private static Map<String, String> property(String name, String value) { return Map.of("name", "smartsca:" + name, "value", value); }
}
