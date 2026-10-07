package com.smartsca.adapter.outbound.maven;

import com.smartsca.domain.component.*;
import com.smartsca.domain.component.Component;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** JSON supplies mediated identities; verbose TGF supplies duplicate/alternate parent edges. */
public final class MavenTreeParser {
    public record Tree(String json, String tgf) {}
    private record Artifact(String group, String name, String type, String classifier, String version, String scope) {
        String key() { return group + ":" + name + ":" + type + ":" + classifier; }
        Component component() {
            String qualifiers = (!classifier.isEmpty() ? "classifier=" + encode(classifier) : "");
            if (!type.equals("jar")) qualifiers += (qualifiers.isEmpty() ? "" : "&") + "type=" + encode(type);
            String purl = "pkg:maven/" + encode(group) + "/" + encode(name) + "@" + encode(version) + (qualifiers.isEmpty() ? "" : "?" + qualifiers);
            return new Component(purl, "maven", group + ":" + name, version,
                Map.of("groupId", group, "artifactId", name, "type", type, "classifier", classifier));
        }
    }

    public DependencyGraph parse(Map<String, Tree> trees, Set<String> scopes) {
        try {
            var roots = new TreeMap<String, String>();
            var components = new TreeMap<String, Component>();
            var edges = new HashSet<DependencyEdge>();
            var mapper = JsonMapper.builder().build();
            for (var entry : trees.entrySet()) {
                String module = entry.getKey();
                JsonNode json = mapper.readTree(entry.getValue().json());
                var resolved = new HashMap<String, Artifact>();
                collect(json, resolved, 0);
                Artifact root = artifact(json);
                roots.put(module, root.component().purl());
                components.put(root.component().purl(), root.component());
                var nodes = new LinkedHashMap<String, Artifact>();
                var links = new HashMap<String, List<String>>();
                boolean relationships = false;
                for (String line : entry.getValue().tgf().lines().toList()) {
                    if (line.equals("#")) { relationships = true; continue; }
                    if (line.isBlank()) continue;
                    String[] fields = line.strip().split("\\s+", 3);
                    if (fields.length < 2) throw new IllegalArgumentException("TGF incompleto.");
                    if (!relationships) {
                        // Verbose TGF wraps omitted identities: (coordinates - omitted for duplicate/conflict ...).
                        String coordinates = fields[1].startsWith("(") ? fields[1].substring(1) : fields[1];
                        String[] value = coordinates.split(":", -1);
                        if (value.length < 4 || value.length > 6) throw new IllegalArgumentException("Identidad Maven no válida.");
                        String classifier = value.length == 6 ? value[3] : "";
                        String version = value[value.length == 6 ? 4 : 3];
                        String scope = value.length == 4 ? "" : value[value.length - 1];
                        Artifact node = new Artifact(value[0], value[1], value[2], classifier, version, scope);
                        if (nodes.putIfAbsent(fields[0], node) != null) throw new IllegalArgumentException("Identificador TGF duplicado.");
                    } else links.computeIfAbsent(fields[0], ignored -> new ArrayList<>()).add(fields[1]);
                }
                if (!relationships || nodes.isEmpty() || !nodes.values().iterator().next().key().equals(root.key()))
                    throw new IllegalArgumentException("Raíz TGF no válida.");
                for (var link : links.entrySet()) if (!nodes.containsKey(link.getKey()) || link.getValue().stream().anyMatch(id -> !nodes.containsKey(id)))
                    throw new IllegalArgumentException("Relación Maven incompleta.");
                walk(nodes.keySet().iterator().next(), module, nodes, links, resolved, scopes, components, edges, new HashSet<>(), 0);
                if (components.size() > 10_000 || edges.size() > 50_000) throw new IllegalArgumentException("Grafo demasiado grande.");
            }
            return new DependencyGraph(roots, components, edges);
        } catch (IllegalArgumentException error) { throw error; }
        catch (Exception error) { throw new IllegalArgumentException("La salida de dependencias Maven no es válida."); }
    }

    private static void collect(JsonNode node, Map<String, Artifact> resolved, int depth) {
        if (depth > 100 || resolved.size() > 10_000) throw new IllegalArgumentException("Árbol demasiado grande.");
        Artifact value = artifact(node);
        Artifact old = resolved.putIfAbsent(value.key(), value);
        if (old != null && !old.version().equals(value.version())) throw new IllegalArgumentException("Resolución Maven ambigua.");
        JsonNode children = node.path("children");
        if (!children.isMissingNode() && !children.isArray()) throw new IllegalArgumentException("Hijos Maven no válidos.");
        for (JsonNode child : children) collect(child, resolved, depth + 1);
    }
    private static Artifact artifact(JsonNode node) {
        String group = node.path("groupId").asString("");
        String name = node.path("artifactId").asString("");
        String version = node.path("version").asString("");
        String type = node.path("type").asString("");
        if (group.isBlank() || name.isBlank() || version.isBlank() || type.isBlank() || version.length() > 256)
            throw new IllegalArgumentException("Identidad Maven incompleta.");
        return new Artifact(group, name, type, node.path("classifier").asString(""), version, node.path("scope").asString(""));
    }
    private static void walk(String id, String module, Map<String, Artifact> nodes,
                             Map<String, List<String>> links, Map<String, Artifact> resolved, Set<String> scopes,
                             Map<String, Component> components, Set<DependencyEdge> edges, Set<String> visited, int depth) {
        if (depth > 100 || visited.size() > 50_000) throw new IllegalArgumentException("Recorrido demasiado grande.");
        if (!visited.add(id)) return;
        Artifact parent = resolved.get(nodes.get(id).key());
        if (parent == null) return;
        for (String childId : links.getOrDefault(id, List.of())) {
            Artifact declared = nodes.get(childId);
            Artifact child = resolved.get(declared.key());
            if (child == null) continue;
            // Maven's TGF already reports the effective scope, including transitive test/provided nodes.
            String effective = declared.scope();
            if (!Set.of("compile", "runtime", "test", "provided").contains(effective))
                throw new IllegalArgumentException("Scope Maven no admitido.");
            if (!scopes.contains(effective)) continue;
            Component parentValue = parent.component(), childValue = child.component();
            components.put(parentValue.purl(), parentValue);
            components.put(childValue.purl(), childValue);
            edges.add(new DependencyEdge(parentValue.purl(), childValue.purl(), new DependencyContext(module, declared.scope(), effective)));
            walk(childId, module, nodes, links, resolved, scopes, components, edges, visited, depth + 1);
        }
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
}
