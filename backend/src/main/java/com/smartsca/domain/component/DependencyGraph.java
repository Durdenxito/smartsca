package com.smartsca.domain.component;
import java.util.*;

/** Persisted graph; shared identities retain distinct module/scope edges. */
public record DependencyGraph(Map<String, String> rootsByModule, Map<String, Component> components,
                              Set<DependencyEdge> edges) {
    public DependencyGraph {
        rootsByModule = Map.copyOf(rootsByModule);
        components = Map.copyOf(components);
        edges = Set.copyOf(edges);
        for (var edge : edges) if (!components.containsKey(edge.parentPurl()) || !components.containsKey(edge.childPurl())
                || !rootsByModule.containsKey(edge.context().module())) throw new IllegalArgumentException("Grafo incompleto.");
        if (!components.keySet().containsAll(rootsByModule.values())) throw new IllegalArgumentException("Raíz no disponible.");
    }
    public record Occurrence(String module, String scope, String originalScope, boolean direct) {}
    public Set<Occurrence> contextsOf(String purl) {
        return contextsByComponent().getOrDefault(purl, Set.of());
    }
    public Map<String, Set<Occurrence>> contextsByComponent() {
        var result = new HashMap<String, Set<Occurrence>>();
        for (var edge : edges) {
            var context = edge.context();
            result.computeIfAbsent(edge.childPurl(), ignored -> new HashSet<>()).add(new Occurrence(context.module(), context.normalizedContext(), context.originalScope(),
                edge.parentPurl().equals(rootsByModule.get(context.module()))));
        }
        result.replaceAll((purl, values) -> Set.copyOf(values));
        return Map.copyOf(result);
    }
    /** The same selected inventory is used by all external sources. */
    public List<Component> componentsInScopes(Set<String> scopes) {
        var contexts = contextsByComponent();
        return components.values().stream().filter(component -> contexts.getOrDefault(component.purl(), Set.of())
            .stream().anyMatch(context -> scopes.contains(context.scope())))
            .sorted(Comparator.comparing(Component::purl)).toList();
    }

    public record Neighborhood(String module, Component root, Component focus, List<Component> neighbors,
                               List<DependencyEdge> edges, int offset, int totalNeighbors, Integer nextOffset) {}
    public record Route(String module, String rootPurl, List<DependencyEdge> steps) {}
    public record Routes(List<Route> routes, Map<String, Component> components, int offset,
                         Integer nextOffset, boolean searchLimited) {}

    /** One-hop view, paged by identity; every scope/parent edge for that page is retained. */
    public Neighborhood neighborhood(String module, String purl, int offset) {
        if (module == null) throw new IllegalArgumentException("Selecciona un módulo del análisis.");
        String root = rootsByModule.get(module);
        if (root == null) throw new IllegalArgumentException("El módulo no pertenece al análisis.");
        String focus = purl == null ? root : purl;
        requireComponent(focus);
        var incident = edges.stream().filter(edge -> edge.context().module().equals(module))
            .filter(edge -> edge.parentPurl().equals(focus) || edge.childPurl().equals(focus)).sorted(EDGE_ORDER).toList();
        if (!focus.equals(root) && incident.isEmpty()) throw new IllegalArgumentException("El componente no pertenece al módulo.");
        var identities = new TreeSet<String>();
        for (var edge : incident) { identities.add(edge.parentPurl()); identities.add(edge.childPurl()); }
        identities.remove(focus);
        if (offset < 0 || offset > identities.size()) throw new IllegalArgumentException("Página del grafo no válida.");
        var neighbors = identities.stream().skip(offset).limit(24).map(components::get).toList();
        var visible = new HashSet<String>();
        visible.add(focus);
        neighbors.forEach(component -> visible.add(component.purl()));
        return new Neighborhood(module, components.get(root), components.get(focus), neighbors,
            incident.stream().filter(edge -> visible.contains(edge.parentPurl()) && visible.contains(edge.childPurl())).toList(),
            offset, identities.size(), offset + neighbors.size() < identities.size() ? offset + neighbors.size() : null);
    }

    /** Deterministic simple paths, walking backwards to preserve alternate parents and module boundaries. */
    public Routes routes(String purl, String module, int offset) {
        requireComponent(purl);
        if (offset < 0 || offset > 1000) throw new IllegalArgumentException("Página de rutas no válida (máximo 1000).");
        if (module != null && !rootsByModule.containsKey(module)) throw new IllegalArgumentException("El módulo no pertenece al análisis.");
        var incoming = new HashMap<String, Map<String, List<DependencyEdge>>>();
        edges.stream().sorted(EDGE_ORDER).forEach(edge -> incoming.computeIfAbsent(edge.context().module(), ignored -> new HashMap<>())
            .computeIfAbsent(edge.childPurl(), ignored -> new ArrayList<>()).add(edge));
        // ponytail: re-enumerate at most 1021 paths per page; use cursors if larger graphs need deeper browsing.
        class Search {
            final List<Route> found = new ArrayList<>();
            int work;
            boolean limited;
            void visit(String context, String root, String node, List<DependencyEdge> reverse, Set<String> seen) {
                if (found.size() >= offset + 21 || work >= 50_000) return;
                work++;
                if (node.equals(root)) {
                    var steps = new ArrayList<>(reverse);
                    Collections.reverse(steps);
                    found.add(new Route(context, root, List.copyOf(steps)));
                    return;
                }
                var parents = incoming.getOrDefault(context, Map.of()).getOrDefault(node, List.of());
                if (reverse.size() >= 100) { if (!parents.isEmpty()) limited = true; return; }
                for (var edge : parents) {
                    if (found.size() >= offset + 21) return;
                    if (++work >= 50_000) { limited = true; return; }
                    if (!seen.add(edge.parentPurl())) continue;
                    reverse.add(edge);
                    visit(context, root, edge.parentPurl(), reverse, seen);
                    reverse.removeLast();
                    seen.remove(edge.parentPurl());
                }
            }
        }
        var search = new Search();
        for (var entry : new TreeMap<>(rootsByModule).entrySet()) {
            if (module != null && !module.equals(entry.getKey())) continue;
            if (search.work >= 50_000) { search.limited = true; break; }
            search.visit(entry.getKey(), entry.getValue(), purl, new ArrayList<>(), new HashSet<>(Set.of(purl)));
        }
        var page = search.found.stream().skip(offset).limit(20).toList();
        var visible = new TreeMap<String, Component>();
        for (var route : page) {
            visible.put(route.rootPurl(), components.get(route.rootPurl()));
            for (var edge : route.steps()) {
                visible.put(edge.parentPurl(), components.get(edge.parentPurl()));
                visible.put(edge.childPurl(), components.get(edge.childPurl()));
            }
        }
        return new Routes(page, Map.copyOf(visible), offset,
            search.found.size() > offset + 20 && offset + 20 <= 1000 ? offset + 20 : null,
            search.limited || (offset + 20 > 1000 && search.found.size() > offset + 20));
    }
    private void requireComponent(String purl) {
        if (purl == null || !components.containsKey(purl)) throw new IllegalArgumentException("El componente no pertenece al análisis.");
    }
    private static final Comparator<DependencyEdge> EDGE_ORDER = Comparator.comparing((DependencyEdge edge) -> edge.context().module())
        .thenComparing(DependencyEdge::parentPurl).thenComparing(DependencyEdge::childPurl)
        .thenComparing(edge -> edge.context().normalizedContext()).thenComparing(edge -> edge.context().originalScope());
}
