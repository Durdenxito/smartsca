package com.smartsca;

import com.smartsca.domain.component.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DependencyGraphTests {
    private Component component(String name) { return new Component(name, "maven", name, "1", Map.of()); }
    private DependencyEdge edge(String parent, String child, String module, String scope) {
        return new DependencyEdge(parent, child, new DependencyContext(module, scope, scope));
    }
    private DependencyGraph graph(Map<String, String> roots, Set<DependencyEdge> edges) {
        var components = new HashMap<String, Component>();
        roots.values().forEach(purl -> components.put(purl, component(purl)));
        for (var edge : edges) {
            components.put(edge.parentPurl(), component(edge.parentPurl()));
            components.put(edge.childPurl(), component(edge.childPurl()));
        }
        return new DependencyGraph(roots, components, edges);
    }
    @Test void retainsBothParentsScopesAndModuleRootsWithoutWalkingCycles() {
        var graph = graph(Map.of("app", "root", "lib", "lib-root"), Set.of(
            edge("root", "a", "app", "compile"), edge("root", "b", "app", "runtime"),
            edge("a", "shared", "app", "runtime"), edge("b", "shared", "app", "runtime"),
            edge("shared", "a", "app", "runtime"), edge("shared", "shared", "app", "compile"),
            edge("lib-root", "shared", "lib", "test")));
        var routes = graph.routes("shared", null, 0);
        assertEquals(3, routes.routes().size());
        assertEquals(List.of("a", "b", "shared"), routes.routes().stream().map(route -> route.steps().getFirst().childPurl()).toList());
        assertEquals("compile", routes.routes().getFirst().steps().getFirst().context().normalizedContext());
        assertEquals("runtime", routes.routes().getFirst().steps().getLast().context().normalizedContext());
        assertFalse(routes.searchLimited());
        assertNull(routes.nextOffset());
        assertEquals(1, graph.routes("shared", "lib", 0).routes().size());
        assertEquals(0, graph.routes("root", "lib", 0).routes().size());
        assertTrue(graph.routes("root", "app", 0).routes().getFirst().steps().isEmpty());
        var neighborhood = graph.neighborhood("app", "shared", 0);
        assertEquals(Set.of("a", "b"), new HashSet<>(neighborhood.neighbors().stream().map(Component::purl).toList()));
        assertEquals(4, neighborhood.edges().size());
        assertThrows(IllegalArgumentException.class, () -> graph.neighborhood("app", "lib-root", 0));
        assertThrows(IllegalArgumentException.class, () -> graph.routes("missing", null, 0));
        assertThrows(IllegalArgumentException.class, () -> graph.routes("shared", "missing", 0));
        assertThrows(IllegalArgumentException.class, () -> graph.routes("shared", null, 1001));
        assertThrows(IllegalArgumentException.class, () -> graph.neighborhood("app", null, -1));
    }
    @Test void pagesNeighborsAndRoutesWithoutDroppingParallelScopes() {
        var edges = new HashSet<DependencyEdge>();
        for (int i = 0; i < 45; i++) {
            String parent = "parent-%02d".formatted(i);
            edges.add(edge("root", parent, ".", "compile"));
            edges.add(edge(parent, "shared", ".", "compile"));
            edges.add(edge(parent, "shared", ".", "test"));
        }
        var graph = graph(Map.of(".", "root"), edges);
        var first = graph.neighborhood(".", "shared", 0);
        assertEquals(45, first.totalNeighbors());
        assertEquals(24, first.neighbors().size());
        assertEquals(48, first.edges().size());
        var second = graph.neighborhood(".", "shared", first.nextOffset());
        assertEquals(21, second.neighbors().size());
        assertNull(second.nextOffset());
        var found = new HashSet<DependencyGraph.Route>();
        Integer offset = 0;
        while (offset != null) {
            var page = graph.routes("shared", null, offset);
            assertTrue(page.routes().size() <= 20);
            assertFalse(page.searchLimited());
            for (var route : page.routes()) assertTrue(found.add(route), "Repeated route across pages");
            offset = page.nextOffset();
        }
        assertEquals(90, found.size());
    }
    @Test void signalsDepthAndWorkLimitsRatherThanClaimingAnExhaustiveResult() {
        var edges = new HashSet<DependencyEdge>();
        for (int i = 0; i < 105; i++) edges.add(edge("node-" + i, "node-" + (i + 1), ".", "compile"));
        var deep = graph(Map.of(".", "node-0"), edges).routes("node-105", null, 0);
        assertTrue(deep.routes().isEmpty());
        assertTrue(deep.searchLimited());
        edges.clear();
        // A disconnected layered DAG has exponentially many reverse walks, but zero root-to-target paths.
        for (int i = 0; i < 18; i++) for (int a = 0; a < 2; a++) for (int b = 0; b < 2; b++)
            edges.add(edge("layer-" + i + "-" + a, "layer-" + (i + 1) + "-" + b, ".", "compile"));
        var limited = graph(Map.of(".", "isolated-root"), edges).routes("layer-18-0", null, 0);
        assertTrue(limited.routes().isEmpty());
        assertTrue(limited.searchLimited());
    }
}
