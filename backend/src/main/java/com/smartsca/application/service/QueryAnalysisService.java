package com.smartsca.application.service;

import com.smartsca.application.port.inbound.GetAnalysisUseCase;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.Analysis;
import java.util.NoSuchElementException;
import java.util.UUID;

/** Reads the persisted request, including after an application restart. */
public final class QueryAnalysisService implements GetAnalysisUseCase {
    private final AnalysisRepository analyses;
    public QueryAnalysisService(AnalysisRepository analyses) { this.analyses = analyses; }
    @Override public Analysis get(UUID id) {
        return analyses.get(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe."));
    }
    private com.smartsca.domain.component.DependencyGraph snapshot(UUID id) {
        var graph = get(id).dependencyGraph();
        if (graph == null) throw new IllegalArgumentException("El grafo todavía no está disponible.");
        return graph;
    }
    @Override public com.smartsca.domain.component.DependencyGraph.Neighborhood graph(UUID id, String module, String purl, int offset) {
        return snapshot(id).neighborhood(module, purl, offset);
    }
    @Override public com.smartsca.domain.component.DependencyGraph.Routes routes(UUID id, String purl, String module, int offset) {
        return snapshot(id).routes(purl, module, offset);
    }
    @Override public java.util.List<ComponentItem> components(UUID id, String search, String module, String scope, Boolean direct) {
        var analysis = get(id);
        var graph = analysis.dependencyGraph();
        if (graph == null) throw new IllegalArgumentException("El inventario todavía no está disponible.");
        String text = search == null ? "" : search.strip().toLowerCase(java.util.Locale.ROOT);
        if (text.length() > 256) throw new IllegalArgumentException("Búsqueda demasiado larga.");
        var result = new java.util.ArrayList<ComponentItem>();
        var allContexts = graph.contextsByComponent();
        for (var component : graph.components().values()) {
            if (!(component.name() + " " + component.version() + " " + component.purl()).toLowerCase(java.util.Locale.ROOT).contains(text)) continue;
            var contexts = allContexts.getOrDefault(component.purl(), java.util.Set.of()).stream()
                .filter(context -> analysis.configuration().scopes().contains(context.scope()))
                .filter(context -> module == null || module.equals(context.module()))
                .filter(context -> scope == null || scope.equals(context.scope()))
                .filter(context -> direct == null || direct == context.direct())
                .sorted(java.util.Comparator.comparing(com.smartsca.domain.component.DependencyGraph.Occurrence::module)
                    .thenComparing(com.smartsca.domain.component.DependencyGraph.Occurrence::scope)
                    .thenComparing(com.smartsca.domain.component.DependencyGraph.Occurrence::direct)).toList();
            if (!contexts.isEmpty()) result.add(new ComponentItem(component, contexts));
        }
        return result.stream().sorted(java.util.Comparator.comparing(item -> item.component().purl())).toList();
    }
}
