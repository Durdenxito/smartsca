package com.smartsca.application.service;

import com.smartsca.application.port.inbound.GetAnalysisUseCase;
import com.smartsca.application.port.inbound.ListAnalysesUseCase;
import com.smartsca.domain.analysis.AnalysisStatus;
import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.domain.analysis.Analysis;
import java.util.NoSuchElementException;
import java.util.UUID;

/** Reads the persisted request, including after an application restart. */
public final class QueryAnalysisService implements GetAnalysisUseCase, ListAnalysesUseCase {
    private final AnalysisRepository analyses;
    public QueryAnalysisService(AnalysisRepository analyses) { this.analyses = analyses; }
    @Override public Analysis get(UUID id) {
        return analyses.get(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe."));
    }
    @Override public Status status(UUID id) { return analyses.readStatus(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe.")); }
    @Override public Resolution resolution(UUID id) { return analyses.readResolution(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe.")); }
    @Override public Sources sources(UUID id) { return analyses.readSources(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe.")); }
    @Override public Inventory inventory(UUID id) {
        var saved = analyses.readInventory(id).orElseThrow(() -> new NoSuchElementException("El análisis no existe."));
        var resolution = saved.resolution();
        if (resolution.dependencyGraph() == null) throw new IllegalArgumentException("El inventario todavía no está disponible.");
        return new Inventory(resolution.projectName(), resolution.status(), resolution.scopes(), resolution.dependencyGraph().rootsByModule(),
            components(resolution, null, null, null, null), saved.healthAssessments(), saved.vulnerabilitiesAvailable());
    }
    @Override public Page list(String projectId, AnalysisStatus status, int offset) {
        String project = projectId == null || projectId.isBlank() ? null : projectId.strip();
        if (project != null && !project.matches("[a-z0-9][a-z0-9-]{0,63}"))
            throw new IllegalArgumentException("Identificador de proyecto inválido.");
        if (offset < 0 || offset > MAX_OFFSET) throw new IllegalArgumentException("Offset del historial fuera de límite (0–10000).");
        return analyses.list(project, status, offset);
    }
    private com.smartsca.domain.component.DependencyGraph snapshot(UUID id) {
        var graph = resolution(id).dependencyGraph();
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
        return components(resolution(id), search, module, scope, direct);
    }
    private java.util.List<ComponentItem> components(Resolution resolution, String search, String module, String scope, Boolean direct) {
        var graph = resolution.dependencyGraph();
        if (graph == null) throw new IllegalArgumentException("El inventario todavía no está disponible.");
        String text = search == null ? "" : search.strip().toLowerCase(java.util.Locale.ROOT);
        if (text.length() > 256) throw new IllegalArgumentException("Búsqueda demasiado larga.");
        var result = new java.util.ArrayList<ComponentItem>();
        var allContexts = graph.contextsByComponent();
        for (var component : graph.components().values()) {
            if (!(component.name() + " " + component.version() + " " + component.purl()).toLowerCase(java.util.Locale.ROOT).contains(text)) continue;
            var contexts = allContexts.getOrDefault(component.purl(), java.util.Set.of()).stream()
                .filter(context -> resolution.scopes().contains(context.scope()))
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
