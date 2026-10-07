package com.smartsca.application.service;

import com.smartsca.application.port.outbound.*;
import com.smartsca.domain.*;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.component.DependencyGraph;
import com.smartsca.domain.vulnerability.*;
import java.util.*;

/** Orchestrates provider ports; alias correlation remains independent of HTTP and persistence. */
public final class EnrichAnalysisService {
    private final VulnerabilitySource vulnerabilities;
    private final ExploitSignalsSource signals;
    public EnrichAnalysisService(VulnerabilitySource vulnerabilities, ExploitSignalsSource signals) {
        this.vulnerabilities = vulnerabilities; this.signals = signals;
    }
    public VulnerabilitySnapshot enrich(DependencyGraph graph, AnalysisConfiguration configuration) {
        var components = graph.componentsInScopes(configuration.scopes());
        VulnerabilitySource.Result lookup;
        try { lookup = vulnerabilities.lookup(components); }
        catch (RuntimeException error) {
            Map<String, Evidence<List<String>>> queries = new TreeMap<>();
            components.forEach(component -> queries.put(component.purl(), Evidence.absent("OSV", EvidenceStatus.ERROR, "No se pudo consultar OSV.")));
            return new VulnerabilitySnapshot(List.of(), List.of(), queries);
        }
        var groups = VulnerabilityCorrelator.correlate(lookup.advisories());
        Set<String> cves = new TreeSet<>();
        for (var group : groups) for (String id : group) if (id.matches("CVE-[0-9]{4}-[0-9]{4,20}")) cves.add(id);
        var epss = observe("FIRST EPSS", cves, () -> signals.epss(cves));
        var kev = observe("CISA KEV", cves, () -> signals.kev(cves));
        List<Vulnerability> correlated = new ArrayList<>();
        Map<String, String> canonical = new HashMap<>();
        for (var group : groups) {
            String id = group.stream().filter(value -> value.startsWith("CVE-")).findFirst().orElse(group.iterator().next());
            group.forEach(value -> canonical.put(value, id));
            Map<String, Evidence<Advisory>> advisories = new TreeMap<>();
            Map<String, Evidence<Vulnerability.Epss>> groupEpss = new TreeMap<>();
            Map<String, Evidence<Boolean>> groupKev = new TreeMap<>();
            for (String alias : group) {
                if (lookup.advisories().containsKey(alias)) advisories.put(alias, lookup.advisories().get(alias));
                if (cves.contains(alias)) { groupEpss.put(alias, epss.get(alias)); groupKev.put(alias, kev.get(alias)); }
            }
            boolean completeDetails = advisories.values().stream().allMatch(value -> value.status() == EvidenceStatus.DISPONIBLE);
            correlated.add(new Vulnerability(id, group, advisories, aggregate("FIRST EPSS", groupEpss, completeDetails),
                aggregate("CISA KEV", groupKev, completeDetails)));
        }
        Set<Finding> findings = new LinkedHashSet<>();
        lookup.identified().forEach((purl, ids) -> ids.stream().map(canonical::get).filter(Objects::nonNull).sorted()
            .forEach(id -> findings.add(new Finding(purl, id))));
        return new VulnerabilitySnapshot(List.copyOf(findings), correlated.stream().sorted(Comparator.comparing(Vulnerability::id)).toList(), lookup.queries());
    }
    private static <T> Map<String, Evidence<T>> observe(String source, Set<String> ids,
            java.util.function.Supplier<Map<String, Evidence<T>>> query) {
        Map<String, Evidence<T>> values;
        try { values = query.get(); } catch (RuntimeException error) { values = Map.of(); }
        var complete = new TreeMap<String, Evidence<T>>();
        for (String id : ids) complete.put(id, values.getOrDefault(id, Evidence.absent(source, EvidenceStatus.ERROR, "Consulta de señal no completada.")));
        return complete;
    }
    private static <T> Evidence<Map<String, Evidence<T>>> aggregate(String source, Map<String, Evidence<T>> values, boolean complete) {
        if (!values.isEmpty()) return Evidence.available(source, java.time.Instant.now(), null, Map.copyOf(values));
        return Evidence.absent(source, complete ? EvidenceStatus.NO_APLICABLE : EvidenceStatus.NO_DISPONIBLE,
            complete ? "Aviso sin CVE; señal no aplicable." : "Detalle incompleto; no se conocen todos los CVE aplicables.");
    }
}
