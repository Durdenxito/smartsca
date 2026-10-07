package com.smartsca.adapter.outbound.kev;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.domain.*;
import java.net.URI;
import java.time.Instant;
import java.util.*;

/** A false value means absence from a successfully validated CISA catalog, never a failed lookup. */
public final class KevCatalogAdapter {
    private final ExternalJsonClient http;
    private final List<URI> endpoints;
    public KevCatalogAdapter(ExternalJsonClient http) {
        this(http, List.of(URI.create("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            URI.create("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json")));
    }
    public KevCatalogAdapter(ExternalJsonClient http, List<URI> endpoints) { this.http = http; this.endpoints = List.copyOf(endpoints); }
    public Map<String, Evidence<Boolean>> lookup(Set<String> cves) {
        if (cves.isEmpty()) return Map.of();
        for (String cve : cves) if (!cve.matches("CVE-[0-9]{4}-[0-9]{4,20}")) throw new IllegalArgumentException("CVE inválido.");
        long deadline = ExternalJsonClient.deadline();
        String diagnostic = "Catálogo KEV no disponible.";
        for (URI endpoint : endpoints) try {
            var response = http.request(endpoint, null, deadline);
            var node = response.json();
            var rows = node.path("vulnerabilities");
            String date = node.path("dateReleased").asString(""); Instant.parse(date);
            if (!node.path("catalogVersion").isString() || !rows.isArray() || !node.path("count").isIntegralNumber()
                || rows.size() != node.path("count").asInt() || rows.isEmpty())
                throw new IllegalArgumentException("Catálogo KEV incompleto.");
            var present = new HashSet<String>();
            for (var row : rows) {
                String id = row.path("cveID").asString("");
                if (!id.matches("CVE-[0-9]{4}-[0-9]{4,20}") || !present.add(id)) throw new IllegalArgumentException("Catálogo KEV inválido.");
            }
            Map<String, Evidence<Boolean>> result = new TreeMap<>();
            for (String id : cves) result.put(id, Evidence.available(endpoint.toString(), response.collectedAt(),
                date, present.contains(id)));
            return Map.copyOf(result);
        } catch (RuntimeException error) {
            diagnostic = error instanceof IllegalArgumentException ? error.getMessage() : "Catálogo KEV no interpretable.";
        }
        Map<String, Evidence<Boolean>> result = new TreeMap<>();
        for (String id : cves) result.put(id, Evidence.absent(endpoints.getFirst().toString(), EvidenceStatus.ERROR, diagnostic));
        return Map.copyOf(result);
    }
}
