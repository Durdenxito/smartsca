package com.smartsca.adapter.outbound.epss;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.domain.*;
import com.smartsca.domain.vulnerability.Vulnerability.Epss;
import java.net.URI;
import java.time.LocalDate;
import java.util.*;

/** FIRST EPSS observations: probability and percentile on scale 0–1, dated individually. */
public final class EpssApiAdapter {
    private final ExternalJsonClient http;
    private final URI endpoint;
    public EpssApiAdapter(ExternalJsonClient http) { this(http, URI.create("https://api.first.org/data/v1/epss")); }
    public EpssApiAdapter(ExternalJsonClient http, URI endpoint) { this.http = http; this.endpoint = endpoint; }
    public Map<String, Evidence<Epss>> lookup(Set<String> cves) {
        var result = new TreeMap<String, Evidence<Epss>>();
        var ids = cves.stream().sorted().toList();
        ids.forEach(id -> {
            if (!id.matches("CVE-[0-9]{4}-[0-9]{4,20}")) throw new IllegalArgumentException("CVE inválido.");
            result.put(id, Evidence.absent(endpoint.toString(), EvidenceStatus.ERROR, "Consulta EPSS no completada."));
        });
        long deadline = ExternalJsonClient.deadline();
        for (int start = 0; start < Math.min(ids.size(), 1000); start += 50) {
            var batch = ids.subList(start, Math.min(start + 50, Math.min(ids.size(), 1000)));
            int offset = 0;
            Set<String> returned = new HashSet<>();
            try {
                for (int page = 0; page < 20; page++) {
                    var uri = URI.create(endpoint + "?cve=" + String.join(",", batch) + "&limit=50&offset=" + offset);
                    var response = http.request(uri, null, deadline);
                    var node = response.json();
                    var data = node.path("data");
                    if (!"OK".equals(node.path("status").asString()) || !data.isArray() || !node.path("total").isIntegralNumber()
                        || node.path("total").asInt() < 0 || node.path("offset").asInt(-1) != offset)
                        throw new IllegalArgumentException("Respuesta EPSS incompleta.");
                    for (var entry : data) {
                        String id = entry.path("cve").asString("");
                        if (!batch.contains(id) || !returned.add(id)) throw new IllegalArgumentException("EPSS devolvió una identidad inesperada o repetida.");
                        try {
                            String date = entry.path("date").asString(); LocalDate.parse(date);
                            double probability = Double.parseDouble(entry.path("epss").asString());
                            double percentile = Double.parseDouble(entry.path("percentile").asString());
                            result.put(id, Evidence.available(uri.toString(), response.collectedAt(), date, new Epss(probability, percentile)));
                        } catch (RuntimeException error) {
                            result.put(id, Evidence.absent(uri.toString(), EvidenceStatus.ERROR, "Valor o fecha EPSS inválido."));
                        }
                    }
                    offset += data.size();
                    if (offset >= node.path("total").asInt()) {
                        for (String id : batch) if (!returned.contains(id)) result.put(id,
                            new Evidence<>(uri.toString(), response.collectedAt(), null, EvidenceStatus.NO_DISPONIBLE, null, "FIRST no publicó EPSS para este CVE."));
                        break;
                    }
                    if (data.isEmpty() || page == 19) throw new IllegalArgumentException("EPSS alcanzó el límite de paginación.");
                }
            } catch (RuntimeException error) {
                // Earlier valid pages remain useful; missing rows stay errors rather than absence.
                for (String id : batch) if (!returned.contains(id)) result.put(id, Evidence.absent(endpoint.toString(), EvidenceStatus.ERROR,
                    error instanceof IllegalArgumentException ? error.getMessage() : "Respuesta EPSS no interpretable."));
            }
        }
        return Map.copyOf(result);
    }
}
