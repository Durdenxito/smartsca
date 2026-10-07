package com.smartsca.adapter.outbound.osv;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.application.port.outbound.VulnerabilitySource;
import com.smartsca.domain.*;
import com.smartsca.domain.component.Component;
import com.smartsca.domain.vulnerability.Advisory;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import tools.jackson.databind.JsonNode;

/** OSV batches of 50, per-query pagination, full details and bounded partial-result preservation. */
public final class OsvApiAdapter implements VulnerabilitySource {
    private final ExternalJsonClient http;
    private final URI endpoint;
    public OsvApiAdapter(ExternalJsonClient http) { this(http, URI.create("https://api.osv.dev/v1/")); }
    public OsvApiAdapter(ExternalJsonClient http, URI endpoint) { this.http = http; this.endpoint = endpoint; }
    @Override public Result lookup(List<Component> components) {
        long deadline = ExternalJsonClient.deadline();
        Map<String, Evidence<List<String>>> queries = new TreeMap<>();
        Map<String, Set<String>> identified = new TreeMap<>();
        Map<String, Evidence<Advisory>> details = new TreeMap<>();
        int identifiedCount = 0;
        for (var component : components) {
            identified.put(component.purl(), new TreeSet<>());
            queries.put(component.purl(), Evidence.absent(endpoint + "querybatch", EvidenceStatus.ERROR, "Consulta no completada."));
        }
        for (int start = 0; start < Math.min(components.size(), 1000); start += 50) {
            var pending = new ArrayList<>(components.subList(start, Math.min(start + 50, Math.min(components.size(), 1000))));
            Map<String, String> tokens = new HashMap<>();
            Map<String, Set<String>> seenTokens = new HashMap<>();
            for (int page = 0; !pending.isEmpty() && page < 20; page++) {
                try {
                    var payload = pending.stream().map(component -> {
                        Map<String, Object> query = new HashMap<>();
                        query.put("package", Map.of("ecosystem", "Maven", "name", component.name()));
                        query.put("version", component.version());
                        if (tokens.containsKey(component.purl())) query.put("page_token", tokens.get(component.purl()));
                        return query;
                    }).toList();
                    var response = http.request(endpoint.resolve("querybatch"), Map.of("queries", payload), deadline);
                    var rows = response.json().path("results");
                    if (!rows.isArray() || rows.size() != pending.size()) throw new IllegalArgumentException("OSV devolvió un lote incompleto.");
                    var next = new ArrayList<Component>();
                    for (int i = 0; i < pending.size(); i++) {
                        var component = pending.get(i);
                        var row = rows.get(i);
                        try {
                            if (!row.isObject() || (row.has("vulns") && !row.path("vulns").isArray())) throw new IllegalArgumentException("Resultado OSV inválido.");
                            for (var item : row.path("vulns")) {
                                String id = item.path("id").asString("");
                                if (!id.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,199}")) throw new IllegalArgumentException("Identificador OSV inválido.");
                                if (!details.containsKey(id) && details.size() >= 1000) throw new IllegalArgumentException("Se alcanzó el límite de avisos OSV.");
                                if (!identified.get(component.purl()).contains(id)) {
                                    if (identifiedCount >= 20_000) throw new IllegalArgumentException("Se alcanzó el límite de 20000 asociaciones componente-aviso.");
                                    identified.get(component.purl()).add(id); identifiedCount++;
                                }
                                details.putIfAbsent(id, Evidence.absent(endpoint + "vulns/" + id, EvidenceStatus.ERROR, "Detalle no recuperado."));
                            }
                            String token = row.path("next_page_token").asString("");
                            if (!token.isEmpty()) {
                                if (token.length() > 4096 || page == 19 || !seenTokens.computeIfAbsent(component.purl(), ignored -> new HashSet<>()).add(token))
                                    throw new IllegalArgumentException("OSV alcanzó el límite de paginación o repitió una página.");
                                tokens.put(component.purl(), token); next.add(component);
                            } else queries.put(component.purl(), Evidence.available(endpoint + "querybatch", response.collectedAt(), null,
                                List.copyOf(identified.get(component.purl()))));
                        } catch (IllegalArgumentException error) {
                            queries.put(component.purl(), Evidence.absent(endpoint + "querybatch", EvidenceStatus.ERROR, error.getMessage()));
                        }
                    }
                    pending = next;
                } catch (RuntimeException error) {
                    for (var component : pending) queries.put(component.purl(), Evidence.absent(endpoint + "querybatch", EvidenceStatus.ERROR,
                        error instanceof IllegalArgumentException ? error.getMessage() : "Respuesta OSV no interpretable."));
                    break;
                }
            }
        }
        long detailBytes = 0;
        for (String id : new ArrayList<>(details.keySet())) {
            if (System.nanoTime() >= deadline) break;
            try {
                var response = http.request(endpoint.resolve("vulns/" + URLEncoder.encode(id, StandardCharsets.UTF_8)), null, deadline);
                var node = response.json();
                String raw = node.toString();
                detailBytes += raw.getBytes(StandardCharsets.UTF_8).length;
                if (detailBytes > 32 * 1024 * 1024) {
                    details.replaceAll((key, value) -> value.status() == EvidenceStatus.DISPONIBLE ? value :
                        Evidence.absent(endpoint + "vulns/" + key, EvidenceStatus.ERROR, "Se alcanzó el límite acumulado de evidencia OSV (32 MiB)."));
                    break;
                }
                if (!id.equals(node.path("id").asString()) || !node.path("affected").isArray() || !node.path("modified").isString())
                    throw new IllegalArgumentException("Detalle OSV incompleto o con identidad distinta.");
                var aliases = new TreeSet<>(strings(node.path("aliases")));
                if (aliases.stream().anyMatch(alias -> !alias.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,199}")))
                    throw new IllegalArgumentException("Aliases OSV inválidos.");
                if (node.hasNonNull("withdrawn")) throw new IllegalArgumentException("Aviso retirado por la fuente; requiere revisión.");
                var affected = new ArrayList<Advisory.AffectedPackage>();
                for (var item : node.path("affected")) {
                    var fixed = new TreeSet<String>();
                    for (var range : item.path("ranges")) for (var event : range.path("events"))
                        if (event.path("fixed").isString()) fixed.add(event.path("fixed").asString());
                    affected.add(new Advisory.AffectedPackage(item.path("package").path("ecosystem").asString(""),
                        item.path("package").path("name").asString(""), item.path("ranges").toString(), strings(item.path("versions")), List.copyOf(fixed),
                        cvss(item.path("severity"), id, response)));
                }
                var references = new ArrayList<String>();
                for (var ref : node.path("references")) if (ref.path("url").isString()) references.add(ref.path("url").asString());
                var advisory = new Advisory(id, aliases, node.path("summary").asString(""), node.path("details").asString(""),
                    references, affected, cvss(node.path("severity"), id, response), raw);
                details.put(id, Evidence.available(endpoint + "vulns/" + id, response.collectedAt(), node.path("modified").asString(), advisory));
            } catch (RuntimeException error) {
                details.put(id, Evidence.absent(endpoint + "vulns/" + id, EvidenceStatus.ERROR,
                    error instanceof IllegalArgumentException ? error.getMessage() : "Detalle OSV no interpretable."));
            }
        }
        return new Result(queries, details, identified);
    }
    private Evidence<List<Advisory.CvssScore>> cvss(JsonNode values, String id, ExternalJsonClient.Response response) {
        var severity = new ArrayList<Advisory.CvssScore>();
        if (!readSeverity(values, id, severity)) return new Evidence<>(endpoint + "vulns/" + id, response.collectedAt(),
            response.json().path("modified").asString(), EvidenceStatus.ERROR, null, "Severidad CVSS no interpretable; respuesta original conservada.");
        if (severity.isEmpty()) return new Evidence<>(endpoint + "vulns/" + id, response.collectedAt(), response.json().path("modified").asString(),
            EvidenceStatus.NO_DISPONIBLE, null, "CVSS no publicado en este ámbito.");
        return Evidence.available(endpoint + "vulns/" + id, response.collectedAt(), response.json().path("modified").asString(), List.copyOf(severity));
    }
    private static List<String> strings(JsonNode values) {
        var result = new ArrayList<String>();
        for (var value : values) if (value.isString()) result.add(value.asString());
        return List.copyOf(result);
    }
    private static boolean readSeverity(JsonNode values, String id, List<Advisory.CvssScore> result) {
        if (values.isMissingNode() || values.isNull()) return true;
        if (!values.isArray()) return false;
        boolean valid = true;
        for (var value : values) {
            if (Set.of("CVSS_V2", "CVSS_V3", "CVSS_V4").contains(value.path("type").asString("")) && value.path("score").isString()
                    && !value.path("score").asString().isBlank() && (!value.hasNonNull("source") || value.path("source").isString())) {
                String source = value.path("source").asString("");
                result.add(new Advisory.CvssScore(version(value), value.path("score").asString(), source.isBlank() ? "OSV/" + id : source));
            }
            else valid = false;
        }
        return valid;
    }
    private static String version(JsonNode value) {
        var matcher = java.util.regex.Pattern.compile("^CVSS:([234]\\.[01])/").matcher(value.path("score").asString());
        return matcher.find() ? matcher.group(1) : value.path("type").asString().replace("CVSS_V", "") + ".0";
    }
}
