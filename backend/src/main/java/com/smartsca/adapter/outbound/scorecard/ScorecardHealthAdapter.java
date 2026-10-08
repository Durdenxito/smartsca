package com.smartsca.adapter.outbound.scorecard;

import com.smartsca.adapter.outbound.ExternalJsonClient;
import com.smartsca.application.port.outbound.HealthSource;
import com.smartsca.domain.*;
import com.smartsca.domain.component.Component;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.health.HealthAssessment.*;
import java.io.ByteArrayInputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import tools.jackson.databind.JsonNode;

/** Published version/parent POM SCM, checked against deps.dev projects; no guessed mirrors or arbitrary fetches. */
public final class ScorecardHealthAdapter implements HealthSource {
    private final ExternalJsonClient http;
    private final URI metadata, central;
    public ScorecardHealthAdapter(ExternalJsonClient http) {
        this(http, URI.create("https://api.deps.dev/v3/"), URI.create("https://repo.maven.apache.org/maven2/"));
    }
    /** Endpoint injection is reserved for HTTP contract tests, never exposed to the User. */
    public ScorecardHealthAdapter(ExternalJsonClient http, URI metadata, URI central) {
        this.http = http; this.metadata = metadata; this.central = central;
    }
    @Override public Map<String, HealthAssessment> assess(List<Component> components) {
        Map<String, HealthAssessment> result = new TreeMap<>();
        long deadline = ExternalJsonClient.deadline(), retained = 0;
        for (int i = 0; i < components.size(); i++) {
            var component = components.get(i);
            HealthAssessment assessment;
            if (i >= 1000 || retained >= 32L * 1024 * 1024 || System.nanoTime() >= deadline)
                assessment = HealthAssessment.unavailable(component.purl(), "deps.dev / Maven Central", EvidenceStatus.ERROR, "Consulta de salud limitada por tiempo, componentes o tamaño acumulado.");
            else {
                assessment = inspect(component, deadline);
                long size = size(assessment);
                if (retained + size > 32L * 1024 * 1024) {
                    assessment = HealthAssessment.unavailable(component.purl(), "deps.dev / Maven Central", EvidenceStatus.ERROR, "La evidencia de salud supera el límite acumulado de 32 MiB.");
                    retained = 32L * 1024 * 1024;
                } else retained += size;
            }
            result.put(component.purl(), assessment);
        }
        return Map.copyOf(result);
    }
    private HealthAssessment inspect(Component component, long deadline) {
        Evidence<RepositoryAssociation> association = null;
        String source = "deps.dev / Maven Central";
        List<Evidence<String>> evidence = new ArrayList<>();
        Instant observed = Instant.now();
        try {
            if (!component.ecosystem().equalsIgnoreCase("maven"))
                return HealthAssessment.unavailable(component.purl(), source, EvidenceStatus.NO_APLICABLE, "La asociación de salud de esta etapa admite Maven.");
            String[] name = component.name().split(":", -1);
            if (name.length != 2 || !coordinate(name[0]) || !coordinate(name[1]) || !coordinate(component.version()))
                return HealthAssessment.unavailable(component.purl(), source, EvidenceStatus.NO_DISPONIBLE, "Coordenadas Maven no admitidas para consultar metadatos.");
            URI versionUri = metadata.resolve("systems/maven/packages/" + encode(component.name()) + "/versions/" + encode(component.version()));
            source = versionUri.toString();
            boolean versionAvailable = true;
            Set<String> candidates = new TreeSet<>();
            try {
                var version = http.request(versionUri, null, deadline);
                observed = version.collectedAt();
                evidence.add(Evidence.available(source, observed, null, version.json().toString()));
                var key = version.json().path("versionKey");
                if (!key.path("system").asString().equals("MAVEN") || !key.path("name").asString().equals(component.name())
                    || !key.path("version").asString().equals(component.version())) throw new IllegalArgumentException("Metadatos de otra identidad o versión.");
                var related = version.json().path("relatedProjects");
                if (!related.isMissingNode() && !related.isArray()) throw new IllegalArgumentException("Relaciones de repositorio inválidas.");
                for (var project : related) if (project.path("relationType").asString().equals("SOURCE_REPO")) {
                    String id = repository(project.path("projectKey").path("id").asString());
                    if (id == null) return unavailable(component.purl(), source, observed, EvidenceStatus.NO_DISPONIBLE, evidence, "Repositorio de origen con formato no admitido; no se adivina una alternativa.");
                    candidates.add(id);
                }
            } catch (ExternalJsonClient.HttpStatusException error) {
                if (error.statusCode() != 404) throw error;
                versionAvailable = false;
                evidence.add(observation(source, observed, null, EvidenceStatus.NO_DISPONIBLE,
                    "deps.dev no tiene registrada esta versión (HTTP 404); se consulta su POM publicado."));
            }
            if (candidates.size() > 1) return unavailable(component.purl(), source, observed, EvidenceStatus.NO_DISPONIBLE, evidence, "La versión tiene varios repositorios de origen; asociación ambigua.");
            URI pomUri = central.resolve(name[0].replace('.', '/') + "/" + name[1] + "/" + component.version() + "/" + name[1] + "-" + component.version() + ".pom");
            source = pomUri.toString();
            observed = Instant.now();
            var poms = new ArrayList<Element>();
            publishedPoms(name[0], name[1], component.version(), deadline, evidence, poms, new HashSet<>());
            var properties = new HashMap<String, String>();
            var fields = new HashMap<String, String>();
            var profileProperties = new HashSet<String>();
            for (int index = poms.size() - 1; index >= 0; index--) {
                Element pom = poms.get(index);
                properties.putAll(properties(pom));
                Element profiles = child(pom, "profiles");
                if (profiles != null)
                    for (var entry = profiles.getFirstChild(); entry != null; entry = entry.getNextSibling())
                        if (entry instanceof Element profile) profileProperties.addAll(properties(profile).keySet());
                Element declaration = child(pom, "scm");
                for (String field : List.of("url", "connection", "developerConnection")) {
                    String value = text(declaration, field);
                    if (!value.isEmpty()) fields.put(field, value);
                }
            }
            properties.put("project.groupId", name[0]); properties.put("pom.groupId", name[0]);
            properties.put("project.artifactId", name[1]); properties.put("pom.artifactId", name[1]);
            properties.put("project.version", component.version()); properties.put("pom.version", component.version());
            Element parent = child(poms.getFirst(), "parent");
            for (String field : List.of("groupId", "artifactId", "version")) {
                properties.put("project.parent." + field, text(parent, field));
                properties.put("pom.parent." + field, text(parent, field));
            }
            Set<String> scm = new TreeSet<>();
            // Repository identity only: inherited checkout subpaths do not change an accepted owner/repository base.
            for (String value : fields.values()) {
                String id = repository(interpolate(value, properties, profileProperties));
                if (id == null) return unavailable(component.purl(), pomUri.toString(), observed, EvidenceStatus.NO_DISPONIBLE, evidence,
                    "SCM sin resolver, dependiente de perfiles o en un host/formato no admitido. No se asigna salud de un repositorio supuesto.");
                scm.add(id);
            }
            if (scm.size() != 1 || (!candidates.isEmpty() && !candidates.equals(scm)))
                return unavailable(component.purl(), source, observed, EvidenceStatus.NO_DISPONIBLE, evidence,
                    "No existe un SCM único concordante con los metadatos disponibles; puede faltar o ser contradictorio.");
            String id = scm.iterator().next();
            URI projectUri = metadata.resolve("projects/" + encode(id));
            source = projectUri.toString();
            observed = Instant.now();
            var project = http.request(projectUri, null, deadline);
            observed = project.collectedAt();
            evidence.add(Evidence.available(source, observed, null, project.json().toString()));
            if (!id.equals(repository(project.json().path("projectKey").path("id").asString())))
                throw new IllegalArgumentException("La respuesta pertenece a otro repositorio; asociación no comprobada.");
            association = Evidence.available(pomUri + " / " + projectUri, project.collectedAt(), null,
                new RepositoryAssociation(id, (versionAvailable ? "SCM_POM_Y_PROYECTO_CONTRASTADOS" : "SCM_POM_Y_PROYECTO_SIN_VERSION_DEPS_DEV")
                        + (poms.size() > 1 ? "_PADRES_V1" : "")));
            var report = project.json().path("scorecard");
            if (report.isMissingNode() || report.isNull()) return absentReport(component.purl(), association, source,
                project.collectedAt(), null, EvidenceStatus.NO_DISPONIBLE, evidence, "El repositorio no tiene un resultado Scorecard publicado en esta fuente.");
            Instant date = Instant.parse(report.path("date").asString());
            if (date.isAfter(project.collectedAt().plus(Duration.ofDays(1)))) throw new IllegalArgumentException("Fecha Scorecard futura o inválida.");
            if (!id.equals(repository(report.path("repository").path("name").asString()))) throw new IllegalArgumentException("Scorecard corresponde a otro repositorio.");
            var checks = report.path("checks");
            if (!checks.isArray() || checks.size() > 100) throw new IllegalArgumentException("Lista de indicadores Scorecard inválida.");
            String repoCommit = required(report.path("repository"), "commit"), toolVersion = required(report.path("scorecard"), "version"), toolCommit = required(report.path("scorecard"), "commit");
            Map<String, Evidence<Indicator>> indicators = new LinkedHashMap<>();
            for (String check : HealthAssessment.CHECKS) {
                var matches = new ArrayList<JsonNode>();
                checks.forEach(row -> { if (row.path("name").asString().equals(check)) matches.add(row); });
                if (matches.isEmpty()) indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.NO_DISPONIBLE, "Indicador no publicado."));
                else if (matches.size() > 1) indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.ERROR, "Indicador duplicado; valor ambiguo."));
                else {
                    var row = matches.getFirst();
                    var score = row.path("score");
                    if (!score.isIntegralNumber() || !score.canConvertToInt() || score.asInt() > 10)
                        indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.ERROR, "Puntuación fuera de la escala publicada 0–10."));
                    else if (score.asInt() < 0) indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.NO_DISPONIBLE,
                        "Scorecard no pudo evaluar el indicador: " + row.path("reason").asString()));
                    else {
                        var details = row.path("details");
                        if ((!details.isMissingNode() && !details.isArray()) || details.size() > 1000 || !row.path("reason").isString()) {
                            indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.ERROR, "Detalle de indicador inválido.")); continue;
                        }
                        List<String> entries = new ArrayList<>(); boolean valid = true;
                        for (var detail : details) { if (!detail.isString()) { valid = false; break; } entries.add(detail.asString()); }
                        if (!valid) indicators.put(check, observation(source, project.collectedAt(), date.toString(), EvidenceStatus.ERROR, "Detalle de indicador inválido."));
                        else indicators.put(check, Evidence.available(source, project.collectedAt(), date.toString(), new Indicator(check, score.asInt(), row.path("reason").asString(), entries, row.path("documentation").path("url").asString())));
                    }
                }
            }
            return new HealthAssessment(component.purl(), association, Evidence.available(source, project.collectedAt(), date.toString(),
                new ScorecardReport(id, repoCommit, toolVersion, toolCommit, date.plus(Duration.ofDays(90)).isBefore(project.collectedAt()),
                    "scorecard-age-v1-90d")), indicators, evidence);
        } catch (Exception error) {
            if (source.endsWith(".pom") && !evidence.isEmpty()) {
                source = evidence.getLast().source(); observed = evidence.getLast().collectedAt();
            }
            String reason = error instanceof IllegalArgumentException ? error.getMessage() : "No se pudo interpretar la evidencia publicada de salud.";
            var status = error instanceof ExternalJsonClient.HttpStatusException httpError && httpError.statusCode() == 404
                ? EvidenceStatus.NO_DISPONIBLE : EvidenceStatus.ERROR;
            return association == null ? unavailable(component.purl(), source, observed, status, evidence, reason)
                : absentReport(component.purl(), association, source, observed, null, status, evidence, reason);
        }
    }
    private void publishedPoms(String groupId, String artifactId, String version, long deadline,
            List<Evidence<String>> evidence, List<Element> poms, Set<String> seen) throws Exception {
        if (!coordinate(groupId) || !groupId.matches("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*")
            || !coordinate(artifactId) || !artifactId.matches("[A-Za-z0-9].*") || !coordinate(version) || !version.matches("[A-Za-z0-9].*"))
            throw new IllegalArgumentException("Coordenadas de POM padre no admitidas; solo valores literales de Maven Central.");
        if (poms.size() >= 16 || !seen.add(groupId + ":" + artifactId + ":" + version))
            throw new IllegalArgumentException("Cadena de padres Maven cíclica o superior a 16 POM.");
        URI uri = central.resolve(groupId.replace('.', '/') + "/" + artifactId + "/" + version + "/" + artifactId + "-" + version + ".pom");
        ExternalJsonClient.Document document;
        try { document = http.document(uri, null, deadline); }
        catch (RuntimeException error) {
            evidence.add(observation(uri.toString(), Instant.now(), null,
                error instanceof ExternalJsonClient.HttpStatusException status && status.statusCode() == 404
                    ? EvidenceStatus.NO_DISPONIBLE : EvidenceStatus.ERROR, error.getMessage()));
            throw error;
        }
        var observed = document.collectedAt();
        byte[] bytes = document.bytes();
        // Reversible and JSONB-safe even when XML cannot be parsed (e.g. UTF-16 with NUL bytes).
        evidence.add(Evidence.available(uri.toString(), observed, null, "BASE64:" + Base64.getEncoder().encodeToString(bytes)));
        if (bytes.length > 1_048_576) throw new IllegalArgumentException("El POM publicado supera 1 MiB.");
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
        var builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
            @Override public void error(org.xml.sax.SAXParseException error) throws org.xml.sax.SAXException { throw error; }
            @Override public void fatalError(org.xml.sax.SAXParseException error) throws org.xml.sax.SAXException { throw error; }
        });
        var parsed = builder.parse(new ByteArrayInputStream(bytes));
        String encoding = parsed.getXmlEncoding() == null ? parsed.getInputEncoding() : parsed.getXmlEncoding();
        String original = java.nio.charset.Charset.forName(encoding == null ? "UTF-8" : encoding).newDecoder()
            .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        if (original.indexOf('\0') < 0) evidence.set(evidence.size() - 1, Evidence.available(uri.toString(), observed, null, original));
        Element pom = parsed.getDocumentElement();
        if (!"project".equals(pom.getLocalName()) || !"http://maven.apache.org/POM/4.0.0".equals(pom.getNamespaceURI()))
            throw new IllegalArgumentException("POM publicado inválido.");
        Element parent = child(pom, "parent");
        String group = text(pom, "groupId"), release = text(pom, "version");
        if (group.isEmpty()) group = text(parent, "groupId");
        if (release.isEmpty()) release = text(parent, "version");
        if (!group.equals(groupId) || !text(pom, "artifactId").equals(artifactId) || !release.equals(version))
            throw new IllegalArgumentException("El POM publicado no coincide con la versión instalada.");
        poms.add(pom);
        Element declaration = child(pom, "scm");
        var ownProperties = properties(pom);
        for (String prefix : List.of("project.", "pom.")) {
            ownProperties.put(prefix + "groupId", groupId);
            ownProperties.put(prefix + "artifactId", artifactId);
            ownProperties.put(prefix + "version", version);
            for (String field : List.of("groupId", "artifactId", "version"))
                ownProperties.put(prefix + "parent." + field, text(parent, field));
        }
        boolean complete = true;
        for (String field : List.of("url", "connection", "developerConnection")) {
            String value = interpolate(text(declaration, field), ownProperties, Set.of());
            if (value.isEmpty() || value.contains("${")) complete = false;
        }
        if (!complete && parent != null)
            publishedPoms(text(parent, "groupId"), text(parent, "artifactId"), text(parent, "version"), deadline, evidence, poms, seen);
    }
    private static Map<String, String> properties(Element pom) {
        var result = new HashMap<String, String>();
        Element values = child(pom, "properties");
        if (values != null) for (var entry = values.getFirstChild(); entry != null; entry = entry.getNextSibling())
            if (entry instanceof Element property && Objects.equals(pom.getNamespaceURI(), property.getNamespaceURI())) {
                if (result.size() >= 256 || property.getTextContent().length() > 8192)
                    throw new IllegalArgumentException("Propiedades Maven superiores al límite de salud.");
                result.put(property.getLocalName(), property.getTextContent().strip());
            }
        return result;
    }
    private static String interpolate(String value, Map<String, String> properties, Set<String> profileProperties) {
        if (value.length() > 8192) return "${limite}";
        var pattern = java.util.regex.Pattern.compile("\\$\\{([^{}]+)}");
        for (int round = 0; round < 16 && value.contains("${"); round++) {
            var matcher = pattern.matcher(value);
            var next = new StringBuilder();
            while (matcher.find()) {
                String key = matcher.group(1), replacement = properties.get(key);
                // Model/environment variables must never be impersonated by a POM property.
                if (key.matches("(?:project|pom|env|settings|java|os|user)\\..*") || key.equals("basedir"))
                    if (!key.matches("(?:project|pom)\\.(?:groupId|artifactId|version|parent\\.(?:groupId|artifactId|version))")) return value;
                if (profileProperties.contains(key) || replacement == null) return value;
                matcher.appendReplacement(next, java.util.regex.Matcher.quoteReplacement(replacement));
                if (next.length() > 8192) return "${limite}";
            }
            matcher.appendTail(next);
            if (next.length() > 8192) return "${limite}";
            String expanded = next.toString();
            if (expanded.equals(value)) break;
            value = expanded;
        }
        return value;
    }
    private static HealthAssessment absentReport(String purl, Evidence<RepositoryAssociation> association, String source, Instant time, String date, EvidenceStatus status, List<Evidence<String>> evidence, String reason) {
        Map<String, Evidence<Indicator>> checks = new LinkedHashMap<>();
        HealthAssessment.CHECKS.forEach(name -> checks.put(name, observation(source, time, date, status, reason)));
        return new HealthAssessment(purl, association, observation(source, time, date, status, reason), checks, evidence);
    }
    private static <T> Evidence<T> observation(String source, Instant time, String date, EvidenceStatus status, String reason) {
        return new Evidence<>(source, time, date, status, null, reason);
    }
    private static String required(JsonNode node, String field) {
        if (!node.path(field).isString() || node.path(field).asString().isBlank()) throw new IllegalArgumentException("Metadatos Scorecard incompletos.");
        return node.path(field).asString();
    }
    private static boolean coordinate(String value) {
        return value != null && value.matches("[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}") && !value.contains("..");
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static String repository(String value) {
        if (value == null || value.contains("${")) return null;
        value = value.strip().replaceFirst("^scm:git:", "");
        value = value.replaceFirst("^git@((?:github\\.com|gitlab\\.com|bitbucket\\.org)):", "https://$1/");
        if (value.matches("(?:github\\.com|gitlab\\.com|bitbucket\\.org)/.*")) value = "https://" + value;
        try {
            URI uri = URI.create(value);
            if (!Set.of("https", "http", "git", "ssh").contains(uri.getScheme()) || uri.getHost() == null
                || !Set.of("github.com", "gitlab.com", "bitbucket.org").contains(uri.getHost().toLowerCase(Locale.ROOT))
                || uri.getPort() != -1 || uri.getQuery() != null || uri.getFragment() != null
                || (uri.getUserInfo() != null && !(uri.getScheme().equals("ssh") && uri.getUserInfo().equals("git")))) return null;
            String path = uri.getPath().replaceFirst("/$", "").replaceFirst("\\.git$", "");
            if (!path.matches("/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+") || path.endsWith("/.") || path.endsWith("/..")) return null;
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            return host + (host.equals("github.com") ? path.toLowerCase(Locale.ROOT) : path);
        } catch (RuntimeException error) { return null; }
    }
    private static Element child(Element element, String name) {
        if (element != null) for (var node = element.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element child && name.equals(child.getLocalName()) && Objects.equals(element.getNamespaceURI(), child.getNamespaceURI())) return child;
        return null;
    }
    private static String text(Element element, String name) { Element found = child(element, name); return found == null ? "" : found.getTextContent().strip(); }
    private static HealthAssessment unavailable(String purl, String source, Instant time, EvidenceStatus status, List<Evidence<String>> evidence, String reason) {
        return absentReport(purl, observation(source, time, null, status, reason), source, time, null, status, evidence, reason);
    }
    private static long size(HealthAssessment assessment) {
        return assessment.associationEvidence().stream().filter(value -> value.value() != null)
            .mapToLong(value -> value.value().getBytes(StandardCharsets.UTF_8).length).sum();
    }
}
