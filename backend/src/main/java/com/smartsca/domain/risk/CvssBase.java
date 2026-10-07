package com.smartsca.domain.risk;
import com.smartsca.domain.vulnerability.Advisory.CvssScore;
import java.util.*;
import us.springett.cvss.Cvss;

/** Strict base-vector projection: temporal/environmental/threat metrics never enter a base score. */
final class CvssBase {
    // FIRST vector tables: validate complete values, including optional metrics that the calculator may ignore.
    private static final Map<String, List<String>> V2 = allowed("AV:L,A,N AC:H,M,L Au:M,S,N C:N,P,C I:N,P,C A:N,P,C "
        + "E:U,POC,F,H,ND RL:OF,TF,W,U,ND RC:UC,UR,C,ND CDP:N,L,LM,MH,H,ND TD:N,L,M,H,ND CR:L,M,H,ND IR:L,M,H,ND AR:L,M,H,ND");
    private static final Map<String, List<String>> V3 = allowed("AV:N,A,L,P AC:L,H PR:N,L,H UI:N,R S:U,C C:N,L,H I:N,L,H A:N,L,H "
        + "E:X,U,P,F,H RL:X,O,T,W,U RC:X,U,R,C CR:X,L,M,H IR:X,L,M,H AR:X,L,M,H "
        + "MAV:X,N,A,L,P MAC:X,L,H MPR:X,N,L,H MUI:X,N,R MS:X,U,C MC:X,N,L,H MI:X,N,L,H MA:X,N,L,H");
    private static final Map<String, List<String>> V4 = allowed("AV:N,A,L,P AC:L,H AT:N,P PR:N,L,H UI:N,P,A VC:H,L,N VI:H,L,N VA:H,L,N SC:H,L,N SI:H,L,N SA:H,L,N "
        + "E:X,A,P,U CR:X,H,M,L IR:X,H,M,L AR:X,H,M,L MAV:X,N,A,L,P MAC:X,L,H MAT:X,N,P MPR:X,N,L,H MUI:X,N,P,A "
        + "MVC:X,N,L,H MVI:X,N,L,H MVA:X,N,L,H MSC:X,N,L,H MSI:X,N,L,H,S MSA:X,N,L,H,S "
        + "S:X,N,P AU:X,N,Y R:X,A,U,I V:X,D,C RE:X,L,M,H U:X,Clear,Green,Amber,Red");
    private static Map<String, List<String>> allowed(String definition) {
        var result = new LinkedHashMap<String, List<String>>();
        for (String entry : definition.split(" ")) {
            String[] pair = entry.split(":");
            result.put(pair[0], List.of(pair[1].split(",")));
        }
        return Collections.unmodifiableMap(result);
    }
    static double score(CvssScore value) {
        String vector = value.vector();
        if (vector == null || vector.length() > 1024) throw new IllegalArgumentException("Vector CVSS ausente o demasiado largo.");
        String prefix = vector.startsWith("CVSS:") ? vector.substring(0, vector.indexOf('/')) : "";
        String version = prefix.isEmpty() ? "2.0" : prefix.substring(5);
        if (!version.equals(value.version())) throw new IllegalArgumentException("Versión y vector CVSS no coinciden.");
        List<String> keys = switch (version) {
            case "2.0" -> List.of("AV", "AC", "Au", "C", "I", "A");
            case "3.0", "3.1" -> List.of("AV", "AC", "PR", "UI", "S", "C", "I", "A");
            case "4.0" -> List.of("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA");
            default -> throw new IllegalArgumentException("Versión CVSS no soportada.");
        };
        var allowed = version.equals("2.0") ? V2 : version.equals("4.0") ? V4 : V3;
        var positions = new ArrayList<>(allowed.keySet());
        int previous = -1;
        var metrics = new HashMap<String, String>();
        String body = prefix.isEmpty() ? vector : vector.substring(prefix.length() + 1);
        for (String part : body.split("/", -1)) {
            String[] pair = part.split(":", -1);
            if (pair.length != 2 || !allowed.containsKey(pair[0]) || !allowed.get(pair[0]).contains(pair[1]) || metrics.putIfAbsent(pair[0], pair[1]) != null)
                throw new IllegalArgumentException("Métrica CVSS inválida o duplicada.");
            int position = positions.indexOf(pair[0]);
            if (version.equals("4.0") && position <= previous) throw new IllegalArgumentException("Orden CVSS 4.0 inválido.");
            previous = position;
        }
        // The complete vector was validated above; the library only calculates its base projection.
        String base = keys.stream().map(key -> {
            if (!metrics.containsKey(key)) throw new IllegalArgumentException("Vector CVSS incompleto.");
            return key + ":" + metrics.get(key);
        }).collect(java.util.stream.Collectors.joining("/"));
        var parsed = Cvss.fromVector(version.equals("2.0") ? base : prefix + "/" + base);
        double score = parsed.calculateScore().getBaseScore();
        if (!Double.isFinite(score) || score < 0 || score > 10) throw new IllegalArgumentException("CVSS fuera de escala.");
        return score;
    }
}
