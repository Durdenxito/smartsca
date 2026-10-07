package com.smartsca;

import com.smartsca.adapter.outbound.maven.MavenTreeParser;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MavenTreeParserTests {
    @Test void preservesEffectiveScopesAndOmittedParentsAndRejectsDanglingEdges() {
        String json = """
            {"groupId":"sample","artifactId":"root","type":"jar","version":"1",
             "children":[{"groupId":"junit","artifactId":"junit","type":"jar","version":"4.13.2","scope":"test",
               "children":[{"groupId":"org.hamcrest","artifactId":"hamcrest-core","type":"jar","version":"1.3","scope":"test"}]}]}
            """;
        String tgf = """
            1 sample:root:jar:1
            2 junit:junit:jar:4.13.2:test
            3 org.hamcrest:hamcrest-core:jar:1.3:test
            4 (org.hamcrest:hamcrest-core:jar:1.3:test - omitted for duplicate)
            5 (junit:junit:jar:4.12:test - omitted for conflict with 4.13.2)
            #
            1 2 test
            2 3 test
            1 4 test
            4 5 test
            """;
        var parser = new MavenTreeParser();
        var graph = parser.parse(Map.of(".", new MavenTreeParser.Tree(json, tgf)), AnalysisConfiguration.SUPPORTED_SCOPES);
        assertEquals(4, graph.edges().size());
        assertEquals(3, graph.components().size());
        var occurrences = graph.contextsOf("pkg:maven/org.hamcrest/hamcrest-core@1.3");
        assertTrue(occurrences.stream().allMatch(occurrence -> occurrence.scope().equals("test")));
        assertTrue(occurrences.stream().anyMatch(occurrence -> !occurrence.direct()));
        assertTrue(occurrences.stream().anyMatch(occurrence -> occurrence.direct()));
        assertTrue(graph.edges().stream().anyMatch(edge -> edge.parentPurl().endsWith("hamcrest-core@1.3")
            && edge.childPurl().equals("pkg:maven/junit/junit@4.13.2")));
        assertThrows(IllegalArgumentException.class, () -> parser.parse(
            Map.of(".", new MavenTreeParser.Tree(json, tgf + "3 99 test\n")), AnalysisConfiguration.SUPPORTED_SCOPES));
    }
}
