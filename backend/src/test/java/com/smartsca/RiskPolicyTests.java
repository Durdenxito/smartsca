package com.smartsca;

import com.smartsca.domain.*;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import com.smartsca.domain.component.*;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.risk.*;
import com.smartsca.domain.vulnerability.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/** Twenty predeclared rule scenarios; fixed observations, no live provider or model-fitting claims. */
class RiskPolicyTests {
    static final Component A = new Component("pkg:maven/demo/library@1", "maven", "demo:library", "1", Map.of());
    static final String HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    static final String LOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    static final String V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    static <T> Evidence<T> available(T value) { return Evidence.available("https://reference.test/", Instant.parse("2026-10-07T00:00:00Z"), "2026-10-06", value); }
    static <T> Evidence<T> absent() { return new Evidence<>("https://reference.test/", Instant.parse("2026-10-07T00:00:00Z"), null, EvidenceStatus.ERROR, null, "Source failure"); }
    static class Fixture {
        String vector = HIGH, version = "3.1", scope = "compile";
        boolean known, noCve, badEpss, badKev, badOsv, missingHealth, stale, ambiguous, badCheck, duplicate, transitive, specific, unrelated;
        int healthScore = 5;
        double probability = .5;
        List<Advisory.CvssScore> extra = List.of();
        RiskSnapshot snapshot() {
            var cvss = available(List.of(new Advisory.CvssScore(version, vector, "NVD")));
            var affected = specific || unrelated ? List.of(new Advisory.AffectedPackage("Maven", unrelated ? "demo:other" : A.name(), "[]", List.of(), List.of(), cvss)) : List.<Advisory.AffectedPackage>of();
            var global = specific || unrelated ? available(List.of(new Advisory.CvssScore("3.1", LOW, "CNA")))
                : available(Stream.concat(cvss.value().stream(), extra.stream()).toList());
            var advisory = new Advisory("GHSA-demo", Set.of(), "Reference", "Reference", List.of(), affected, global, "{}");
            Evidence<Map<String, Evidence<Vulnerability.Epss>>> epss = noCve ? new Evidence<>("EPSS", Instant.EPOCH, null, EvidenceStatus.NO_APLICABLE, null, "Sin CVE")
                : available(Map.of("CVE-2026-1234", badEpss ? RiskPolicyTests.<Vulnerability.Epss>absent() : available(new Vulnerability.Epss(probability, .9))));
            Evidence<Map<String, Evidence<Boolean>>> kev = noCve ? new Evidence<>("KEV", Instant.EPOCH, null, EvidenceStatus.NO_APLICABLE, null, "Sin CVE")
                : available(Map.of("CVE-2026-1234", badKev ? RiskPolicyTests.<Boolean>absent() : available(known)));
            var vulnerability = new Vulnerability(noCve ? "GHSA-demo" : "CVE-2026-1234", noCve ? Set.of("GHSA-demo") : Set.of("CVE-2026-1234", "GHSA-demo"), Map.of("GHSA-demo", available(advisory)), epss, kev);
            var finding = new Finding(A.purl(), vulnerability.id());
            var snapshot = new VulnerabilitySnapshot(duplicate ? List.of(finding, finding) : List.of(finding), List.of(vulnerability), Map.of(A.purl(), badOsv ? absent() : available(List.of("GHSA-demo"))));
            var root = new Component("root", "maven", "demo:root", "1", Map.of());
            var middle = new Component("middle", "maven", "demo:middle", "1", Map.of());
            var graph = new DependencyGraph(Map.of(".", root.purl()), Map.of(A.purl(), A, "root", root, "middle", middle), transitive
                ? Set.of(new DependencyEdge("root", "middle", new DependencyContext(".", scope, scope)), new DependencyEdge("middle", A.purl(), new DependencyContext(".", scope, scope)))
                : Set.of(new DependencyEdge("root", A.purl(), new DependencyContext(".", scope, scope))));
            var indicators = new HashMap<String, Evidence<HealthAssessment.Indicator>>();
            HealthAssessment.CHECKS.forEach(name -> indicators.put(name, badCheck && name.equals("Code-Review") ? absent()
                : available(new HealthAssessment.Indicator(name, healthScore, "Reference", List.of(), "https://example.test/"))));
            var health = new HealthAssessment(A.purl(), ambiguous ? absent() : available(new HealthAssessment.RepositoryAssociation("github.com/demo/library", "REFERENCE")),
                available(new HealthAssessment.ScorecardReport("github.com/demo/library", "abc", "v5", "tool", stale, "scorecard-age-v1-90d")), indicators, List.of());
            return new RiskPolicy().evaluate(snapshot, graph, new AnalysisConfiguration(Set.of("."), Set.of(), Set.of(scope), "java-21", null), missingHealth ? Map.of() : Map.of(A.purl(), health));
        }
        RiskAssessment result() { return snapshot().assessments().getFirst(); }
    }
    static void pending(Fixture fixture) { var result = fixture.result(); assertEquals(RiskEvaluationStatus.PENDIENTE_REVISION, result.status()); assertNull(result.score()); assertNull(result.level()); }
    @TestFactory Stream<DynamicTest> twentyRules() {
        return Stream.of(
            DynamicTest.dynamicTest("01 complete weighted score", () -> { var f = new Fixture(); assertEquals(84d, f.result().score()); assertEquals(PriorityLevel.ALTA, f.result().level()); assertEquals(0d, f.result().contributions().stream().filter(value -> value.dimension().equals("KEV")).findFirst().orElseThrow().points()); }),
            DynamicTest.dynamicTest("02 KEV floor and precedence", () -> { var f = new Fixture(); f.known = true; assertEquals(90d, f.result().score()); assertTrue(f.result().knownExploited()); assertEquals(PriorityLevel.CRITICA, f.result().level()); }),
            DynamicTest.dynamicTest("03 missing EPSS is pending", () -> { var f = new Fixture(); f.badEpss = true; pending(f); }),
            DynamicTest.dynamicTest("04 missing KEV is not false", () -> { var f = new Fixture(); f.badKev = true; pending(f); assertFalse(f.result().knownExploited()); }),
            DynamicTest.dynamicTest("05 unavailable OSV is pending", () -> { var f = new Fixture(); f.badOsv = true; pending(f); }),
            DynamicTest.dynamicTest("06 missing health is pending", () -> { var f = new Fixture(); f.missingHealth = true; pending(f); }),
            DynamicTest.dynamicTest("07 stale health is pending", () -> { var f = new Fixture(); f.stale = true; pending(f); }),
            DynamicTest.dynamicTest("08 ambiguous repository is pending", () -> { var f = new Fixture(); f.ambiguous = true; pending(f); }),
            DynamicTest.dynamicTest("09 missing check is pending", () -> { var f = new Fixture(); f.badCheck = true; pending(f); }),
            DynamicTest.dynamicTest("10 malformed CVSS is pending", () -> { var f = new Fixture(); f.vector = "CVSS:3.1/AV:N"; pending(f); }),
            DynamicTest.dynamicTest("11 duplicate metric is pending", () -> { var f = new Fixture(); f.vector = HIGH + "/AV:N"; pending(f); }),
            DynamicTest.dynamicTest("12 no CVE renormalizes applicable weights", () -> { var f = new Fixture(); f.noCve = true; assertEquals(92.5, f.result().score()); }),
            DynamicTest.dynamicTest("13 test scope context documented", () -> { var f = new Fixture(); f.scope = "test"; assertEquals(74d, f.result().score()); }),
            DynamicTest.dynamicTest("14 transitivity never discounts", () -> { var a = new Fixture(); var b = new Fixture(); b.transitive = true; assertEquals(a.result().score(), b.result().score()); }),
            DynamicTest.dynamicTest("15 CVSS increase never lowers score", () -> { var high = new Fixture(); var low = new Fixture(); low.vector = LOW; assertTrue(high.result().score() > low.result().score()); }),
            DynamicTest.dynamicTest("16 health zero is real", () -> { var f = new Fixture(); f.healthScore = 0; assertEquals(89d, f.result().score()); }),
            DynamicTest.dynamicTest("17 EPSS zero is real", () -> { var f = new Fixture(); f.probability = 0; assertEquals(74d, f.result().score()); }),
            DynamicTest.dynamicTest("18 aliases do not multiply assessments", () -> { var f = new Fixture(); f.duplicate = true; assertEquals(1, f.snapshot().assessments().size()); }),
            DynamicTest.dynamicTest("19 package CVSS scope wins", () -> { var f = new Fixture(); f.specific = true; assertEquals(84d, f.result().score()); f.specific = false; f.unrelated = true; assertEquals(61.5, f.result().score()); }),
            DynamicTest.dynamicTest("20 newest base version and threat projection", () -> { var f = new Fixture(); f.extra = List.of(new Advisory.CvssScore("4.0", V4 + "/E:U", "CNA")); var score = f.result().score(); assertNotNull(score); assertTrue(f.result().explanation().getFirst().contains("versión 4.0")); f.extra = List.of(new Advisory.CvssScore("4.0", V4, "CNA")); assertEquals(score, f.result().score()); })
        );
    }
    @Test void deterministicOrderingKeepsKnownExploitationAndUnknownsAheadOfScores() {
        var evaluated = new Fixture().result(); var f = new Fixture(); f.badEpss = true; var pending = f.result();
        f.known = true; var knownPending = f.result(); f.badEpss = false; var knownEvaluated = f.result();
        assertEquals(List.of(knownPending, knownEvaluated, pending, evaluated), Stream.of(evaluated, knownEvaluated, pending, knownPending).sorted(RiskPolicy.order()).toList());
        assertThrows(UnsupportedOperationException.class, () -> new Fixture().snapshot().policy().weights().put("CVSS", 0d));
        assertThrows(UnsupportedOperationException.class, () -> evaluated.contributions().clear());
    }
    @Test void legacyBaseVectorsAndUnknownMetricsRemainExplicit() {
        var f = new Fixture(); f.version = "2.0"; f.vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
        assertEquals(85d, f.result().score());
        f.version = "3.0"; f.vector = HIGH.replace("3.1", "3.0");
        assertEquals(84d, f.result().score());
        f.vector = f.vector.replace("AV:N", "AV:Z"); pending(f);
    }
    @Test void completeMetricValuesAndValidOptionalMetricsAreCheckedBeforeProjection() {
        var f = new Fixture(); f.vector = HIGH.replace("AV:N", "AV:NETWORK"); pending(f);
        f.version = "3.0"; f.vector = HIGH.replace("3.1", "3.0") + "/MAV:Z"; pending(f);
        f.vector = HIGH.replace("3.1", "3.0") + "/MAV:L/E:U"; assertEquals(84d, f.result().score());
        f.version = "3.1"; f.vector = HIGH + "/UNKNOWN:X"; pending(f);
        f.vector = HIGH + "/MAV:X/E:X"; assertEquals(84d, f.result().score());
        f.version = "2.0"; f.vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/CDP:LM"; assertEquals(85d, f.result().score());
        f.vector = f.vector.replace("E:POC", "E:POCEXTRA"); pending(f);
        f.version = "4.0"; f.vector = V4; var base = f.result().score();
        f.vector = V4 + "/E:U/MSI:S/U:Amber"; assertEquals(base, f.result().score());
        f.vector = V4 + "/U:Amber/E:U"; pending(f);
        f.vector = V4.replace("SI:N", "SI:S"); pending(f);
    }
}
