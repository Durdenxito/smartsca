package com.smartsca.configuration;

import com.smartsca.SmartScaApplication;
import com.smartsca.adapter.outbound.maven.FixtureProjectSource;
import com.smartsca.adapter.outbound.persistence.JpaAnalysisRepository;
import com.smartsca.application.port.inbound.*;
import com.smartsca.application.port.outbound.*;
import com.smartsca.application.service.*;
import jakarta.persistence.EntityManager;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.smartsca.adapter.outbound.maven.MavenDependencyResolver;
import com.smartsca.adapter.inbound.job.AnalysisWorker;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import java.time.Duration;

/** Connects the pure application core with its concrete adapters. */
@Configuration @EnableScheduling
public class AnalysisConfigurationBeans {
    @Bean ProjectSource projects(@Value("${smartsca.fixtures-root}") String root) {
        return new FixtureProjectSource(Path.of(root));
    }
    @Bean AnalysisRepository analyses(EntityManager manager) { return new JpaAnalysisRepository(manager); }
    @Bean StartAnalysisUseCase startAnalysis(ProjectSource projects, AnalysisRepository analyses) {
        String version = SmartScaApplication.class.getPackage().getImplementationVersion();
        return new StartAnalysisService(projects, analyses, version == null ? "development" : version);
    }
    @Bean QueryAnalysisService queryAnalysis(AnalysisRepository analyses) { return new QueryAnalysisService(analyses); }
    @Bean SbomExporter sbomExporter() { return new com.smartsca.adapter.outbound.sbom.CycloneDxSbomExporter(); }
    @Bean ExportAnalysisUseCase exportAnalysis(AnalysisRepository analyses) { return new ExportAnalysisService(analyses); }
    @Bean DependencyResolver dependencyResolver(@Value("${smartsca.fixtures-root}") String root,
                                                @Value("${smartsca.maven.timeout-seconds:180}") long seconds) {
        return new MavenDependencyResolver(new FixtureProjectSource(Path.of(root)), Duration.ofSeconds(seconds));
    }
    @Bean com.smartsca.adapter.outbound.ExternalJsonClient externalJson(@Value("${smartsca.enrichment.enabled:true}") boolean enabled) {
        return new com.smartsca.adapter.outbound.ExternalJsonClient(enabled);
    }
    @Bean VulnerabilitySource vulnerabilitySource(com.smartsca.adapter.outbound.ExternalJsonClient http) {
        return new com.smartsca.adapter.outbound.osv.OsvApiAdapter(http);
    }
    @Bean ExploitSignalsSource exploitSignals(com.smartsca.adapter.outbound.ExternalJsonClient http) {
        var epss = new com.smartsca.adapter.outbound.epss.EpssApiAdapter(http);
        var kev = new com.smartsca.adapter.outbound.kev.KevCatalogAdapter(http);
        return new ExploitSignalsSource() {
            public java.util.Map<String, com.smartsca.domain.Evidence<com.smartsca.domain.vulnerability.Vulnerability.Epss>> epss(java.util.Set<String> cves) { return epss.lookup(cves); }
            public java.util.Map<String, com.smartsca.domain.Evidence<Boolean>> kev(java.util.Set<String> cves) { return kev.lookup(cves); }
        };
    }
    @Bean EnrichAnalysisService enrichment(VulnerabilitySource vulnerabilities, ExploitSignalsSource signals) {
        return new EnrichAnalysisService(vulnerabilities, signals);
    }
    @Bean HealthSource healthSource(com.smartsca.adapter.outbound.ExternalJsonClient http) {
        return new com.smartsca.adapter.outbound.scorecard.ScorecardHealthAdapter(http);
    }
    @Bean(destroyMethod = "close") RunAnalysisService runAnalysis(AnalysisRepository analyses, DependencyResolver resolver, EnrichAnalysisService enrichment,
                                                               HealthSource health, SbomExporter sbom,
                                                               @Value("${smartsca.worker.concurrency:1}") int concurrency) {
        return new RunAnalysisService(analyses, resolver, enrichment, health, sbom, concurrency, MavenDependencyResolver.VERSIONS);
    }
    @Bean @ConditionalOnProperty(name = "smartsca.worker.enabled", havingValue = "true", matchIfMissing = true)
    AnalysisWorker worker(RunPendingAnalysesUseCase useCase) { return new AnalysisWorker(useCase); }
}
