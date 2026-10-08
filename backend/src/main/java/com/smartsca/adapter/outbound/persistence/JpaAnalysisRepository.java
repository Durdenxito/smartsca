package com.smartsca.adapter.outbound.persistence;

import com.smartsca.application.port.outbound.AnalysisRepository;
import com.smartsca.application.port.inbound.ListAnalysesUseCase;
import com.smartsca.application.port.inbound.GetAnalysisUseCase;
import com.smartsca.domain.component.DependencyGraph;
import com.smartsca.domain.health.HealthAssessment;
import com.smartsca.domain.vulnerability.VulnerabilitySnapshot;
import java.util.List;
import java.util.Map;
import com.smartsca.domain.analysis.AnalysisConfiguration;
import java.util.Set;
import java.util.Arrays;
import com.smartsca.domain.analysis.Analysis;
import com.smartsca.domain.analysis.AnalysisArtifact;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.annotation.Transactional;
import com.smartsca.domain.analysis.AnalysisStatus;
import java.time.Instant;

/** Transactional persistence adapter; no JPA objects cross its outbound port. */
public class JpaAnalysisRepository implements AnalysisRepository {
    private final EntityManager manager;
    public JpaAnalysisRepository(EntityManager manager) { this.manager = manager; }
    @Override @Transactional public void save(Analysis analysis) { manager.persist(AnalysisEntity.from(analysis)); }
    @Override @Transactional(readOnly = true) public Optional<Analysis> get(UUID id) {
        return Optional.ofNullable(manager.find(AnalysisEntity.class, id)).map(AnalysisEntity::toDomain);
    }
    private Optional<Object[]> row(String columns, UUID id) {
        return manager.createQuery("select " + columns + " from AnalysisEntity e where e.id = :id", Object[].class)
            .setParameter("id", id).getResultList().stream().findFirst();
    }
    @SuppressWarnings("unchecked")
    @Override @Transactional(readOnly = true) public Optional<GetAnalysisUseCase.Status> readStatus(UUID id) {
        return row("""
            e.projectName, e.modules, e.profiles, e.scopes, e.environmentId, e.declaredDeployment,
            e.status, e.currentStep, e.createdAt, e.startedAt, e.finishedAt, e.diagnostics, e.environmentVersions,
            e.dependencyGraph is not null, e.vulnerabilitySnapshot is not null
            """, id).map(value -> new GetAnalysisUseCase.Status(id, (String) value[0],
                new AnalysisConfiguration(Set.copyOf(Arrays.asList((String[]) value[1])), Set.copyOf(Arrays.asList((String[]) value[2])),
                    Set.copyOf(Arrays.asList((String[]) value[3])), (String) value[4], (String) value[5]),
                (AnalysisStatus) value[6], (String) value[7], (Instant) value[8], (Instant) value[9], (Instant) value[10],
                List.copyOf(Arrays.asList((String[]) value[11])), (Map<String, String>) value[12], (Boolean) value[13], (Boolean) value[14]));
    }
    private static GetAnalysisUseCase.Resolution resolution(Object[] value) {
        return new GetAnalysisUseCase.Resolution((String) value[0], (AnalysisStatus) value[1],
            Set.copyOf(Arrays.asList((String[]) value[2])), (DependencyGraph) value[3]);
    }
    @Override @Transactional(readOnly = true) public Optional<GetAnalysisUseCase.Resolution> readResolution(UUID id) {
        return row("e.projectName, e.status, e.scopes, e.dependencyGraph", id).map(JpaAnalysisRepository::resolution);
    }
    @SuppressWarnings("unchecked")
    @Override @Transactional(readOnly = true) public Optional<GetAnalysisUseCase.Sources> readSources(UUID id) {
        return row("e.vulnerabilitySnapshot, e.healthAssessments", id).map(value ->
            new GetAnalysisUseCase.Sources((VulnerabilitySnapshot) value[0], (Map<String, HealthAssessment>) value[1]));
    }
    @SuppressWarnings("unchecked")
    @Override @Transactional(readOnly = true) public Optional<InventorySnapshot> readInventory(UUID id) {
        return row("e.projectName, e.status, e.scopes, e.dependencyGraph, e.healthAssessments, e.vulnerabilitySnapshot is not null", id)
            .map(value -> new InventorySnapshot(resolution(value), (Map<String, HealthAssessment>) value[4], (Boolean) value[5]));
    }
    @Override @Transactional(readOnly = true) public ListAnalysesUseCase.Page list(String projectId, AnalysisStatus status, int offset) {
        var query = manager.createQuery("""
            select e.id, e.projectId, e.projectName, e.sourceReference, e.analyzedReference,
                   e.modules, e.profiles, e.scopes, e.environmentId, e.declaredDeployment,
                   e.status, e.createdAt, e.startedAt, e.finishedAt
            from AnalysisEntity e
            """ + (projectId != null || status != null ? " where " : "")
            + (projectId != null ? "e.projectId = :project" : "")
            + (projectId != null && status != null ? " and " : "")
            + (status != null ? "e.status = :status" : "")
            + " order by e.createdAt desc, e.id desc", Object[].class);
        if (projectId != null) query.setParameter("project", projectId);
        if (status != null) query.setParameter("status", status);
        var rows = query.setFirstResult(offset).setMaxResults(ListAnalysesUseCase.PAGE_SIZE + 1).getResultList();
        var items = rows.stream().limit(ListAnalysesUseCase.PAGE_SIZE).map(row ->
            new ListAnalysesUseCase.Entry((UUID) row[0], (String) row[1], (String) row[2], (String) row[3], (String) row[4],
                new AnalysisConfiguration(Set.copyOf(Arrays.asList((String[]) row[5])),
                    Set.copyOf(Arrays.asList((String[]) row[6])), Set.copyOf(Arrays.asList((String[]) row[7])), (String) row[8], (String) row[9]),
                (AnalysisStatus) row[10], (Instant) row[11], (Instant) row[12], (Instant) row[13])).toList();
        boolean more = rows.size() > ListAnalysesUseCase.PAGE_SIZE;
        int next = offset + ListAnalysesUseCase.PAGE_SIZE;
        boolean limited = more && next > ListAnalysesUseCase.MAX_OFFSET;
        return new ListAnalysesUseCase.Page(items, offset, more && !limited ? next : null, limited);
    }
    @Override @Transactional public Optional<Analysis> claimNextPending() {
        var ids = manager.createNativeQuery("""
            WITH next AS (SELECT id FROM analyses WHERE status = 'EN_COLA' ORDER BY created_at, id
                          FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE analyses SET status = 'EN_EJECUCION', current_step = 'RESOLVIENDO_MAVEN', started_at = CURRENT_TIMESTAMP
            FROM next WHERE analyses.id = next.id RETURNING analyses.id
            """, UUID.class).getResultList();
        manager.clear();
        return ids.isEmpty() ? Optional.empty() : Optional.of(manager.find(AnalysisEntity.class, ids.getFirst()).toDomain());
    }
    @Override @Transactional public void updateStep(UUID id, String step) {
        manager.createQuery("update AnalysisEntity set currentStep = :step where id = :id and status = :status")
            .setParameter("step", step).setParameter("id", id).setParameter("status", AnalysisStatus.EN_EJECUCION).executeUpdate();
        manager.clear();
    }
    @Override @Transactional(readOnly = true) public Optional<AnalysisArtifact> readSbom(UUID id) {
        return Optional.ofNullable(manager.find(AnalysisArtifactEntity.class, id)).map(AnalysisArtifactEntity::toDomain);
    }
    @Override @Transactional public void finish(Analysis analysis) { finish(analysis, null); }
    @Override @Transactional public void finish(Analysis analysis, AnalysisArtifact sbom) {
        var entity = manager.find(AnalysisEntity.class, analysis.id(), jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
        if (entity == null) throw new IllegalStateException("El trabajo no existe.");
        // A committed write may lose its acknowledgement; retry without replacing an existing terminal result.
        if (entity.status != AnalysisStatus.EN_EJECUCION) {
            if (entity.status == AnalysisStatus.EN_COLA) throw new IllegalStateException("El trabajo todavía no está en ejecución.");
            return;
        }
        entity.status = analysis.status();
        entity.currentStep = analysis.currentStep();
        entity.finishedAt = analysis.finishedAt();
        entity.diagnostics = analysis.diagnostics().toArray(String[]::new);
        entity.environmentVersions = analysis.environmentVersions();
        entity.dependencyGraph = analysis.dependencyGraph();
        entity.vulnerabilitySnapshot = analysis.vulnerabilitySnapshot();
        entity.healthAssessments = analysis.healthAssessments();
        entity.riskSnapshot = analysis.riskSnapshot();
        if (sbom != null) manager.persist(AnalysisArtifactEntity.from(analysis.id(), sbom));
    }
    @Override @Transactional public void failInterrupted() {
        // ponytail: one backend process; add owner leases before running multiple replicas.
        manager.createNativeQuery("""
            UPDATE analyses SET status='FALLIDO', current_step='INTERRUMPIDO', finished_at=CURRENT_TIMESTAMP,
            diagnostics=ARRAY['La ejecución se interrumpió al reiniciar el servidor. Inicia un nuevo análisis.']::text[]
            WHERE status='EN_EJECUCION'
            """).executeUpdate();
        manager.clear();
    }
}
