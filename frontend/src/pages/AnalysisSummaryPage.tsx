import { useEffect, useState } from 'react';
import { request, errorMessage, type Analysis, type ComponentItem, type RiskAssessment } from '../api/client';
import AnalysisNotice from '../components/AnalysisNotice';
import SourceAvailability from '../components/SourceAvailability';

const levels = ['CRITICA', 'ALTA', 'MEDIA', 'BAJA', 'PENDIENTE_REVISION'] as const;
const checks = ['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'];
const key = (finding: RiskAssessment['finding']) => JSON.stringify([finding.componentPurl, finding.vulnerabilityId]);

/** Counts the saved snapshot; neither providers nor the priority policy run when this view is opened. */
export default function AnalysisSummaryPage({ id }: { id: string }) {
  const [analysis, setAnalysis] = useState<Analysis>();
  const [components, setComponents] = useState<ComponentItem[]>();
  const [error, setError] = useState('');
  const [inventoryError, setInventoryError] = useState('');
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setAnalysis(undefined); setComponents(undefined); setError(''); setInventoryError('');
    async function load() {
      try {
        const value = await request<Analysis>(`/analyses/${encodeURIComponent(id)}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setAnalysis(value);
        if (value.dependencyGraph) {
          try {
            const items = await request<ComponentItem[]>(`/analyses/${encodeURIComponent(id)}/components`, { signal: controller.signal });
            if (!controller.signal.aborted) setComponents(items);
          } catch (error) { if (!controller.signal.aborted) setInventoryError(errorMessage(error)); }
        }
      } catch (error) { if (!controller.signal.aborted) setError(errorMessage(error)); }
    }
    void load();
    return () => controller.abort();
  }, [id, retry]);

  const snapshot = analysis?.vulnerabilitySnapshot;
  const findings = snapshot ? [...new Map(snapshot.findings.map(value => [key(value), value])).values()] : undefined;
  const risk = analysis?.riskSnapshot;
  const assessments = new Map(risk?.assessments.map(value => [key(value.finding), value]));
  const priority = (finding: RiskAssessment['finding']) => {
    const value = assessments.get(key(finding));
    return value?.status === 'EVALUADO' && value.score != null && value.level != null ? value.level : 'PENDIENTE_REVISION';
  };
  const pending = findings?.filter(value => priority(value) === 'PENDIENTE_REVISION').length;
  const purls = components ? new Set(components.map(value => value.component.purl)) : undefined;
  const osvAvailable = purls && snapshot ? [...purls].filter(purl => snapshot.componentQueries[purl]?.status === 'DISPONIBLE').length : undefined;
  const advisories = snapshot ? [...new Map(snapshot.vulnerabilities.flatMap(value => Object.entries(value.advisories))).values()] : undefined;
  const detailsAvailable = advisories?.filter(value => value.status === 'DISPONIBLE').length;
  const osvComplete = snapshot != null && purls != null && osvAvailable === purls.size && detailsAvailable === advisories?.length;
  const healthCovered = purls && analysis?.healthAssessments ? [...purls].filter(purl => {
    const value = analysis.healthAssessments![purl];
    return value?.repository.status === 'DISPONIBLE' && value.scorecard.status === 'DISPONIBLE' && !value.scorecard.value?.stale
      && checks.every(name => value.indicators[name]?.status === 'DISPONIBLE');
  }).length : undefined;
  const coverage = (available: number | undefined, total: number | undefined) => available == null || total == null ? 'No disponible' : `${available} de ${total}`;

  return <section aria-labelledby="analysis-summary-title">
    <h1 id="analysis-summary-title">Resumen y cobertura del análisis</h1>
    <p className="identifier">Identificador: <code>{id}</code></p>
    <p><a href={`#analysis/${id}`}>Estado y diagnóstico</a></p>
    {error && <p role="alert" className="error">{error}</p>}
    {!analysis && !error && <p role="status">Consultando resumen guardado…</p>}
    {analysis && <>
      <p>{analysis.project.name} · Estado: {analysis.status}</p>
      <AnalysisNotice status={analysis.status} />
      <p>Scopes seleccionados: {analysis.configuration.scopes.join(', ')}. Las raíces del proyecto no se cuentan como dependencias; la selección corresponde a este análisis.</p>
      {inventoryError && <p role="alert" className="error">No se pudo consultar el inventario: {inventoryError}. Se conservan las demás evidencias del resumen.</p>}
      {analysis.dependencyGraph && !components && !inventoryError && <p role="status">Consultando inventario guardado…</p>}
      <dl aria-label="Totales identificados en la instantánea">
        <dt>Componentes seleccionados</dt><dd>{purls?.size ?? 'No disponible'}</dd>
        <dt>Componentes con hallazgos</dt><dd>{findings ? new Set(findings.map(value => value.componentPurl)).size : 'No disponible'}</dd>
        <dt>Vulnerabilidades únicas identificadas</dt><dd>{findings ? new Set(findings.map(value => value.vulnerabilityId)).size : 'No disponible'}</dd>
        <dt>Hallazgos componente-vulnerabilidad</dt><dd>{findings?.length ?? 'No disponible'}</dd>
        <dt>Pendientes de revisión / sin evaluación</dt><dd>{pending ?? 'No disponible'}</dd>
      </dl>
      <p className="muted">Un mismo aviso correlacionado cuenta una vez como vulnerabilidad; cada componente-versión afectado conserva su propio hallazgo. Aliases y múltiples rutas no multiplican estos totales.</p>
      {!osvComplete && <p className="error">Cobertura OSV incompleta o no disponible. Cero hallazgos identificados no demuestra ausencia de vulnerabilidades.</p>}
      {purls?.size === 0 && <p>No hay dependencias en los scopes seleccionados; no se realizó una evaluación OSV de componentes seleccionados.</p>}
      <div className="table-scroll"><table>
        <caption>Distribución de prioridades guardadas</caption>
        <thead><tr><th scope="col">Prioridad</th><th scope="col">Hallazgos</th></tr></thead>
        <tbody>{levels.map(level => <tr key={level}><th scope="row">{level}</th><td>{findings?.filter(value => priority(value) === level).length ?? 'No disponible'}</td></tr>)}</tbody>
      </table></div>
      <p>{risk ? `Política guardada: ${risk.policy.version}. Los pendientes quedan fuera de los cuatro niveles evaluados.`
        : 'Sin evaluación de prioridad guardada; los hallazgos conocidos quedan pendientes y no se recalculan al consultar.'}</p>
      <div className="table-scroll"><table>
        <caption>Cobertura observada de la instantánea</caption>
        <thead><tr><th scope="col">Aspecto</th><th scope="col">Disponible / total</th></tr></thead>
        <tbody>
          <tr><th scope="row">Consultas OSV por componente</th><td>{coverage(osvAvailable, purls?.size)}</td></tr>
          <tr><th scope="row">Detalles de avisos OSV</th><td>{coverage(detailsAvailable, advisories?.length)}</td></tr>
          <tr><th scope="row">Salud con asociación, informe vigente y cuatro checks</th><td>{coverage(healthCovered, purls?.size)}</td></tr>
          <tr><th scope="row">Hallazgos con prioridad evaluada</th><td>{coverage(findings && pending != null ? findings.length - pending : undefined, findings?.length)}</td></tr>
        </tbody>
      </table></div>
      <p className="muted">La vigencia de Scorecard usa la advertencia guardada, sin reevaluar fechas. La cobertura describe datos recuperados; no mide calidad ni certifica seguridad.</p>
      <SourceAvailability analysis={analysis} />
      <h2>Limitaciones</h2>
      <ul><li>Alcanzabilidad no analizada; despliegue declarado no demuestra exposición real.</li>
        <li>Los pesos de prioridad son decisiones iniciales del prototipo; evaluación académica pendiente.</li>
        <li>SBOM y exportación JSON todavía no disponibles en este prototipo.</li>
        <li>Fechas y evidencias pertenecen a esta instantánea y no garantizan disponibilidad actual de los proveedores.</li>
        {analysis.diagnostics.map((value, index) => <li key={index}>{value}</li>)}
      </ul>
      <nav aria-label="Resultados del análisis">
        {analysis.dependencyGraph && <><a href={`#analysis/${id}/components`}>Inventario</a>{' · '}<a href={`#analysis/${id}/graph`}>Grafo y rutas</a>{' · '}</>}
        {snapshot && <a href={`#analysis/${id}/findings`}>Hallazgos y explicación de prioridad</a>}
      </nav>
    </>}
    <button onClick={() => setRetry(value => value + 1)}>Actualizar resumen</button>
  </section>;
}
