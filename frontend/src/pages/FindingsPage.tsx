import { useEffect, useState, type ReactNode } from 'react';
import { request, errorMessage, type Analysis, type Advisory, type ComponentItem, type Evidence, type Vulnerability, type RiskAssessment } from '../api/client';
import HealthDetails from '../components/HealthDetails';

function safeUrl(value: string) {
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined; }
  catch { return undefined; }
}
function CvssObservation({ evidence }: { evidence: Advisory['cvss'] }) {
  return <Observation evidence={evidence}><ul>{(evidence.value ?? []).map((cvss, index) => <li key={index}>
    CVSS {cvss.version} · <code>{cvss.vector}</code> · {cvss.source}
  </li>)}</ul></Observation>;
}
function Observation<T>({ evidence, children }: { evidence: Evidence<T>; children?: ReactNode }) {
  const url = safeUrl(evidence.source);
  return <div className="observation">
    <p><strong>{evidence.status}</strong>{evidence.diagnostic && ` · ${evidence.diagnostic}`}</p>
    {evidence.status === 'DISPONIBLE' && children}
    <p className="muted">Fuente: {url ? <a href={url} target="_blank" rel="noreferrer">{evidence.source}</a> : evidence.source}
      {' · '}Registrada: {new Date(evidence.collectedAt).toLocaleString('es-PE')}
      {evidence.sourceDate && ` · Fecha de la fuente: ${evidence.sourceDate}`}</p>
  </div>;
}
function VulnerabilityDetails({ vulnerability, componentName }: { vulnerability: Vulnerability; componentName: string }) {
  return <>
    <p>Identificadores y aliases: {[...vulnerability.aliases].sort().join(', ')}</p>
    {Object.entries(vulnerability.advisories).sort(([a], [b]) => a.localeCompare(b)).map(([id, evidence]) => <section key={id} aria-label={`Aviso ${id}`}>
      <h3>{id}</h3><Observation evidence={evidence}>
        {evidence.value && <>
          <p><strong>{evidence.value.summary || 'Resumen no publicado'}</strong></p>
          <p className="advisory-description">{evidence.value.description || 'Descripción no publicada'}</p>
          <h4>Rangos afectados y versiones corregidas publicadas</h4>
          {evidence.value.affected.filter(affected => affected.ecosystem === 'Maven' && affected.name === componentName).map((affected, index) => <div key={index}>
            <pre>{affected.ranges}</pre>
            <p>Versiones enumeradas: {affected.versions.join(', ') || 'No publicadas'}</p>
            <p>Versiones corregidas: {affected.fixedVersions.join(', ') || 'No publicadas'}. Compatibilidad no validada.</p>
            <h4>CVSS del paquete {affected.name}</h4><CvssObservation evidence={affected.cvss} />
          </div>)}
          <h4>CVSS global del aviso</h4><CvssObservation evidence={evidence.value.cvss} />
          <p className="muted">Se conservan todos los vectores, escala base CVSS 0–10. La explicación de prioridad indica la selección guardada.</p>
          <h4>Referencias</h4><ul>{evidence.value.references.map((reference, index) => <li key={index}>
            {safeUrl(reference) ? <a href={safeUrl(reference)} target="_blank" rel="noreferrer">{reference}</a> : reference}
          </li>)}</ul>
          <details><summary>Respuesta OSV conservada</summary><pre>{evidence.value.rawResponse}</pre></details>
        </>}
      </Observation>
    </section>)}
    <h3>EPSS por CVE</h3><Observation evidence={vulnerability.epssByCve}>
      {Object.entries(vulnerability.epssByCve.value ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([cve, evidence]) => <div key={cve}>
        <h4>{cve}</h4><Observation evidence={evidence}>{evidence.value && <p>
          Probabilidad: {(evidence.value.probability * 100).toFixed(4)} % · Percentil: {(evidence.value.percentile * 100).toFixed(4)} % (escala original 0–1).
        </p>}</Observation>
      </div>)}
    </Observation>
    <h3>CISA KEV por CVE</h3><Observation evidence={vulnerability.kevByCve}>
      {Object.entries(vulnerability.kevByCve.value ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([cve, evidence]) => <div key={cve}>
        <h4>{cve}</h4><Observation evidence={evidence}>{evidence.value !== null && <p>
          {evidence.value ? 'Incluido en el catálogo de explotación conocida.' : 'Ausente del catálogo consultado; no demuestra ausencia de explotación.'}
        </p>}</Observation>
      </div>)}
    </Observation>
  </>;
}

export default function FindingsPage({ id, initialPurl }: { id: string; initialPurl: string }) {
  const [analysis, setAnalysis] = useState<Analysis>();
  const [components, setComponents] = useState<ComponentItem[]>([]);
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [search, setSearch] = useState('');
  const [purl, setPurl] = useState(initialPurl);
  const [module, setModule] = useState('');
  const [scope, setScope] = useState('');
  const [kev, setKev] = useState('');
  const [priority, setPriority] = useState('');
  const [page, setPage] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setAnalysis(undefined); setError('');
    void Promise.all([
      request<Analysis>(`/analyses/${encodeURIComponent(id)}`, { signal: controller.signal }),
      request<ComponentItem[]>(`/analyses/${encodeURIComponent(id)}/components`, { signal: controller.signal }),
    ]).then(([value, items]) => {
      if (controller.signal.aborted) return;
      if (!value.vulnerabilitySnapshot) throw new Error('Las evidencias todavía no están disponibles para este análisis.');
      setAnalysis(value); setComponents(items);
    }).catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, retry]);
  const snapshot = analysis?.vulnerabilitySnapshot;
  const vulnerabilities = new Map(snapshot?.vulnerabilities.map(value => [value.id, value]));
  const inventory = new Map(components.map(item => [item.component.purl, item]));
  const risk = analysis?.riskSnapshot;
  const assessments = new Map(risk?.assessments.map(value => [`${value.finding.componentPurl}/${value.finding.vulnerabilityId}`, value]));
  // Preserve the server's persisted order; legacy snapshots keep their original identities and remain unevaluated.
  const orderedFindings = risk ? risk.assessments.map(value => value.finding) : snapshot?.findings ?? [];
  const filtered = orderedFindings.filter(finding => {
    const item = inventory.get(finding.componentPurl);
    const vulnerability = vulnerabilities.get(finding.vulnerabilityId);
    if (!item || !vulnerability || (purl && purl !== finding.componentPurl)) return false;
    const evaluation = assessments.get(`${finding.componentPurl}/${finding.vulnerabilityId}`);
    if (priority && priority !== (evaluation?.level ?? 'PENDIENTE_REVISION')) return false;
    const text = `${item.component.name} ${item.component.version} ${finding.componentPurl} ${vulnerability.aliases.join(' ')}`.toLowerCase();
    if (!text.includes(search.trim().toLowerCase())) return false;
    if (!item.contexts.some(context => (!module || context.module === module) && (!scope || context.scope === scope))) return false;
    const signals = Object.values(vulnerability.kevByCve.value ?? {});
    return !kev || (kev === 'true' ? signals.some(value => value.value === true) : signals.length > 0 && signals.every(value => value.status === 'DISPONIBLE' && value.value === false));
  });
  const pages = Math.max(1, Math.ceil(filtered.length / 20));
  const current = Math.min(page, pages - 1);
  const queries = Object.values(snapshot?.componentQueries ?? {});
  const completed = queries.filter(value => value.status === 'DISPONIBLE').length;
  return <section aria-labelledby="findings-title">
    <h1 id="findings-title">Vulnerabilidades y evidencias</h1>
    <p><a href={`#analysis/${id}`}>Estado del análisis</a> · <a href={`#analysis/${id}/components`}>Inventario</a></p>
    {error && <><p role="alert" className="error">{error}</p><button onClick={() => setRetry(value => value + 1)}>Reintentar</button></>}
    {!analysis && !error && <p role="status">Consultando evidencias guardadas…</p>}
    {analysis && snapshot && <>
      <p>{analysis.project.name} · Estado: {analysis.status}</p>
      <p className="muted">{risk ? `Prioridad guardada: ${risk.policy.version}. KEV confirmado primero; pendientes antes que evaluados dentro de cada grupo KEV; después puntuación e identidad.`
        : 'Prioridad no evaluada en esta instantánea anterior; no se recalcula al consultar.'} Alcanzabilidad no analizada.</p>
      {risk && <details><summary>Política de prioridad guardada</summary>
        <p>Calculada: {new Date(risk.evaluatedAt).toLocaleString('es-PE')}. Índice del prototipo, no probabilidad de ataque ni modelo validado académicamente.</p>
        <p>{risk.policy.formula}</p><dl>
          {Object.entries(risk.policy.weights).map(([name, value]) => <div key={name}><dt>Peso {name}</dt><dd>{value}</dd></div>)}
          {Object.entries(risk.policy.thresholds).map(([name, value]) => <div key={name}><dt>Umbral {name}</dt><dd>≥ {value}</dd></div>)}
        </dl><p>{risk.policy.cvssSelection} · {risk.policy.calculator}</p>
        <ul>{risk.policy.missingEvidenceRules.map(rule => <li key={rule}>{rule}</li>)}</ul>
        <ol>{risk.policy.tieBreakRules.map(rule => <li key={rule}>{rule}</li>)}</ol>
      </details>}
      <p>Consultas OSV completas: {completed} de {queries.length}. Los errores y ausencias no equivalen a cero vulnerabilidades.</p>
      <details><summary>Cobertura y diagnóstico de OSV por componente</summary><ul>
        {Object.entries(snapshot.componentQueries).sort(([a], [b]) => a.localeCompare(b)).map(([key, evidence]) => <li key={key}>
          <code>{key}</code><Observation evidence={evidence}>{evidence.value && <p>{evidence.value.length} avisos identificados antes de correlacionar aliases.</p>}</Observation>
        </li>)}
      </ul></details>
      <div className="filters">
        <label>Buscar componente o identificador<input type="search" maxLength={256} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>
        <label>Componente de los hallazgos<select value={purl} onChange={event => { setPurl(event.target.value); setPage(0); }}>
          <option value="">Todos</option>{components.map(item => <option key={item.component.purl} value={item.component.purl}>{item.component.name} @ {item.component.version}</option>)}
        </select></label>
        <label>Módulo de los hallazgos<select value={module} onChange={event => { setModule(event.target.value); setPage(0); }}>
          <option value="">Todos</option>{Object.keys(analysis.dependencyGraph!.rootsByModule).sort().map(value => <option key={value}>{value}</option>)}
        </select></label>
        <label>Scope de los hallazgos<select value={scope} onChange={event => { setScope(event.target.value); setPage(0); }}>
          <option value="">Todos</option>{analysis.configuration.scopes.map(value => <option key={value}>{value}</option>)}
        </select></label>
        <label>Señal KEV<select value={kev} onChange={event => { setKev(event.target.value); setPage(0); }}>
          <option value="">Todas</option><option value="true">Incluido</option><option value="false">Ausencia confirmada en catálogo</option>
        </select></label>
        <label>Prioridad del hallazgo<select value={priority} onChange={event => { setPriority(event.target.value); setPage(0); }}>
          <option value="">Todas</option>{['CRITICA', 'ALTA', 'MEDIA', 'BAJA', 'PENDIENTE_REVISION'].map(value => <option key={value}>{value}</option>)}
        </select></label>
      </div>
      <p role="status">{filtered.length} hallazgos encontrados</p>
      {filtered.length === 0 && <p>No hay hallazgos identificados que coincidan. Revisa la cobertura antes de concluir ausencia de vulnerabilidades.</p>}
      <ul className="findings">{filtered.slice(current * 20, (current + 1) * 20).map(finding => {
        const item = inventory.get(finding.componentPurl)!;
        return <li key={`${finding.componentPurl}/${finding.vulnerabilityId}`}>
          <h2>{finding.vulnerabilityId} · {item.component.name} @ {item.component.version}</h2>
          <code>{finding.componentPurl}</code>
          <p>{item.contexts.map(context => `${context.module} · ${context.scope} · ${context.direct ? 'Directa' : 'Transitiva'}`).join('; ')}</p>
          <p><a href={`#analysis/${id}/graph?component=${encodeURIComponent(finding.componentPurl)}`}>Consultar rutas de introducción</a></p>
          <PriorityDetails assessment={assessments.get(`${finding.componentPurl}/${finding.vulnerabilityId}`)} />
          <details><summary>Detalle de {finding.vulnerabilityId}</summary><VulnerabilityDetails vulnerability={vulnerabilities.get(finding.vulnerabilityId)!} componentName={item.component.name} /></details>
          <HealthDetails assessment={analysis.healthAssessments?.[finding.componentPurl]} />
        </li>;
      })}</ul>
      {pages > 1 && <nav aria-label="Páginas de hallazgos"><button disabled={current === 0} onClick={() => setPage(current - 1)}>Anterior</button>
        <span> Página {current + 1} de {pages} </span><button disabled={current + 1 === pages} onClick={() => setPage(current + 1)}>Siguiente</button></nav>}
    </>}
  </section>;
}

function PriorityDetails({ assessment }: { assessment: RiskAssessment | undefined }) {
  return <>
    <p>Prioridad: {assessment?.level ?? 'PENDIENTE_REVISION'} · {assessment?.score == null ? 'Sin puntuación concluyente' : `${assessment.score} / 100`}
      {assessment?.knownExploited && ' · Explotación conocida confirmada (KEV)'}</p>
    {assessment && <details><summary>Explicación de prioridad</summary>
      <p>Política: {assessment.policyVersion} · Estado: {assessment.status}</p>
      <ul>{assessment.explanation.map((value, index) => <li key={index}>{value}</li>)}</ul>
      <div className="table-scroll"><table><caption>Contribuciones guardadas de la prioridad</caption>
        <thead><tr><th scope="col">Dimensión / peso</th><th scope="col">Puntos o regla KEV</th><th scope="col">Regla y evidencia utilizada</th></tr></thead>
        <tbody>{assessment.contributions.map(value => <tr key={value.dimension}>
          <th scope="row">{value.dimension} · {value.weight}</th><td>{value.points == null ? 'No evaluable' : value.points}</td>
          <td>{value.rule}<details><summary>Evidencia utilizada de {value.dimension}</summary>
            {value.usedEvidence.map((evidence, index) => <Observation key={index} evidence={evidence}><pre>{evidence.value}</pre></Observation>)}
          </details></td>
        </tr>)}</tbody></table></div>
      <ul>{assessment.limits.map(value => <li key={value}>{value}</li>)}</ul>
    </details>}
  </>;
}
