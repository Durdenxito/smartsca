import { useEffect, useState } from 'react';
import { request, errorMessage, type AnalysisInventory, type ComponentItem } from '../api/client';
import HealthDetails from '../components/HealthDetails';
import AnalysisNotice from '../components/AnalysisNotice';

export default function ComponentsPage({ id }: { id: string }) {
  const [analysis, setAnalysis] = useState<AnalysisInventory>();
  const [items, setItems] = useState<ComponentItem[]>([]);
  const [search, setSearch] = useState('');
  const [module, setModule] = useState('');
  const [scope, setScope] = useState('');
  const [direct, setDirect] = useState('');
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError('');
    setAnalysis(undefined); setItems([]);
    request<AnalysisInventory>(`/analyses/${encodeURIComponent(id)}/inventory`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) { setAnalysis(value); setItems(value.items); } })
      .catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, retry]);

  const filtered = items.map(item => ({ ...item, contexts: item.contexts.filter(context =>
    (!module || context.module === module) && (!scope || context.scope === scope)
    && (!direct || context.direct === (direct === 'true'))) })).filter(item => item.contexts.length
      && `${item.component.name} ${item.component.version} ${item.component.purl}`.toLowerCase().includes(search.toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / 50));
  const current = Math.min(page, pages - 1);

  return <section aria-labelledby="components-title">
    <h1 id="components-title">Inventario de componentes</h1>
    <p><a href={`#analysis/${id}`}>Volver al estado del análisis</a></p>
    <p><a href={`#analysis/${id}/graph`}>Explorar grafo y rutas</a></p>
    {error && <><p role="alert" className="error">{error}</p><button onClick={() => setRetry(value => value + 1)}>Reintentar</button></>}
    {!analysis && !error && <p role="status">Cargando inventario…</p>}
    {analysis && <>
      <p>{analysis.projectName} · Estado: {analysis.status}</p>
      <AnalysisNotice status={analysis.status} />
      <p><a href={`#analysis/${id}/summary`}>Consultar resumen y cobertura</a></p>
      <p className="muted">Este inventario refleja la resolución Maven guardada. Consulta la salud y disponibilidad de evidencias por componente; las prioridades y sus limitaciones están en los hallazgos.</p>
      {analysis.vulnerabilitiesAvailable && <p><a href={`#analysis/${id}/findings`}>Revisar vulnerabilidades y evidencias</a></p>}
      <div className="filters">
        <label>Buscar componente<input type="search" maxLength={256} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>
        <label>Filtrar por módulo<select value={module} onChange={event => { setModule(event.target.value); setPage(0); }}>
          <option value="">Todos</option>{Object.keys(analysis.rootsByModule).sort().map(module => <option key={module}>{module}</option>)}
        </select></label>
        <label>Filtrar por scope<select value={scope} onChange={event => { setScope(event.target.value); setPage(0); }}>
          <option value="">Todos</option>{[...analysis.scopes].sort().map(scope => <option key={scope}>{scope}</option>)}
        </select></label>
        <label>Filtrar por condición<select value={direct} onChange={event => { setDirect(event.target.value); setPage(0); }}>
          <option value="">Todas</option><option value="true">Directa</option><option value="false">Transitiva</option>
        </select></label>
      </div>
      <p role="status">{filtered.length} componentes encontrados</p>
      <div className="table-scroll"><table>
        <caption>Identidades y contextos de las dependencias resueltas</caption>
        <thead><tr><th scope="col">Componente / Package URL</th><th scope="col">Ecosistema</th><th scope="col">Versión</th><th scope="col">Módulo · Scope · Condición</th></tr></thead>
        <tbody>{filtered.slice(current * 50, (current + 1) * 50).map(item => <tr key={item.component.purl}>
          <td><strong>{item.component.name}</strong><p><a href={`#analysis/${id}/graph?component=${encodeURIComponent(item.component.purl)}`}>Ver grafo y rutas de {item.component.name}</a></p>
            {analysis.vulnerabilitiesAvailable && <p><a href={`#analysis/${id}/findings?component=${encodeURIComponent(item.component.purl)}`}>Ver evidencias de {item.component.name}</a></p>}
            <details><summary>Package URL y metadatos</summary><code>{item.component.purl}</code>
            <dl>{Object.entries(item.component.metadata).filter(([, value]) => value).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>
          </details><HealthDetails assessment={analysis.healthAssessments?.[item.component.purl]} /></td>
          <td>{item.component.ecosystem}</td><td>{item.component.version}</td>
          <td><ul>{item.contexts.map(context => <li key={`${context.module}/${context.scope}/${context.originalScope}/${context.direct}`}>
            {context.module} · {context.scope} · {context.direct ? 'Directa' : 'Transitiva'}
          </li>)}</ul></td>
        </tr>)}</tbody>
      </table></div>
      {filtered.length === 0 && <p>No hay componentes que coincidan con estos filtros.</p>}
      {pages > 1 && <nav aria-label="Páginas del inventario">
        <button disabled={current === 0} onClick={() => setPage(current - 1)}>Anterior</button>
        <span> Página {current + 1} de {pages} </span>
        <button disabled={current + 1 === pages} onClick={() => setPage(current + 1)}>Siguiente</button>
      </nav>}
    </>}
  </section>;
}
