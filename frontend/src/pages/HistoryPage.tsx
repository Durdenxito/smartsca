import { useEffect, useState } from 'react';
import { request, errorMessage, type AnalysisHistory } from '../api/client';

/** Lists saved metadata; filters and pagination survive a reload in the URL. */
export default function HistoryPage({ query }: { query: string }) {
  const params = new URLSearchParams(query);
  const [project, setProject] = useState(params.get('projectId') ?? '');
  const [status, setStatus] = useState(params.get('status') ?? '');
  const [history, setHistory] = useState<AnalysisHistory>();
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setHistory(undefined); setError('');
    const filters = new URLSearchParams(query);
    const api = new URLSearchParams();
    for (const name of ['projectId', 'status', 'offset']) if (filters.has(name)) api.set(name, filters.get(name)!);
    void request<AnalysisHistory>(`/analyses?${api}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setHistory(value); })
      .catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [query, retry]);
  function navigate(offset: number) {
    const filters = new URLSearchParams(query);
    filters.set('offset', String(offset));
    window.location.hash = `history?${filters}`;
  }
  return <section aria-labelledby="history-title">
    <h1 id="history-title">Historial de análisis</h1>
    <p>Historial común del prototipo. Abrir un análisis recupera su instantánea y política originales, sin consultar proveedores ni recalcular resultados.</p>
    <form onSubmit={event => {
      event.preventDefault();
      const filters = new URLSearchParams();
      if (project.trim()) filters.set('projectId', project.trim());
      if (status) filters.set('status', status);
      const target = `#history${filters.size ? `?${filters}` : ''}`;
      if (window.location.hash === target) setRetry(value => value + 1);
      else window.location.hash = target;
    }}>
      <div className="filters">
        <label>Filtrar por identificador de proyecto<input type="search" maxLength={64} value={project} placeholder="maven-basic" onChange={event => setProject(event.target.value)} /></label>
        <label>Filtrar por estado<select value={status} onChange={event => setStatus(event.target.value)}>
          <option value="">Todos</option>{['EN_COLA', 'EN_EJECUCION', 'COMPLETO', 'PARCIAL', 'FALLIDO'].map(value => <option key={value}>{value}</option>)}
        </select></label>
      </div>
      <p><button type="submit">Aplicar filtros</button>{' '}<a href="#history">Limpiar filtros</a></p>
    </form>
    {error && <p role="alert" className="error">{error}</p>}
    {!history && !error && <p role="status">Consultando historial guardado…</p>}
    {history && <>
      <p role="status">{history.items.length} análisis en esta página.</p>
      {!history.items.length ? <p>No hay análisis para los filtros seleccionados.</p> : <div className="table-scroll"><table>
        <caption>Análisis persistidos, más recientes primero</caption>
        <thead><tr><th scope="col">Proyecto y referencia</th><th scope="col">Configuración guardada</th><th scope="col">Fechas y duración</th><th scope="col">Estado</th><th scope="col">Resultados</th></tr></thead>
        <tbody>{history.items.map(value => <tr key={value.id}>
          <th scope="row">{value.projectName}<code className="identifier">{value.projectId}</code><code className="identifier">{value.sourceReference}</code><code className="identifier">{value.analyzedReference}</code></th>
          <td>Módulos: {value.configuration.modules.join(', ')}<br />Perfiles: {value.configuration.profiles.join(', ') || 'Sin perfiles'}<br />Scopes: {value.configuration.scopes.join(', ')}<br />Entorno: {value.configuration.environmentId}<br />Contexto declarado: {value.configuration.declaredDeployment || 'No declarado'}</td>
          <td>Registro: {new Date(value.createdAt).toLocaleString('es-PE')}<br />Inicio: {value.startedAt ? new Date(value.startedAt).toLocaleString('es-PE') : 'No disponible'}<br />Fin: {value.finishedAt ? new Date(value.finishedAt).toLocaleString('es-PE') : 'No disponible'}<br />Duración: {value.startedAt && value.finishedAt ? `${Math.max(0, (Date.parse(value.finishedAt) - Date.parse(value.startedAt)) / 1000).toFixed(1)} s` : 'No disponible'}</td>
          <td>{value.status}{value.status === 'PARCIAL' && <p className="muted">Resultados incompletos; revisar cobertura.</p>}{value.status === 'FALLIDO' && <p className="muted">Consultar diagnóstico y datos disponibles.</p>}</td>
          <td><code className="identifier">{value.id}</code><a href={`#analysis/${value.id}`}>Estado y diagnóstico</a><br /><a href={`#analysis/${value.id}/summary`}>Resumen y cobertura</a></td>
        </tr>)}</tbody>
      </table></div>}
      <p className="muted">Hasta 20 registros por página; desempate por identificador. Nuevas ejecuciones y cambios de estado pueden desplazar páginas al actualizar.</p>
      {history.navigationLimited && <p className="error">Se alcanzó el límite de navegación del historial (offset 10000). Acota los filtros; esta lista no es exhaustiva.</p>}
      <nav aria-label="Páginas del historial">
        <button disabled={history.offset === 0} onClick={() => navigate(Math.max(0, history.offset - 20))}>Anterior</button>{' '}
        <button disabled={history.nextOffset == null} onClick={() => navigate(history.nextOffset!)}>Siguiente</button>
      </nav>
    </>}
    <button onClick={() => setRetry(value => value + 1)}>Actualizar historial</button>
  </section>;
}
