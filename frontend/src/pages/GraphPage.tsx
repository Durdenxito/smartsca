import { useEffect, useMemo, useState } from 'react';
import { request, errorMessage, type AnalysisResolution, type Component, type Neighborhood, type Routes } from '../api/client';
import AnalysisNotice from '../components/AnalysisNotice';

/** A bounded neighborhood and textual routes from the saved snapshot; no tool or external API runs here. */
export default function GraphPage({ id, initialPurl = '' }: { id: string; initialPurl?: string }) {
  const [analysis, setAnalysis] = useState<AnalysisResolution>();
  const [module, setModule] = useState('');
  const [focus, setFocus] = useState(initialPurl);
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [routeModule, setRouteModule] = useState('');
  const [routeOffset, setRouteOffset] = useState(0);
  const [loadedView, setView] = useState<Neighborhood>();
  const [loadedRoutes, setRoutes] = useState<{ purl: string; module: string; data: Routes }>();
  const [error, setError] = useState('');
  const [viewError, setViewError] = useState('');
  const [routeError, setRouteError] = useState('');
  const [retry, setRetry] = useState(0);
  const snapshot = analysis?.dependencyGraph;
  const purl = focus || snapshot?.rootsByModule[module] || '';
  const view = loadedView?.focus.purl === purl && loadedView.module === module && loadedView.offset === offset ? loadedView : undefined;
  const routes = loadedRoutes?.purl === purl && loadedRoutes.module === routeModule && loadedRoutes.data.offset === routeOffset ? loadedRoutes.data : undefined;

  useEffect(() => {
    const controller = new AbortController();
    setError('');
    request<AnalysisResolution>(`/analyses/${encodeURIComponent(id)}/resolution`, { signal: controller.signal }).then(value => {
      if (controller.signal.aborted) return;
      if (!value.dependencyGraph) throw new Error('El grafo todavía no está disponible.');
      const graph = value.dependencyGraph;
      const modules = Object.keys(graph.rootsByModule).sort();
      const matching = modules.find(module => graph.rootsByModule[module] === initialPurl
        || graph.edges.some(edge => edge.context.module === module && (edge.parentPurl === initialPurl || edge.childPurl === initialPurl)));
      setAnalysis(value);
      setModule(current => graph.rootsByModule[current] ? current : matching ?? modules[0]);
    }).catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, initialPurl, retry]);

  useEffect(() => {
    if (!module || !purl) return;
    const controller = new AbortController();
    setView(undefined); setViewError('');
    const query = new URLSearchParams({ module, purl, offset: String(offset) });
    request<Neighborhood>(`/analyses/${encodeURIComponent(id)}/graph?${query}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setView(value); })
      .catch(error => { if (!controller.signal.aborted) setViewError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, module, purl, offset, retry]);

  useEffect(() => {
    if (!purl) return;
    const controller = new AbortController();
    setRoutes(undefined); setRouteError('');
    const query = new URLSearchParams({ purl, offset: String(routeOffset) });
    if (routeModule) query.set('module', routeModule);
    request<Routes>(`/analyses/${encodeURIComponent(id)}/routes?${query}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setRoutes({ purl, module: routeModule, data: value }); })
      .catch(error => { if (!controller.signal.aborted) setRouteError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, purl, routeModule, routeOffset, retry]);

  const available = useMemo(() => {
    if (!snapshot) return [];
    const members = new Set([snapshot.rootsByModule[module]]);
    for (const edge of snapshot.edges) if (edge.context.module === module) { members.add(edge.parentPurl); members.add(edge.childPurl); }
    return Object.values(snapshot.components).filter(component => members.has(component.purl)).sort((a, b) => a.purl.localeCompare(b.purl));
  }, [snapshot, module]);
  const matches = available.filter(component => `${component.name} ${component.version} ${component.purl}`.toLowerCase().includes(search.toLowerCase()));
  const choices = matches.slice(0, 50);
  const selected = snapshot?.components[purl];
  if (selected && !choices.some(component => component.purl === purl)) choices.unshift(selected);

  function pick(value: string) { setFocus(value); setOffset(0); setRouteOffset(0); }
  const positions = new Map<string, { x: number; y: number }>();
  let left = 0, right = 0;
  for (const component of view?.neighbors ?? []) {
    const parent = view!.edges.some(edge => edge.parentPurl === component.purl && edge.childPurl === purl);
    positions.set(component.purl, { x: parent ? 140 : 720, y: 55 + (parent ? left++ : right++) * 95 });
  }
  const height = Math.max(180, Math.max(left, right) * 95 + 20);
  positions.set(purl, { x: 430, y: height / 2 });
  const pairs = new Map<string, { parent: string; child: string; scopes: Set<string> }>();
  for (const edge of view?.edges ?? []) {
    const key = JSON.stringify([edge.parentPurl, edge.childPurl]);
    const pair = pairs.get(key) ?? { parent: edge.parentPurl, child: edge.childPurl, scopes: new Set<string>() };
    pair.scopes.add(edge.context.normalizedContext); pairs.set(key, pair);
  }
  function label(component: Component) {
    return `${component.name} @ ${component.version}${component.metadata.classifier ? ` [${component.metadata.classifier}]` : ''}${component.metadata.type && component.metadata.type !== 'jar' ? ` [${component.metadata.type}]` : ''}`;
  }

  return <section aria-labelledby="graph-title">
    <h1 id="graph-title">Grafo de dependencias</h1>
    <p><a href={`#analysis/${id}`}>Volver al estado del análisis</a> · <a href={`#analysis/${id}/components`}>Consultar inventario</a></p>
    {error && <p role="alert" className="error">{error}</p>}
    {!analysis && !error && <p role="status">Cargando grafo…</p>}
    {analysis && snapshot && <>
      <p>{analysis.projectName} · Estado: {analysis.status}</p>
      <AnalysisNotice status={analysis.status} />
      <p><a href={`#analysis/${id}/summary`}>Consultar resumen y cobertura</a></p>
      <p className="muted">Consulta la salud en el inventario y la prioridad guardada en los hallazgos. La profundidad y la transitividad no indican menor riesgo.</p>
      <p>La instantánea conserva todos los scopes Maven. Los scopes configurados en el análisis filtran el inventario.</p>
      <div className="filters">
        <label>Módulo del grafo<select value={module} onChange={event => { setModule(event.target.value); pick(''); }}>
          {Object.keys(snapshot.rootsByModule).sort().map(module => <option key={module}>{module}</option>)}
        </select></label>
        <label>Buscar en el grafo<input type="search" maxLength={256} value={search} onChange={event => setSearch(event.target.value)} /></label>
      </div>
      <label>Seleccionar componente<select value={purl} onChange={event => pick(event.target.value)}>
        {choices.map(component => <option key={component.purl} value={component.purl}>{label(component)}</option>)}
      </select></label>
      <p>{matches.length} coincidencias. {matches.length > 50 && 'Se muestran las primeras 50; precisa la búsqueda para encontrar otras.'}</p>
      <button onClick={() => pick('')}>Ir a la raíz del módulo</button>
      {viewError && <p role="alert" className="error">{viewError}</p>}
      {!view && !viewError && <p role="status">Cargando relaciones…</p>}
      {view && <>
        <h2>Componente seleccionado</h2><p><strong>{label(view.focus)}</strong></p><code className="identifier">{view.focus.purl}</code>
        <p>Raíz del módulo {view.module}: {label(view.root)}</p>
        <p role="status">{view.totalNeighbors === 0 ? 'Sin componentes vecinos.' : `Vecinos ${view.offset + 1}–${view.offset + view.neighbors.length} de ${view.totalNeighbors}.`} Vista del componente y sus relaciones inmediatas.</p>
        <figure>
          <figcaption>Las flechas van del padre a su dependencia. Selecciona un nodo para explorar sus vecinos; también puedes usar la tabla con el teclado.</figcaption>
          <div className="graph-scroll" tabIndex={0} role="region" aria-label="Vista gráfica desplazable">
            <svg viewBox={`0 0 860 ${height}`} width="860" height={height} role="img" aria-label={`Relaciones inmediatas de ${label(view.focus)} en ${view.module}`}>
              <defs><marker id="dependency-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#496a8d" /></marker></defs>
              {[...pairs.entries()].map(([key, pair]) => {
                const a = positions.get(pair.parent)!, b = positions.get(pair.child)!;
                if (pair.parent === pair.child) return <path key={key} d={`M ${a.x} ${a.y - 29} c -60 -65 60 -65 0 0`} fill="none" stroke="#496a8d" markerEnd="url(#dependency-arrow)"><title>Relación consigo mismo; consultar scopes en la tabla</title></path>;
                const direction = b.x > a.x ? 1 : -1;
                return <g key={key}><line x1={a.x + direction * 118} y1={a.y} x2={b.x - direction * 118} y2={b.y} stroke="#496a8d" strokeWidth="1.5" markerEnd="url(#dependency-arrow)" />
                  <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 5} textAnchor="middle" fontSize="11">{[...pair.scopes].sort().join(', ')}</text></g>;
              })}
              {[view.focus, ...view.neighbors].map(component => {
                const point = positions.get(component.purl)!;
                const name = component.metadata.artifactId || component.name;
                const version = `${component.version}${component.metadata.classifier ? ` · ${component.metadata.classifier}` : ''}`;
                return <g key={component.purl} transform={`translate(${point.x},${point.y})`} onClick={() => pick(component.purl)} className="graph-node">
                  <title>{label(component)} — {component.purl}</title><rect x="-118" y="-29" width="236" height="58" rx="6" fill={component.purl === purl ? '#dbeafa' : '#fff'} stroke="#18589b" strokeWidth={component.purl === purl ? 2 : 1} />
                  <text textAnchor="middle" y="-3" fontSize="13">{name.length > 30 ? `${name.slice(0, 29)}…` : name}</text>
                  <text textAnchor="middle" y="17" fontSize="12">{version.length > 30 ? `${version.slice(0, 29)}…` : version}</text>
                </g>;
              })}
            </svg>
          </div>
        </figure>
        <div className="table-scroll"><table>
          <caption>Relaciones textuales de la página del grafo — módulo {view.module}</caption>
          <thead><tr><th scope="col">Padre</th><th scope="col">Dependencia</th><th scope="col">Scope efectivo / reportado</th></tr></thead>
          <tbody>{view.edges.map(edge => <tr key={JSON.stringify(edge)}>
            <td><button className="node-link" onClick={() => pick(edge.parentPurl)}>{label(snapshot.components[edge.parentPurl])}</button></td>
            <td><button className="node-link" onClick={() => pick(edge.childPurl)}>{label(snapshot.components[edge.childPurl])}</button></td>
            <td>{edge.context.normalizedContext} / {edge.context.originalScope}</td>
          </tr>)}</tbody>
        </table></div>
        {(view.offset > 0 || view.nextOffset !== null) && <nav aria-label="Páginas del grafo">
          <button disabled={view.offset === 0} onClick={() => setOffset(Math.max(0, view.offset - 24))}>Vecinos anteriores</button>{' '}
          <button disabled={view.nextOffset === null} onClick={() => setOffset(view.nextOffset!)}>Más vecinos</button>
        </nav>}
      </>}
      <h2>Rutas de introducción</h2>
      <label>Módulo de las rutas<select value={routeModule} onChange={event => { setRouteModule(event.target.value); setRouteOffset(0); }}>
        <option value="">Todos los módulos</option>{Object.keys(snapshot.rootsByModule).sort().map(module => <option key={module}>{module}</option>)}
      </select></label>
      <p>Rutas simples desde la raíz hasta el componente seleccionado, sin repetir componentes. Cada paso conserva su scope Maven reportado.</p>
      {routeError && <p role="alert" className="error">{routeError}</p>}
      {!routes && !routeError && <p role="status">Consultando rutas…</p>}
      {routes && <>
        <p role="status">{routes.routes.length} rutas en esta página.{routes.nextOffset !== null && ' Hay más rutas disponibles.'}</p>
        {routes.searchLimited && <p role="status" className="error">Búsqueda limitada: se alcanzó el máximo de trabajo, profundidad o paginación. Esta lista no es exhaustiva. Selecciona un módulo para acotar la búsqueda.</p>}
        {!routes.routes.length && <p>{routes.searchLimited ? 'No se encontraron rutas dentro del límite.' : 'No hay rutas en esta página para el módulo seleccionado.'}</p>}
        <ol className="routes" start={routes.offset + 1}>{routes.routes.map((route, index) => <li key={`${routes.offset + index}`}>
          <strong>Módulo {route.module}</strong>
          <ol aria-label={`Pasos de la ruta ${routes.offset + index + 1}`}>
            <li>{label(routes.components[route.rootPurl])} <span className="muted">(raíz)</span></li>
            {route.steps.map((edge, step) => <li key={step}>{label(routes.components[edge.childPurl])} — scope {edge.context.normalizedContext}, reportado {edge.context.originalScope}
              <details><summary>Identidad del paso</summary><code className="identifier">{edge.childPurl}</code></details>
            </li>)}
          </ol>
          {route.steps.length === 0 && <p>El componente seleccionado es la raíz de este módulo.</p>}
        </li>)}</ol>
        {(routes.offset > 0 || routes.nextOffset !== null) && <nav aria-label="Páginas de rutas">
          <button disabled={routes.offset === 0} onClick={() => setRouteOffset(Math.max(0, routes.offset - 20))}>Rutas anteriores</button>{' '}
          <button disabled={routes.nextOffset === null} onClick={() => setRouteOffset(routes.nextOffset!)}>Más rutas</button>
        </nav>}
      </>}
    </>}
    {(error || viewError || routeError) && <button onClick={() => setRetry(value => value + 1)}>Reintentar</button>}
  </section>;
}
