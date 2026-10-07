import { useEffect, useState, type FormEvent } from 'react';
import { request, errorMessage, type Catalog } from '../api/client';

export default function NewAnalysisPage() {
  const [catalog, setCatalog] = useState<Catalog>();
  const [projectId, setProjectId] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [modules, setModules] = useState(['.']);
  const [profiles, setProfiles] = useState<string[]>([]);
  const [context, setContext] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError('');
    request<Catalog>('/projects', { signal: controller.signal })
      .then(value => {
        setCatalog(value);
        setProjectId(value.projects[0]?.id ?? '');
        setScopes(value.defaults.scopes);
      })
      .catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [retry]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!catalog || busy) return;
    if (!scopes.length) { setError('Selecciona al menos un scope.'); return; }
    if (!modules.length) { setError('Selecciona al menos un módulo.'); return; }
    setBusy(true);
    setError('');
    try {
      const accepted = await request<{ id: string }>('/analyses', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, configuration: {
          ...catalog.defaults, modules, profiles, scopes, declaredDeployment: context.trim() || null,
        } }),
      });
      window.location.hash = `analysis/${accepted.id}`;
    } catch (error) {
      setError(errorMessage(error));
    } finally { setBusy(false); }
  }

  return (
    <section aria-labelledby="new-analysis-title">
      <h1 id="new-analysis-title">Nuevo análisis</h1>
      <p>Selecciona un proyecto del catálogo y guarda su configuración de análisis.</p>
      {error && <p role="alert" className="error">{error}</p>}
      {!catalog ? <>
        {!error && <p role="status">Cargando catálogo…</p>}
        {error && <button onClick={() => setRetry(value => value + 1)}>Reintentar</button>}
      </> : catalog.projects.length === 0 ? <p>No hay proyectos disponibles en el catálogo.</p> : (
        <form onSubmit={submit}>
          <fieldset disabled={busy}>
            <legend>Proyecto y configuración</legend>
            <label htmlFor="project">Proyecto Maven</label>
            <select id="project" value={projectId} onChange={event => {
              setProjectId(event.target.value); setModules(['.']); setProfiles([]);
            }} required>
              {catalog.projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}
            </select>
            <dl>
              <dt>Fuente del proyecto</dt><dd><code>{catalog.projects.find(project => project.id === projectId)?.sourceReference}</code></dd>
              <dt>Huella del catálogo</dt><dd><code>{catalog.projects.find(project => project.id === projectId)?.analyzedReference}</code></dd>
            </dl>
            <p className="muted">La referencia se valida de nuevo al registrar el análisis. Entorno: Java 21</p>
            <fieldset className="scopes">
              <legend>Módulos</legend>
              {(catalog.projects.find(project => project.id === projectId)?.modules ?? []).sort().map(module => <label key={module}>
                <input type="checkbox" checked={modules.includes(module)} onChange={event => setModules(current => {
                  if (!event.target.checked) return current.filter(value => value !== module);
                  return module === '.' ? ['.'] : [...current.filter(value => value !== '.'), module];
                })} />{module === '.' ? 'Raíz y reactor completo' : module}
              </label>)}
            </fieldset>
            {(catalog.projects.find(project => project.id === projectId)?.profiles.length ?? 0) > 0 && <fieldset className="scopes">
              <legend>Perfiles</legend>
              {catalog.projects.find(project => project.id === projectId)!.profiles.map(profile => <label key={profile}>
                <input type="checkbox" checked={profiles.includes(profile)} onChange={event => setProfiles(current =>
                  event.target.checked ? [...current, profile] : current.filter(value => value !== profile))} />{profile}
              </label>)}
            </fieldset>}
            <fieldset className="scopes">
              <legend>Scopes incluidos</legend>
              {catalog.scopes.map(scope => <label key={scope}>
                <input type="checkbox" checked={scopes.includes(scope)} onChange={event => setScopes(current =>
                  event.target.checked ? [...current, scope] : current.filter(value => value !== scope))} />
                {scope}
              </label>)}
            </fieldset>
            <p className="muted">Los scopes seleccionan los componentes incluidos. La resolución conserva las rutas Maven completas.</p>
            <label htmlFor="deployment">Contexto de despliegue declarado (opcional)</label>
            <textarea id="deployment" maxLength={500} rows={3} value={context}
              onChange={event => setContext(event.target.value)} aria-describedby="deployment-help" />
            <p id="deployment-help" className="muted">Hasta 500 caracteres. Esta declaración no acredita el despliegue real.</p>
            <button type="submit">{busy ? 'Guardando…' : 'Registrar análisis'}</button>
          </fieldset>
        </form>
      )}
    </section>
  );
}
