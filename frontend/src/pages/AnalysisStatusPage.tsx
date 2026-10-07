import { useEffect, useState } from 'react';
import { request, errorMessage, type Analysis } from '../api/client';
import SourceAvailability from '../components/SourceAvailability';
import AnalysisNotice from '../components/AnalysisNotice';

export default function AnalysisStatusPage({ id }: { id: string }) {
  const [analysis, setAnalysis] = useState<Analysis>();
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setAnalysis(undefined);
    setError('');
    async function refresh() {
      try {
        const value = await request<Analysis>(`/analyses/${encodeURIComponent(id)}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setAnalysis(value);
        setError('');
        if (value.status === 'EN_COLA' || value.status === 'EN_EJECUCION') timer = setTimeout(refresh, 3000);
      } catch (error) { if (!controller.signal.aborted) setError(errorMessage(error)); }
    }
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [id, retry]);

  return (
    <section aria-labelledby="analysis-status-title">
      <h1 id="analysis-status-title">Estado del análisis</h1>
      <p className="identifier">Identificador: <code>{id}</code></p>
      {error && <><p role="alert" className="error">{error}</p>
        <button onClick={() => setRetry(value => value + 1)}>Reintentar consulta</button></>}
      {!analysis && !error && <p role="status">Consultando estado…</p>}
      {analysis && <>
        <p role="status" className="status">{analysis.status}</p>
        <AnalysisNotice status={analysis.status} />
        <p><a href={`#analysis/${id}/summary`}>Consultar resumen y cobertura</a></p>
        <dl>
          <dt>Proyecto</dt><dd>{analysis.project.name}</dd>
          <dt>Paso actual</dt><dd>{analysis.currentStep}</dd>
          <dt>Registrado</dt><dd>{new Date(analysis.createdAt).toLocaleString('es-PE')}</dd>
          <dt>Módulos</dt><dd>{analysis.configuration.modules.join(', ')}</dd>
          <dt>Perfiles</dt><dd>{analysis.configuration.profiles.join(', ') || 'Sin perfiles'}</dd>
          <dt>Scopes</dt><dd>{analysis.configuration.scopes.join(', ')}</dd>
          <dt>Entorno</dt><dd>{analysis.configuration.environmentId}</dd>
          <dt>Contexto declarado</dt><dd>{analysis.configuration.declaredDeployment || 'No declarado'}</dd>
        </dl>
        {analysis.status === 'EN_COLA' && <p>La solicitud está guardada y espera su turno de ejecución.</p>}
        {analysis.status === 'EN_EJECUCION' && <p>Resolviendo dependencias Maven y consultando las evidencias del análisis.</p>}
        {analysis.dependencyGraph && <p><a href={`#analysis/${id}/components`}>Consultar inventario de componentes</a></p>}
        {analysis.dependencyGraph && <p><a href={`#analysis/${id}/graph`}>Explorar grafo y rutas</a></p>}
        {analysis.vulnerabilitySnapshot && <p><a href={`#analysis/${id}/findings`}>Revisar vulnerabilidades y evidencias</a></p>}
        {analysis.startedAt && <p>Inicio: {new Date(analysis.startedAt).toLocaleString('es-PE')}</p>}
        {analysis.finishedAt && <p>Fin: {new Date(analysis.finishedAt).toLocaleString('es-PE')} · Duración: {Math.max(0, (Date.parse(analysis.finishedAt) - Date.parse(analysis.startedAt!)) / 1000).toFixed(1)} s</p>}
        {Object.keys(analysis.environmentVersions).length > 0 && <details><summary>Entorno de resolución</summary>
          <dl>{Object.entries(analysis.environmentVersions).map(([name, version]) => <div key={name}><dt>{name}</dt><dd>{version}</dd></div>)}</dl>
        </details>}
        {analysis.diagnostics.length > 0 && <ul>{analysis.diagnostics.map((text, index) => <li key={index}>{text}</li>)}</ul>}
        <SourceAvailability analysis={analysis} />
        <p className="muted">Conserva esta dirección para consultar la solicitud después de recargar.</p>
      </>}
      <a href="#">Registrar otro análisis</a>
    </section>
  );
}
