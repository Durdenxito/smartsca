import { useEffect, useState } from 'react';
import { request, errorMessage } from '../api/client';
import ArtifactDownload from './ArtifactDownload';

interface SbomStatus { available: boolean; schemaVersion: string | null; generatedAt: string | null; sha256: string | null; diagnostic: string | null }

/** Availability and download read stored bytes; failures leave the remaining results visible. */
export default function SbomDownload({ id, revision }: { id: string; revision: number }) {
  const [status, setStatus] = useState<SbomStatus>();
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    setStatus(undefined); setError('');
    request<SbomStatus>(`/analyses/${encodeURIComponent(id)}/sbom/status`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setStatus(value); })
      .catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, revision]);
  return <section aria-labelledby="sbom-title">
    <h2 id="sbom-title">SBOM CycloneDX</h2>
    {error && <p role="alert" className="error">No se pudo consultar o descargar el SBOM: {error}</p>}
    {!status && !error && <p>Consultando disponibilidad del SBOM guardado…</p>}
    {status?.available ? <>
      <p>Esquema {status.schemaVersion} · Generado: {status.generatedAt}</p>
      <p className="identifier">SHA-256 del documento: <code>{status.sha256}</code></p>
      <p>Incluye dependencias seleccionadas, raíces de módulos y conectores de sus rutas, identificados por separado. Conserva perfiles, scopes, versiones y contextos por módulo. No inspecciona binarios, licencias ni alcanzabilidad.</p>
      <ArtifactDownload url={`/api/analyses/${encodeURIComponent(id)}/sbom`} filename={`smartsca-${id}-cyclonedx-1.6.json`}
        contentType="application/vnd.cyclonedx+json" label="Descargar SBOM CycloneDX JSON" />
    </> : status && <p>{status.diagnostic ?? 'SBOM no disponible: este análisis no tiene un documento validado guardado.'}</p>}
  </section>;
}
