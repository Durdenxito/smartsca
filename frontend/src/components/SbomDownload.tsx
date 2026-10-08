import { useEffect, useState } from 'react';
import { request, errorMessage } from '../api/client';

interface SbomStatus { available: boolean; schemaVersion: string | null; generatedAt: string | null; sha256: string | null; diagnostic: string | null }

/** Availability and download read stored bytes; failures leave the remaining results visible. */
export default function SbomDownload({ id, revision }: { id: string; revision: number }) {
  const [status, setStatus] = useState<SbomStatus>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    setStatus(undefined); setError('');
    request<SbomStatus>(`/analyses/${encodeURIComponent(id)}/sbom/status`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setStatus(value); })
      .catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)); });
    return () => controller.abort();
  }, [id, revision]);
  async function download() {
    setBusy(true); setError('');
    let url: string | undefined;
    try {
      const response = await fetch(`/api/analyses/${encodeURIComponent(id)}/sbom`);
      if (!response.ok) {
        const problem = await response.json().catch(() => null);
        throw new Error(problem?.detail ?? `Descarga no disponible (${response.status}).`);
      }
      const content = await response.blob();
      if (!content.size || !content.type.startsWith('application/vnd.cyclonedx+json')) throw new Error('El servidor no entregó un SBOM CycloneDX válido.');
      url = URL.createObjectURL(content);
      const link = document.createElement('a');
      link.href = url; link.download = `smartsca-${id}-cyclonedx-1.6.json`;
      document.body.append(link); link.click(); link.remove();
    } catch (error) { setError(errorMessage(error)); }
    finally {
      // Keep the blob alive until the browser has started its download.
      if (url) { const savedUrl = url; setTimeout(() => URL.revokeObjectURL(savedUrl), 1000); }
      setBusy(false);
    }
  }
  return <section aria-labelledby="sbom-title">
    <h2 id="sbom-title">SBOM CycloneDX</h2>
    {error && <p role="alert" className="error">No se pudo consultar o descargar el SBOM: {error}</p>}
    {!status && !error && <p>Consultando disponibilidad del SBOM guardado…</p>}
    {status?.available ? <>
      <p>Esquema {status.schemaVersion} · Generado: {status.generatedAt}</p>
      <p className="identifier">SHA-256 del documento: <code>{status.sha256}</code></p>
      <p>Incluye dependencias seleccionadas, raíces de módulos y conectores de sus rutas, identificados por separado. Conserva perfiles, scopes, versiones y contextos por módulo. No inspecciona binarios, licencias ni alcanzabilidad.</p>
      <button disabled={busy} onClick={() => void download()}>{busy ? 'Descargando SBOM…' : 'Descargar SBOM CycloneDX JSON'}</button>
    </> : status && <p>{status.diagnostic ?? 'SBOM no disponible: este análisis no tiene un documento validado guardado.'}</p>}
  </section>;
}
