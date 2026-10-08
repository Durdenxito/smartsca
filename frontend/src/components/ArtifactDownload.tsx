import { useState } from 'react';
import { errorMessage } from '../api/client';

/** Native download with HTTP/type checks; errors leave the saved results visible. */
export default function ArtifactDownload({ url, filename, contentType, label }: { url: string; filename: string; contentType: string; label: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function download() {
    setBusy(true); setError('');
    let objectUrl: string | undefined;
    try {
      const response = await fetch(url);
      if (!response.ok) {
        const problem = await response.json().catch(() => null);
        throw new Error(problem?.detail ?? `Descarga no disponible (${response.status}).`);
      }
      const content = await response.blob();
      if (!content.size || content.type.split(';')[0] !== contentType) throw new Error('El servidor no entregó el documento JSON esperado.');
      objectUrl = URL.createObjectURL(content);
      const link = document.createElement('a');
      link.href = objectUrl; link.download = filename;
      document.body.append(link); link.click(); link.remove();
    } catch (error) { setError(errorMessage(error)); }
    finally {
      // Keep the blob alive until the browser has started its download.
      if (objectUrl) { const savedUrl = objectUrl; setTimeout(() => URL.revokeObjectURL(savedUrl), 1000); }
      setBusy(false);
    }
  }
  return <>
    {error && <p role="alert" className="error">No se pudo descargar: {error}</p>}
    <button disabled={busy} onClick={() => void download()}>{busy ? 'Descargando…' : label}</button>
  </>;
}
