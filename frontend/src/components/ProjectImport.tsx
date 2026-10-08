import { useState, type FormEvent } from 'react';
import { request, errorMessage, type Project } from '../api/client';

/** Imports first; the existing catalog form then selects modules/profiles and registers an analysis. */
export default function ProjectImport({ onImported }: { onImported: (project: Project) => void }) {
  const [kind, setKind] = useState('zip');
  const [file, setFile] = useState<File>();
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (busy) return;
    setBusy(true); setError(''); setSuccess('');
    try {
      let project: Project;
      if (kind === 'zip') {
        if (!file || !file.size || file.size > 10 * 1024 * 1024) throw new Error('Selecciona un ZIP no vacío de hasta 10 MiB.');
        const body = new FormData(); body.append('file', file);
        project = await request<Project>('/projects/import/zip', { method: 'POST', body });
      } else {
        project = await request<Project>('/projects/import/git', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url.trim() }) });
      }
      onImported(project);
      setSuccess(`Proyecto importado: ${project.name}. Seleccionado para configurar y registrar el análisis.`);
    } catch (error) { setError(errorMessage(error)); }
    finally { setBusy(false); }
  }
  return <section aria-labelledby="project-import-title">
    <h2 id="project-import-title">Importar proyecto propio</h2>
    <p>Proyecto Java/Maven con pom.xml en la raíz o dentro de una única carpeta. El catálogo conserva la copia y su referencia para futuras ejecuciones.</p>
    <form onSubmit={submit}>
      <fieldset disabled={busy}>
        <legend>Origen del proyecto</legend>
        <label htmlFor="import-kind">Tipo de entrada</label>
        <select id="import-kind" value={kind} onChange={event => { setKind(event.target.value); setFile(undefined); setError(''); setSuccess(''); }}>
          <option value="zip">Archivo ZIP</option><option value="git">Repositorio público de GitHub</option>
        </select>
        {kind === 'zip' ? <><label htmlFor="project-zip">Archivo ZIP del proyecto</label>
          <input key="zip" id="project-zip" type="file" accept=".zip,application/zip" required onChange={event => setFile(event.target.files?.[0])} />
          <p>Máximo 10 MiB comprimidos, 25 MiB extraídos y 2048 entradas. Prepara el ZIP sin target, node_modules, .git ni archivos de secretos.</p></>
          : <><label htmlFor="project-git">URL del repositorio público</label>
            <input key="git" id="project-git" type="url" maxLength={255} required placeholder="https://github.com/propietario/repositorio" value={url} onChange={event => setUrl(event.target.value)} />
            <p>Se guarda el commit de la rama predeterminada. Solo GitHub HTTPS público, sin credenciales ni submódulos; archivo descargado de hasta 8 MiB.</p></>}
        <p>No se admiten enlaces, extensiones de compilación ni opciones Maven/JVM del proyecto. Padres Maven con coordenadas literales, locales o de Maven Central. Catálogo limitado a veinte importaciones.</p>
        <button type="submit">{busy ? 'Importando proyecto…' : 'Importar proyecto'}</button>
      </fieldset>
    </form>
    {busy && <p role="status">Validando y guardando el proyecto…</p>}
    {error && <p role="alert" className="error">No se pudo importar: {error}</p>}
    {success && <p role="status">{success}</p>}
  </section>;
}
