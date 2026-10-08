import type { Evidence, HealthAssessment } from '../api/client';

function Observation({ evidence }: { evidence: Evidence<unknown> }) {
  return <p>{evidence.status} · Fuente: {evidence.source} · Registrada: {new Date(evidence.collectedAt).toLocaleString('es-PE')}
    {evidence.sourceDate && <> · Publicada: {evidence.sourceDate}</>}{evidence.diagnostic && <> · {evidence.diagnostic}</>}</p>;
}

export default function HealthDetails({ assessment }: { assessment: HealthAssessment | undefined }) {
  if (!assessment) return <p>Salud no consultada en esta instantánea.</p>;
  const report = assessment.scorecard.value;
  const covered = Object.values(assessment.indicators).filter(value => value.status === 'DISPONIBLE').length;
  return <details>
    <summary>Salud del repositorio · {covered} de 4 indicadores disponibles</summary>
    <p>Describe el repositorio evaluado; no certifica el artefacto instalado ni demuestra ausencia de vulnerabilidades. Los metadatos del editor no constituyen una prueba criptográfica de procedencia.</p>
    <h3>Resultado OpenSSF Scorecard</h3>
    <Observation evidence={assessment.scorecard} />
    {report && <>
      {assessment.repository.value?.method.includes('SIN_VERSION_DEPS_DEV') && <p>Informe obtenido mediante el POM de Maven Central y la identidad del repositorio en deps.dev.</p>}
      <p>Repositorio: {report.repository} · Commit: <code>{report.repositoryCommit}</code> · Scorecard: {report.toolVersion} · Commit de herramienta: <code>{report.toolCommit}</code></p>
      {report.stale && <p className="error">Informe antiguo: supera 90 días respecto a la consulta guardada. No demuestra el estado actual del repositorio.</p>}
      <p className="muted">Vigencia: {report.freshnessPolicy}. Cobertura: {covered} / 4 ({covered * 25} %). No es una puntuación de riesgo.</p>
    </>}
    <div className="table-scroll"><table>
      <caption>Cuatro indicadores previstos y sus estados individuales</caption>
      <thead><tr><th scope="col">Indicador</th><th scope="col">Valor publicado</th><th scope="col">Evidencia</th></tr></thead>
      <tbody>{['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'].map(name => {
        const evidence = assessment.indicators[name];
        const value = evidence.value;
        return <tr key={name}><th scope="row">{name === 'Dependency-Update-Tool' ? 'Dependency-Update (Dependency-Update-Tool)' : name}</th>
          <td>{value ? `${value.score} / 10` : 'Sin valor'}</td>
          <td><Observation evidence={evidence} />{value && <>
            <p>{value.reason}</p>{value.details.length > 0 && <ul>{value.details.map((detail, index) => <li key={index}>{detail}</li>)}</ul>}
            {/^https:\/\//i.test(value.documentationUrl) && <a href={value.documentationUrl} target="_blank" rel="noreferrer">Documentación de {name}</a>}
          </>}</td></tr>;
      })}</tbody>
    </table></div>
    <details open={!report}><summary>Diagnóstico técnico y fuentes de asociación</summary>
      <h3>Asociación del repositorio</h3>
      <Observation evidence={assessment.repository} />
      {assessment.repository.value && <p><strong>{assessment.repository.value.id}</strong> · Método: {assessment.repository.value.method}</p>}
      <p>Se conservan también los intentos sin datos. No sustituyen el informe obtenido ni sus indicadores.</p>
      {assessment.associationEvidence.map((evidence, index) => <div key={index}><Observation evidence={evidence} /><pre>{evidence.value}</pre></div>)}
    </details>
  </details>;
}
