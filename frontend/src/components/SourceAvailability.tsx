import { type Analysis, type Evidence } from '../api/client';

/** Summarizes stored observations, including inner CVE/check failures; reading never queries providers. */
export default function SourceAvailability({ analysis }: { analysis: Pick<Analysis, 'status' | 'vulnerabilitySnapshot' | 'healthAssessments'> }) {
  const snapshot = analysis.vulnerabilitySnapshot;
  const vulnerabilities = snapshot?.vulnerabilities ?? [];
  const health = Object.entries(analysis.healthAssessments ?? {});
  type Observation = { subject: string; evidence: Evidence<unknown> };
  const signals = (field: 'epssByCve' | 'kevByCve'): Observation[] => vulnerabilities.flatMap((value): Observation[] => {
    const records = Object.entries(value[field].value ?? {});
    return records.length ? records.map(([subject, evidence]) => ({ subject, evidence }))
      : [{ subject: value.id, evidence: value[field] }];
  });
  const sources: { name: string; description: string; observations: Observation[] }[] = [
    { name: 'OSV', description: 'Consultas por componente y detalles de avisos.', observations: [
      ...Object.entries(snapshot?.componentQueries ?? {}).map(([purl, evidence]) => ({ subject: `Componente ${purl}`, evidence })),
      ...vulnerabilities.flatMap(value => Object.entries(value.advisories).map(([id, evidence]) => ({ subject: `Aviso ${id}`, evidence }))),
    ] },
    { name: 'FIRST EPSS', description: 'Señales por CVE o motivo de ausencia del aviso.', observations: signals('epssByCve') },
    { name: 'CISA KEV', description: 'Señales por CVE o motivo de ausencia del aviso.', observations: signals('kevByCve') },
    { name: 'OpenSSF Scorecard', description: 'Informes e indicadores por componente.', observations: health.flatMap(([purl, value]) => [
      { subject: `${purl} · Informe`, evidence: value.scorecard },
      ...Object.entries(value.indicators).map(([name, evidence]) => ({ subject: `${purl} · ${name}`, evidence })),
    ]) },
  ];
  const stale = health.filter(([, value]) => value.scorecard.value?.stale).length;
  const states = ['ERROR', 'NO_DISPONIBLE', 'NO_APLICABLE', 'DISPONIBLE'] as const;
  return <section aria-labelledby="source-availability-title">
    <h2 id="source-availability-title">Disponibilidad de fuentes</h2>
    <p>Estados de las observaciones guardadas, no cantidades de vulnerabilidades. Los errores y ausencias limitan los resultados; no equivalen a cero vulnerabilidades.</p>
    <p className="muted">Sin observaciones no se confirma que la fuente haya respondido. Las fechas corresponden a esta instantánea; abrirla no vuelve a consultar las fuentes.</p>
    <div className="table-scroll"><table>
      <caption>Disponibilidad y diagnóstico por fuente</caption>
      <thead><tr><th scope="col">Fuente</th><th scope="col">Observaciones guardadas</th><th scope="col">Diagnóstico y fechas</th></tr></thead>
      <tbody>{sources.map(({ name, description, observations }) => <tr key={name}>
        <th scope="row">{name}<p className="muted">{description}</p></th>
        <td>{observations.length ? <ul>{states.map(status =>
          <li key={status}>{status}: {observations.filter(value => value.evidence.status === status).length}</li>)}</ul>
          : analysis.status === 'EN_COLA' || analysis.status === 'EN_EJECUCION' ? 'Aún sin observaciones guardadas.' : 'Sin observaciones en esta instantánea.'}</td>
        <td>{observations.length > 0 && <details>
          <summary>Ver diagnóstico y fechas de {name}</summary>
          <p>Mostrando hasta 20 observaciones; consulta inventario o hallazgos para el detalle por componente.</p>
          <ul>{[...observations].sort((a, b) => states.indexOf(a.evidence.status) - states.indexOf(b.evidence.status))
            .slice(0, 20).map(({ subject, evidence }, index) => <li key={index}>
              <strong>{subject}</strong> · {evidence.status} · Fuente: {evidence.source}
              {' · '}Registrada: {new Date(evidence.collectedAt).toLocaleString('es-PE')}
              {evidence.sourceDate && <> · Fecha de la fuente: {evidence.sourceDate}</>}
              {evidence.diagnostic && <> · {evidence.diagnostic}</>}
            </li>)}</ul>
        </details>}
          {name === 'OpenSSF Scorecard' && stale > 0 && <p className="error">{stale} informes antiguos según la advertencia guardada. No demuestran el estado actual del repositorio.</p>}
        </td>
      </tr>)}</tbody>
    </table></div>
  </section>;
}
