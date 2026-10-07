import { type Analysis } from '../api/client';

/** Keep terminal limitations visible when navigating between views of the same snapshot. */
export default function AnalysisNotice({ status }: { status: Analysis['status'] }) {
  if (status === 'PARCIAL') return <p className="error">Resultado parcial: conserva datos útiles, pero hay evidencias o artefactos incompletos. Revisa la cobertura y los diagnósticos antes de sacar conclusiones.</p>;
  if (status === 'FALLIDO') return <p className="error">El análisis falló. Los datos ausentes no equivalen a cero componentes ni a ausencia de vulnerabilidades.</p>;
  return null;
}
