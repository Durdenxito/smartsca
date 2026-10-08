export interface Project {
  id: string;
  name: string;
  sourceReference: string;
  analyzedReference: string;
  modules: string[];
  profiles: string[];
}

export interface AnalysisConfiguration {
  modules: string[];
  profiles: string[];
  scopes: string[];
  environmentId: string;
  declaredDeployment: string | null;
}

export interface Catalog {
  projects: Project[];
  defaults: AnalysisConfiguration;
  scopes: string[];
}

export interface Analysis {
  id: string;
  project: Project;
  configuration: AnalysisConfiguration;
  status: 'EN_COLA' | 'EN_EJECUCION' | 'COMPLETO' | 'PARCIAL' | 'FALLIDO';
  currentStep: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  engineVersion: string;
  diagnostics: string[];
  environmentVersions: Record<string, string>;
  dependencyGraph: { rootsByModule: Record<string, string>; components: Record<string, Component>; edges: DependencyEdge[] } | null;
  vulnerabilitySnapshot: VulnerabilitySnapshot | null;
  healthAssessments: Record<string, HealthAssessment> | null;
  riskSnapshot: { policy: { version: string; weights: Record<string, number>; thresholds: Record<string, number>; formula: string;
    missingEvidenceRules: string[]; tieBreakRules: string[]; cvssSelection: string; calculator: string }; evaluatedAt: string; assessments: RiskAssessment[] } | null;
}

export interface AnalysisHistory {
  items: { id: string; projectId: string; projectName: string; sourceReference: string; analyzedReference: string;
    configuration: AnalysisConfiguration; status: Analysis['status']; createdAt: string; startedAt: string | null; finishedAt: string | null }[];
  offset: number; nextOffset: number | null; navigationLimited: boolean;
}

export type AnalysisStatusView = Pick<Analysis, 'id' | 'configuration' | 'status' | 'currentStep' | 'createdAt' | 'startedAt' | 'finishedAt' | 'diagnostics' | 'environmentVersions'>
  & { projectName: string; graphAvailable: boolean; vulnerabilitiesAvailable: boolean };
export type AnalysisSources = Pick<Analysis, 'vulnerabilitySnapshot' | 'healthAssessments'>;
export type AnalysisResolution = Pick<Analysis, 'status' | 'dependencyGraph'> & { projectName: string; scopes: string[] };
export type AnalysisInventory = Pick<Analysis, 'status' | 'healthAssessments'> & {
  projectName: string; scopes: string[]; rootsByModule: Record<string, string>; items: ComponentItem[]; vulnerabilitiesAvailable: boolean;
};

export interface RiskAssessment {
  finding: { componentPurl: string; vulnerabilityId: string }; policyVersion: string;
  status: 'EVALUADO' | 'PENDIENTE_REVISION'; score: number | null; level: 'CRITICA' | 'ALTA' | 'MEDIA' | 'BAJA' | null;
  knownExploited: boolean; explanation: string[]; limits: string[];
  contributions: { dimension: string; weight: number; points: number | null; rule: string; usedEvidence: Evidence<string>[] }[];
}

export interface HealthAssessment {
  componentPurl: string;
  repository: Evidence<{ id: string; method: string }>;
  scorecard: Evidence<{ repository: string; repositoryCommit: string; toolVersion: string; toolCommit: string; stale: boolean; freshnessPolicy: string }>;
  indicators: Record<string, Evidence<{ name: string; score: number; reason: string; details: string[]; documentationUrl: string }>>;
  associationEvidence: Evidence<string>[];
}

export interface Evidence<T> {
  source: string; collectedAt: string; sourceDate: string | null;
  status: 'DISPONIBLE' | 'NO_DISPONIBLE' | 'NO_APLICABLE' | 'ERROR'; value: T | null; diagnostic: string | null;
}
export interface Advisory {
  id: string; aliases: string[]; summary: string; description: string; references: string[];
  affected: { ecosystem: string; name: string; ranges: string; versions: string[]; fixedVersions: string[]; cvss: Advisory['cvss'] }[];
  cvss: Evidence<{ version: string; vector: string; source: string }[]>; rawResponse: string;
}
export interface Vulnerability {
  id: string; aliases: string[]; advisories: Record<string, Evidence<Advisory>>;
  epssByCve: Evidence<Record<string, Evidence<{ probability: number; percentile: number }>>>;
  kevByCve: Evidence<Record<string, Evidence<boolean>>>;
}
export interface VulnerabilitySnapshot {
  findings: { componentPurl: string; vulnerabilityId: string }[];
  vulnerabilities: Vulnerability[]; componentQueries: Record<string, Evidence<string[]>>;
}

export interface Component {
  purl: string; ecosystem: string; name: string; version: string; metadata: Record<string, string>;
}
export interface DependencyEdge {
  parentPurl: string; childPurl: string;
  context: { module: string; originalScope: string; normalizedContext: string };
}
export interface Neighborhood {
  module: string; root: Component; focus: Component; neighbors: Component[]; edges: DependencyEdge[];
  offset: number; totalNeighbors: number; nextOffset: number | null;
}
export interface Routes {
  routes: { module: string; rootPurl: string; steps: DependencyEdge[] }[];
  components: Record<string, Component>; offset: number; nextOffset: number | null; searchLimited: boolean;
}
export interface ComponentItem {
  component: Component;
  contexts: { module: string; scope: string; originalScope: string; direct: boolean }[];
}

/** Same-origin API; unsuccessful responses use the server's public ProblemDetail. */
export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, options);
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.detail ?? `No se pudo completar la solicitud (${response.status}).`);
  }
  return response.json() as Promise<T>;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'No se pudo conectar con el servidor.';
}
