import { test, expect } from '@playwright/test';

const id = '33333333-3333-3333-3333-333333333333', purl = 'pkg:maven/demo/library@1';
const observation = (status: string, value: unknown = null, diagnostic: string | null = null) => ({
  source: 'https://example.test/evidence', collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-01-01', status, value, diagnostic,
});
const record = {
  id, project: { name: 'Referencia HTTP de estado' }, configuration: { modules: ['.'], profiles: [], scopes: ['compile'], environmentId: 'java-21', declaredDeployment: null },
  status: 'PARCIAL', currentStep: 'INVENTARIO_Y_EVIDENCIAS_DISPONIBLES', createdAt: '2026-10-07T00:00:00Z', startedAt: '2026-10-07T00:00:01Z', finishedAt: '2026-10-07T00:00:05Z',
  diagnostics: ['Prioridad y SBOM pendientes.'], environmentVersions: {}, dependencyGraph: null, vulnerabilitySnapshot: null, healthAssessments: null,
};

test('summarizes stored source observations including inner failures, absence and stale reports after reload', async ({ page }) => {
  const advisory = observation('DISPONIBLE', { id: 'GHSA-demo' });
  const absent = observation('NO_APLICABLE', null, 'Aviso sin CVE; señal no aplicable.');
  const vulnerability = {
    id: 'CVE-2026-1234', advisories: { 'GHSA-demo': advisory },
    epssByCve: observation('DISPONIBLE', { 'CVE-2026-1234': observation('ERROR', null, 'FIRST EPSS no respondió.') }),
    kevByCve: observation('DISPONIBLE', { 'CVE-2026-1234': observation('DISPONIBLE', false) }),
  };
  const snapshot = {
    ...record,
    vulnerabilitySnapshot: { componentQueries: {
      ...Object.fromEntries(Array.from({ length: 21 }, (_, index) => [`pkg:maven/demo/library${index}@1`, observation('DISPONIBLE', [])])),
      [purl]: observation('ERROR', null, '<script>no se ejecuta</script>'),
    }, findings: [], vulnerabilities: [
      vulnerability, { id: 'GHSA-no-cve', advisories: {}, epssByCve: absent, kevByCve: absent },
    ] },
    healthAssessments: { [purl]: { scorecard: observation('DISPONIBLE', { stale: true }), indicators: {
      Maintained: observation('DISPONIBLE', { score: 0 }), 'Security-Policy': observation('NO_DISPONIBLE', null, 'Indicador no publicado.'),
      'Code-Review': observation('ERROR', null, 'Indicador duplicado.'), 'Dependency-Update-Tool': observation('NO_APLICABLE'),
    } } },
  };
  const requests: string[] = [];
  await page.route('**/api/analyses/**', route => {
    requests.push(route.request().url());
    return route.request().url().endsWith(`/api/analyses/${id}`) ? route.fulfill({ json: snapshot }) : route.abort();
  });
  await page.goto(`/#analysis/${id}`);
  const table = page.getByRole('table', { name: 'Disponibilidad y diagnóstico por fuente', exact: true });
  const row = (name: RegExp) => table.getByRole('row').filter({ has: page.getByRole('rowheader', { name }) });
  await expect(row(/^OSV/)).toContainText('ERROR: 1');
  await expect(row(/^OSV/)).toContainText('DISPONIBLE: 22');
  await expect(row(/^FIRST EPSS/)).toContainText('ERROR: 1');
  await expect(row(/^FIRST EPSS/)).toContainText('DISPONIBLE: 0');
  await expect(row(/^FIRST EPSS/)).toContainText('NO_APLICABLE: 1');
  await row(/^FIRST EPSS/).getByText('Ver diagnóstico y fechas de FIRST EPSS', { exact: true }).click();
  await expect(row(/^FIRST EPSS/)).toContainText('FIRST EPSS no respondió.');
  await expect(row(/^FIRST EPSS/)).toContainText('CVE-2026-1234');
  await expect(row(/^FIRST EPSS/)).toContainText('Fecha de la fuente: 2026-01-01');
  await expect(row(/^CISA KEV/)).toContainText('DISPONIBLE: 1');
  await expect(row(/^CISA KEV/)).toContainText('NO_APLICABLE: 1');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('DISPONIBLE: 2');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('ERROR: 1');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('NO_DISPONIBLE: 1');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('NO_APLICABLE: 1');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('1 informes antiguos');
  const detail = row(/^OSV/).getByText('Ver diagnóstico y fechas de OSV', { exact: true });
  await detail.focus(); await page.keyboard.press('Enter');
  await expect(row(/^OSV/).locator('details > ul > li')).toHaveCount(20);
  await expect(page.getByText('<script>no se ejecuta</script>', { exact: false })).toBeVisible();
  await expect(page.locator('script').filter({ hasText: 'no se ejecuta' })).toHaveCount(0);
  await page.reload();
  await expect(row(/^FIRST EPSS/)).toContainText('ERROR: 1');
  await expect(row(/^OpenSSF Scorecard/)).toContainText('1 informes antiguos');
  expect(requests.length).toBeGreaterThanOrEqual(2);
  expect(requests.every(url => url.endsWith(`/api/analyses/${id}`))).toBe(true);
});

test('polls queued and running states then preserves terminal failure diagnostics and legacy missing observations', async ({ page }) => {
  let response = { ...record, status: 'EN_COLA', currentStep: 'REGISTRADO', startedAt: null as string | null, finishedAt: null as string | null, diagnostics: [] as string[] };
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: response }));
  await page.goto(`/#analysis/${id}`);
  const table = page.getByRole('table', { name: 'Disponibilidad y diagnóstico por fuente', exact: true });
  await expect(page.getByRole('status')).toHaveText('EN_COLA');
  await expect(table.getByText('Aún sin observaciones guardadas.', { exact: true })).toHaveCount(4);
  response = { ...response, status: 'EN_EJECUCION', currentStep: 'RESOLVIENDO_MAVEN', startedAt: record.startedAt };
  await expect(page.getByRole('status')).toHaveText('EN_EJECUCION', { timeout: 8_000 });
  response = { ...response, status: 'FALLIDO', currentStep: 'RESOLUCION_FALLIDA', finishedAt: record.finishedAt, diagnostics: ['Se agotó el tiempo de resolución Maven.'] };
  await expect(page.getByRole('status')).toHaveText('FALLIDO', { timeout: 8_000 });
  await expect(page.getByText('Se agotó el tiempo de resolución Maven.', { exact: true })).toBeVisible();
  await expect(table.getByText('Sin observaciones en esta instantánea.', { exact: true })).toHaveCount(4);
  await expect(table).not.toContainText('DISPONIBLE: 0');
  await page.reload();
  await expect(page.getByRole('status')).toHaveText('FALLIDO');
  response = { ...response, status: 'COMPLETO', currentStep: 'FINALIZADO', diagnostics: [] };
  await page.reload();
  await expect(page.getByRole('status')).toHaveText('COMPLETO');
  await expect(table.getByText('Sin observaciones en esta instantánea.', { exact: true })).toHaveCount(4);
});
