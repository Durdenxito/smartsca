import { test, expect, type Page } from '@playwright/test';

const id = '55555555-5555-5555-5555-555555555555';
const purls = [1, 2, 3, 4].map(version => `pkg:maven/demo/library@${version}`);
const evidence = (status: string, value: unknown = null) => ({ status, value, source: 'https://reference.test/', collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2000-01-01', diagnostic: status === 'ERROR' ? '<script>fuente fallida</script>' : null });
const items = purls.map(purl => ({ component: { purl, name: 'demo:library', version: purl.slice(-1), ecosystem: 'maven', metadata: {} }, contexts: [{ module: '.', scope: 'compile', direct: true }, { module: 'app', scope: 'compile', direct: false }] }));
const findings = [
  { componentPurl: purls[0], vulnerabilityId: 'CVE-2026-1111' },
  { componentPurl: purls[1], vulnerabilityId: 'CVE-2026-1111' },
  { componentPurl: purls[1], vulnerabilityId: 'CVE-2026-2222' },
  { componentPurl: purls[2], vulnerabilityId: 'CVE-2026-3333' },
];
function record() {
  return { id, project: { name: 'Referencia de resumen' }, configuration: { scopes: ['compile'] }, status: 'PARCIAL', diagnostics: ['Diagnóstico guardado'],
    dependencyGraph: { rootsByModule: { '.': 'root' } },
    vulnerabilitySnapshot: { findings: [...findings, findings[0]], componentQueries: Object.fromEntries(purls.map((purl, i) => [purl, evidence(i === 3 ? 'ERROR' : 'DISPONIBLE', i === 3 ? null : [])])),
      vulnerabilities: findings.filter((value, i) => i !== 1).map((value, i) => ({ id: value.vulnerabilityId, aliases: [value.vulnerabilityId, `GHSA-ref-${i}`],
        advisories: { [`GHSA-ref-${i}`]: evidence(i === 2 ? 'ERROR' : 'DISPONIBLE', i === 2 ? null : { id: `GHSA-ref-${i}` }) },
        epssByCve: evidence('ERROR'), kevByCve: evidence('ERROR') })) },
    riskSnapshot: { policy: { version: 'reference-priority-v1' }, assessments: findings.map((finding, i) => ({ finding, status: i === 3 ? 'PENDIENTE_REVISION' : 'EVALUADO', score: [90, 84, 0, null][i], level: ['CRITICA', 'ALTA', 'BAJA', null][i] })) },
    healthAssessments: Object.fromEntries(purls.map((purl, i) => [purl, { repository: evidence('DISPONIBLE', { id: 'github.com/demo/library' }),
      scorecard: evidence('DISPONIBLE', { stale: i === 1 }), indicators: Object.fromEntries(['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'].map(name => [name, evidence(i === 2 && name === 'Code-Review' ? 'ERROR' : 'DISPONIBLE', i === 2 && name === 'Code-Review' ? null : { score: 0 })])) }])) };
}
const metric = (page: Page, name: string) => page.getByText(name, { exact: true }).locator('xpath=following-sibling::dd[1]');
const row = (page: Page, table: string, name: string) => page.getByRole('table', { name: table, exact: true }).getByRole('row').filter({ has: page.getByRole('rowheader', { name, exact: true }) }).getByRole('cell');

test('counts correlated findings, versions, zero scores and pending separately and reads persisted coverage after reload', async ({ page }) => {
  const requests: string[] = [];
  await page.route('**/api/analyses/**', route => {
    const url = route.request().url(); requests.push(url);
    if (url.endsWith('/sbom/status')) return route.fulfill({ json: { available: false } });
    return route.fulfill({ json: url.endsWith('/components') ? items : record() });
  });
  await page.goto(`/#analysis/${id}/summary`);
  await expect(metric(page, 'Componentes seleccionados')).toHaveText('4');
  await expect(metric(page, 'Componentes con hallazgos')).toHaveText('3');
  await expect(metric(page, 'Vulnerabilidades únicas identificadas')).toHaveText('3');
  await expect(metric(page, 'Hallazgos componente-vulnerabilidad')).toHaveText('4');
  await expect(metric(page, 'Pendientes de revisión / sin evaluación')).toHaveText('1');
  for (const [name, count] of [['CRITICA', '1'], ['ALTA', '1'], ['MEDIA', '0'], ['BAJA', '1'], ['PENDIENTE_REVISION', '1']])
    await expect(row(page, 'Distribución de prioridades guardadas', name)).toHaveText(count);
  await expect(row(page, 'Cobertura observada de la instantánea', 'Consultas OSV por componente')).toHaveText('3 de 4');
  await expect(row(page, 'Cobertura observada de la instantánea', 'Detalles de avisos OSV')).toHaveText('2 de 3');
  await expect(row(page, 'Cobertura observada de la instantánea', 'Salud con asociación, informe vigente y cuatro checks')).toHaveText('2 de 4');
  await expect(page.getByText(/Resultado parcial:/)).toBeVisible();
  await expect(page.getByText(/Cobertura OSV incompleta/)).toBeVisible();
  await page.getByText('Ver diagnóstico y fechas de OSV', { exact: true }).click();
  await expect(page.getByText('<script>fuente fallida</script>', { exact: false }).first()).toBeVisible();
  await expect(page.locator('script').filter({ hasText: 'fuente fallida' })).toHaveCount(0);
  await page.reload();
  await expect(metric(page, 'Hallazgos componente-vulnerabilidad')).toHaveText('4');
  expect(requests.every(url => url.endsWith(`/analyses/${id}`) || url.endsWith(`/analyses/${id}/components`) || url.endsWith(`/analyses/${id}/sbom/status`))).toBe(true);
});

test('keeps failed, queued and legacy missing snapshots unknown and counts legacy findings pending', async ({ page }) => {
  let data: unknown = { ...record(), status: 'FALLIDO', dependencyGraph: null, vulnerabilitySnapshot: null, healthAssessments: null, riskSnapshot: null };
  let inventoryRequests = 0;
  await page.route('**/api/analyses/**', route => {
    if (route.request().url().endsWith('/sbom/status')) return route.fulfill({ json: { available: false } });
    if (route.request().url().endsWith('/components')) { inventoryRequests++; return route.fulfill({ json: items }); }
    return route.fulfill({ json: data });
  });
  await page.goto(`/#analysis/${id}/summary`);
  await expect(metric(page, 'Componentes seleccionados')).toHaveText('No disponible');
  await expect(metric(page, 'Hallazgos componente-vulnerabilidad')).toHaveText('No disponible');
  await expect(row(page, 'Distribución de prioridades guardadas', 'BAJA')).toHaveText('No disponible');
  await expect(page.getByText(/El análisis falló/)).toBeVisible();
  data = { ...record(), status: 'EN_COLA', dependencyGraph: null, vulnerabilitySnapshot: null, healthAssessments: null, riskSnapshot: null };
  await page.reload();
  await expect(metric(page, 'Componentes seleccionados')).toHaveText('No disponible');
  expect(inventoryRequests).toBe(0);
  data = { ...record(), riskSnapshot: null };
  await page.reload();
  await expect(metric(page, 'Pendientes de revisión / sin evaluación')).toHaveText('4');
  await expect(row(page, 'Distribución de prioridades guardadas', 'BAJA')).toHaveText('0');
  await expect(page.getByText(/Sin evaluación de prioridad guardada/)).toBeVisible();
});

test('preserves known findings on inventory failure and recovers the same identifier after retry', async ({ page }) => {
  let failure = true;
  await page.route(`**/api/analyses/${id}/sbom/status`, route => route.fulfill({ json: { available: false } }));
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: record() }));
  await page.route(`**/api/analyses/${id}/components`, route => failure
    ? route.fulfill({ status: 503, json: { detail: 'Consulta de inventario temporalmente fallida' } }) : route.fulfill({ json: items }));
  await page.goto(`/#analysis/${id}/summary`);
  await expect(page.getByRole('alert')).toContainText('Consulta de inventario temporalmente fallida');
  await expect(metric(page, 'Componentes seleccionados')).toHaveText('No disponible');
  await expect(metric(page, 'Hallazgos componente-vulnerabilidad')).toHaveText('4');
  failure = false;
  await page.getByRole('button', { name: 'Actualizar resumen' }).click();
  await expect(metric(page, 'Componentes seleccionados')).toHaveText('4');
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('opens a real persisted analysis summary and preserves source failures and totals on reload', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Proyecto Maven').selectOption('maven-direct');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  await page.getByRole('link', { name: 'Consultar resumen y cobertura' }).click();
  await expect(page.getByRole('heading', { name: 'Resumen y cobertura del análisis' })).toBeVisible();
  await expect(metric(page, 'Componentes seleccionados')).toHaveText(/^[1-9]\d*$/);
  const total = await metric(page, 'Componentes seleccionados').innerText();
  await expect(metric(page, 'Hallazgos componente-vulnerabilidad')).toHaveText('0');
  await expect(row(page, 'Cobertura observada de la instantánea', 'Consultas OSV por componente')).toHaveText(`0 de ${total}`);
  await expect(page.getByText(/Cero hallazgos identificados no demuestra/)).toBeVisible();
  await page.reload();
  await expect(metric(page, 'Componentes seleccionados')).toHaveText(total);
  await page.getByRole('link', { name: 'Inventario', exact: true }).click();
  await expect(page.getByText(/Resultado parcial:/)).toBeVisible();
  await page.getByRole('link', { name: 'Explorar grafo y rutas' }).click();
  await expect(page.getByText(/Resultado parcial:/)).toBeVisible();
});
