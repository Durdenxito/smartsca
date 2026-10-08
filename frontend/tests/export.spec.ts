import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('exports a real persisted partial snapshot, coverage and unknown signals through a keyboard download', async ({ page, request }) => {
  await page.goto('/');
  await page.getByLabel('Proyecto Maven').selectOption('maven-multimodule');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  const id = page.url().split('/').at(-1)!;
  const before = await (await request.get(`/api/analyses/${id}`)).json();
  const inventory = await (await request.get(`/api/analyses/${id}/components`)).json();
  await page.getByRole('link', { name: 'Consultar resumen y cobertura' }).click();
  const button = page.getByRole('button', { name: 'Descargar resultados JSON' });
  await expect(button).toBeEnabled();
  await button.focus();
  const event = page.waitForEvent('download'); await page.keyboard.press('Enter');
  const download = await event;
  expect(download.suggestedFilename()).toBe(`smartsca-${id}-analysis-v1.json`);
  const exported = JSON.parse(await readFile((await download.path())!, 'utf8'));
  expect(exported.schemaVersion).toBe('1.0');
  expect(exported.schemaVersion).not.toBe(exported.analysis.riskSnapshot.policy.version);
  expect(exported.analysis).toEqual(before);
  expect(exported.selectedComponentPurls).toEqual(inventory.map((item: { component: { purl: string } }) => item.component.purl));
  expect(exported.coverage.osvComponentQueries).toEqual({ available: 0, total: inventory.length });
  const coverage = page.getByRole('table', { name: 'Cobertura observada de la instantánea' });
  const names = { osvComponentQueries: 'Consultas OSV por componente', osvAdvisoryDetails: 'Detalles de avisos OSV',
    health: 'Salud con asociación, informe vigente y cuatro checks', evaluatedFindings: 'Hallazgos con prioridad evaluada' };
  for (const [key, name] of Object.entries(names)) {
    const counts = exported.coverage[key];
    await expect(coverage.getByRole('row').filter({ has: page.getByRole('rowheader', { name, exact: true }) }).getByRole('cell'))
      .toHaveText(counts.available == null || counts.total == null ? 'No disponible' : `${counts.available} de ${counts.total}`);
  }
  expect(exported.analysis.vulnerabilitySnapshot.componentQueries[exported.selectedComponentPurls[0]].value).toBeNull();
  expect(exported.sectionsNotObtained).toEqual([]);
  expect(exported.limitations.length).toBeGreaterThan(0);
  await page.reload(); await expect(button).toBeEnabled();
  const again = page.waitForEvent('download'); await button.click();
  expect(JSON.parse(await readFile((await (await again).path())!, 'utf8'))).toEqual(exported);
  expect(await (await request.get(`/api/analyses/${id}`)).json()).toEqual(before);
});

test('downloads failed diagnostics and unknown sections, preserves results on HTTP/type errors and retries', async ({ page }) => {
  const id = '88888888-8888-8888-8888-888888888888';
  const analysis = { id, project: { name: 'Diagnóstico conservado' }, configuration: { scopes: ['compile'] }, status: 'FALLIDO',
    diagnostics: ['<script>Resolución fallida</script>'], dependencyGraph: null, vulnerabilitySnapshot: null, healthAssessments: null, riskSnapshot: null };
  const exported = { schemaVersion: '1.0', analysis, selectedComponentPurls: null, coverage: { osvComponentQueries: { available: null, total: null } },
    sectionsNotObtained: ['dependencyGraph', 'vulnerabilitySnapshot', 'healthAssessments', 'riskSnapshot'], limitations: ['Sin resolución'] };
  let mode = 'error';
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: analysis }));
  await page.route(`**/api/analyses/${id}/sbom/status`, route => route.fulfill({ json: { available: false } }));
  await page.route(`**/api/analyses/${id}/export`, route => mode === 'error'
    ? route.fulfill({ status: 503, json: { detail: 'Almacenamiento no disponible' } }) : mode === 'html'
      ? route.fulfill({ contentType: 'text/html', body: '<html>Error</html>' }) : route.fulfill({ json: exported }));
  await page.goto(`/#analysis/${id}/summary`);
  const button = page.getByRole('button', { name: 'Descargar resultados JSON' });
  await button.click();
  await expect(page.getByRole('alert')).toContainText('Almacenamiento no disponible');
  await expect(page.getByText('Diagnóstico conservado · Estado: FALLIDO')).toBeVisible();
  await expect(page.getByText('<script>Resolución fallida</script>', { exact: true })).toBeVisible();
  mode = 'html'; await button.click();
  await expect(page.getByRole('alert')).toContainText('documento JSON esperado');
  mode = 'ok';
  const event = page.waitForEvent('download'); await button.click();
  expect(JSON.parse(await readFile((await (await event).path())!, 'utf8'))).toEqual(exported);
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByText('Componentes seleccionados', { exact: true }).locator('xpath=following-sibling::dd[1]')).toHaveText('No disponible');
});
