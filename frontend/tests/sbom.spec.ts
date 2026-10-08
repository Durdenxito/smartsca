import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

test('downloads byte-stable CycloneDX from a real partial analysis without registering another execution', async ({ page, request }) => {
  await page.goto('/');
  await page.getByLabel('Proyecto Maven').selectOption('maven-multimodule');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  const id = page.url().split('/').at(-1)!;
  const analysis = await (await request.get(`/api/analyses/${id}`)).json();
  const inventory = await (await request.get(`/api/analyses/${id}/components`)).json();
  await page.getByRole('link', { name: 'Consultar resumen y cobertura' }).click();
  const button = page.getByRole('button', { name: 'Descargar SBOM CycloneDX JSON' });
  await expect(button).toBeEnabled();
  await button.focus();
  const firstDownload = page.waitForEvent('download');
  await page.keyboard.press('Enter');
  const first = await firstDownload;
  expect(first.suggestedFilename()).toBe(`smartsca-${id}-cyclonedx-1.6.json`);
  const bytes = await readFile((await first.path())!);
  const bom = JSON.parse(bytes.toString('utf8'));
  expect(bom.bomFormat).toBe('CycloneDX'); expect(bom.specVersion).toBe('1.6');
  expect(bom.serialNumber).toBe(`urn:uuid:${id}`);
  const selected = bom.components.filter((value: { properties: { name: string; value: string }[] }) => value.properties.some(p => p.name === 'smartsca:role' && p.value === 'selected-dependency'));
  expect(selected.map((value: { purl: string }) => value.purl).sort()).toEqual(inventory.map((value: { component: { purl: string } }) => value.component.purl).sort());
  const status = await (await request.get(`/api/analyses/${id}/sbom/status`)).json();
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(status.sha256);
  const contexts = JSON.parse(bom.properties.find((value: { name: string }) => value.name === 'smartsca:dependency-contexts').value);
  expect(contexts.filter((edge: { childPurl: string }) => edge.childPurl === 'pkg:maven/org.apache.commons/commons-lang3@3.14.0')).toHaveLength(3);
  await page.reload();
  await expect(button).toBeEnabled();
  const secondDownload = page.waitForEvent('download'); await button.click();
  expect(await readFile((await (await secondDownload).path())!)).toEqual(bytes);
  expect(await (await request.get(`/api/analyses/${id}`)).json()).toEqual(analysis);
});

test('reports unavailable legacy artifacts and failed downloads while keeping the saved summary', async ({ page }) => {
  const id = '77777777-7777-7777-7777-777777777777';
  let available = false;
  let statusFailed = false;
  const downloads: string[] = [];
  page.on('download', value => downloads.push(value.suggestedFilename()));
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: { id, project: { name: 'Resultados conservados' }, configuration: { scopes: ['compile'] }, status: 'PARCIAL', diagnostics: [], dependencyGraph: null, vulnerabilitySnapshot: null, healthAssessments: null, riskSnapshot: null } }));
  await page.route(`**/api/analyses/${id}/sbom/status`, route => statusFailed
    ? route.fulfill({ status: 503, json: { detail: 'Almacenamiento no disponible' } })
    : route.fulfill({ json: { available, schemaVersion: available ? '1.6' : null, generatedAt: available ? '2026-10-07T00:00:00Z' : null, sha256: available ? 'a'.repeat(64) : null,
      diagnostic: available ? null : 'SBOM no disponible: no hay documento validado guardado.' } }));
  await page.route(`**/api/analyses/${id}/sbom`, route => route.fulfill({ status: 409, json: { detail: 'SBOM no disponible: integridad no verificada.' } }));
  await page.goto(`/#analysis/${id}/summary`);
  await expect(page.getByText('SBOM no disponible: no hay documento validado guardado.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Descargar SBOM CycloneDX JSON' })).toHaveCount(0);
  available = true; await page.getByRole('button', { name: 'Actualizar resumen' }).click();
  await page.getByRole('button', { name: 'Descargar SBOM CycloneDX JSON' }).click();
  await expect(page.getByRole('alert')).toContainText('integridad no verificada');
  await expect(page.getByText('Resultados conservados · Estado: PARCIAL')).toBeVisible();
  expect(downloads).toEqual([]);
  statusFailed = true; await page.reload();
  await expect(page.getByRole('alert')).toContainText('Almacenamiento no disponible');
  await expect(page.getByRole('button', { name: 'Descargar SBOM CycloneDX JSON' })).toHaveCount(0);
});
