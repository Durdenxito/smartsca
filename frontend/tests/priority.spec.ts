import { test, expect } from '@playwright/test';

test('keeps persisted ranking, pending KEV and score zero distinct and filters/explains priority after reload', async ({ page }) => {
  const id = '44444444-4444-4444-4444-444444444444', purl = 'pkg:maven/demo/library@1';
  const observation = { source: 'https://reference.test/', collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-10-06', status: 'DISPONIBLE', value: '<script>evidencia conservada</script>', diagnostic: null };
  const ids = ['CVE-2026-1111', 'CVE-2026-2222', 'CVE-2026-3333'];
  const findings = ids.map(vulnerabilityId => ({ componentPurl: purl, vulnerabilityId }));
  const assessments = findings.map((finding, index) => ({
    finding, policyVersion: 'reference-priority-v1', status: index === 0 ? 'PENDIENTE_REVISION' : 'EVALUADO',
    score: index === 0 ? null : index === 1 ? 84 : 0, level: index === 0 ? null : index === 1 ? 'ALTA' : 'BAJA', knownExploited: index === 0,
    explanation: ['Regla de referencia; falta EPSS para el primer hallazgo.'], limits: ['Alcanzabilidad no analizada.'],
    contributions: [{ dimension: 'CVSS', weight: 50, points: index === 0 ? null : 49, rule: 'CVSS base / 10 × 50', usedEvidence: [observation] }],
  }));
  let calls = 0;
  await page.route(`**/api/analyses/${id}`, route => {
    calls++;
    return route.fulfill({ json: {
      id, project: { name: 'Referencia HTTP de prioridad' }, status: 'PARCIAL', configuration: { scopes: ['compile'] }, dependencyGraph: { rootsByModule: { '.': 'root' } },
      vulnerabilitySnapshot: { findings: [...findings].reverse(), componentQueries: {}, vulnerabilities: ids.map(value => ({ id: value, aliases: [value],
        advisories: {}, epssByCve: { ...observation, value: null, status: 'NO_DISPONIBLE' }, kevByCve: { ...observation, value: { [value]: { ...observation, value: value === ids[0] } } } })) },
      riskSnapshot: { evaluatedAt: '2026-10-07T00:00:05Z', policy: { version: 'reference-priority-v1', weights: { CVSS: 50, EPSS: 20, CONTEXTO: 20, SALUD: 10 },
        thresholds: { CRITICA: 90, ALTA: 70, MEDIA: 40, BAJA: 0 }, formula: 'Fórmula guardada de referencia.', missingEvidenceRules: ['Sin evidencia esencial: pendiente.'],
        tieBreakRules: ['KEV confirmado primero'], cvssSelection: 'Selección CVSS guardada', calculator: 'Calculador de referencia' }, assessments },
    } });
  });
  await page.route(`**/api/analyses/${id}/components`, route => route.fulfill({ json: [{ component: { purl, name: 'demo:library', version: '1', ecosystem: 'maven', metadata: {} }, contexts: [{ module: '.', scope: 'compile', direct: false }] }] }));
  await page.goto(`/#analysis/${id}/findings`);
  await expect(page.getByRole('status')).toHaveText('3 hallazgos encontrados');
  const callsBeforeFilters = calls;
  await expect(page.locator('.findings > li').first()).toContainText(ids[0]);
  await expect(page.locator('.findings > li').first()).toContainText('Sin puntuación concluyente');
  await expect(page.locator('.findings > li').first()).toContainText('Explotación conocida confirmada');
  await expect(page.locator('.findings > li').last()).toContainText('0 / 100');
  await page.getByLabel('Prioridad del hallazgo').selectOption('ALTA');
  await expect(page.getByRole('status')).toHaveText('1 hallazgos encontrados');
  await expect(page.locator('.findings > li')).toContainText('84 / 100');
  const detail = page.getByText('Explicación de prioridad', { exact: true });
  await detail.focus(); await page.keyboard.press('Enter');
  await expect(page.getByRole('table', { name: 'Contribuciones guardadas de la prioridad' })).toBeVisible();
  await page.getByText('Evidencia utilizada de CVSS', { exact: true }).click();
  await expect(page.getByText('<script>evidencia conservada</script>', { exact: true })).toBeVisible();
  await expect(page.locator('script').filter({ hasText: 'evidencia conservada' })).toHaveCount(0);
  await page.getByLabel('Prioridad del hallazgo').selectOption('PENDIENTE_REVISION');
  await expect(page.getByRole('status')).toHaveText('1 hallazgos encontrados');
  await expect(page.locator('.findings > li')).toContainText(ids[0]);
  expect(calls).toBe(callsBeforeFilters);
  await page.reload();
  await expect(page.getByRole('status')).toHaveText('3 hallazgos encontrados');
  await expect(page.locator('.findings > li').first()).toContainText(ids[0]);
  await page.getByText('Política de prioridad guardada', { exact: true }).click();
  await expect(page.getByText('Fórmula guardada de referencia.', { exact: true })).toBeVisible();
  expect(calls).toBeGreaterThan(callsBeforeFilters);
});
