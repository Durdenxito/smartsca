import { test, expect } from '@playwright/test';

test('shows source failures from a real persisted analysis and recovers evidence after reload', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Proyecto Maven').selectOption('maven-direct');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  const sources = page.getByRole('table', { name: 'Disponibilidad y diagnóstico por fuente', exact: true });
  const osv = sources.getByRole('row').filter({ has: page.getByRole('rowheader', { name: /^OSV/ }) });
  await expect(osv).toContainText(/ERROR: [1-9]/);
  await osv.getByText('Ver diagnóstico y fechas de OSV', { exact: true }).click();
  await expect(osv).toContainText('Consulta externa deshabilitada');
  const scorecard = sources.getByRole('row').filter({ has: page.getByRole('rowheader', { name: /^OpenSSF Scorecard/ }) });
  await expect(scorecard).toContainText(/ERROR: [1-9]/);
  await page.reload();
  await expect(page.getByRole('status')).toHaveText('PARCIAL');
  await expect(osv).toContainText(/ERROR: [1-9]/);
  await expect(sources).toContainText('Sin observaciones en esta instantánea.');
  await page.getByRole('link', { name: 'Revisar vulnerabilidades y evidencias' }).click();
  await expect(page.getByRole('heading', { name: 'Vulnerabilidades y evidencias' })).toBeVisible();
  await expect(page.getByText(/Consultas OSV completas: 0 de/)).toBeVisible();
  await expect(page.getByText(/Prioridad guardada: smartsca-priority-v1/)).toBeVisible();
  await page.getByText('Cobertura y diagnóstico de OSV por componente', { exact: true }).click();
  await expect(page.getByText('ERROR', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/Consulta externa deshabilitada/).first()).toBeVisible();
  await page.reload();
  await expect(page.getByText(/Los errores y ausencias no equivalen a cero vulnerabilidades/)).toBeVisible();
  await page.getByRole('link', { name: 'Inventario', exact: true }).click();
  await page.getByText('Salud del repositorio · 0 de 4 indicadores disponibles', { exact: true }).first().click();
  await expect(page.getByText('Asociación del repositorio', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/Consulta externa deshabilitada/).first()).toBeVisible();
  await page.reload();
  await expect(page.getByText('Salud del repositorio · 0 de 4 indicadores disponibles', { exact: true }).first()).toBeVisible();
});

test('renders a reference advisory accessibly, distinguishes KEV absence/error and rejects script links', async ({ page }) => {
  const id = '11111111-1111-1111-1111-111111111111';
  const purl = 'pkg:maven/demo/library@1';
  const observation = <T,>(value: T, source = 'https://osv.dev/') => ({ source, collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-10-06', status: 'DISPONIBLE', value, diagnostic: null });
  const item = { component: { purl, name: 'demo:library', version: '1', ecosystem: 'maven', metadata: {} }, contexts: [{ module: '.', scope: 'compile', originalScope: 'compile', direct: true }] };
  const other = { ...item, component: { ...item.component, purl: 'pkg:maven/demo/other@1', name: 'demo:other' } };
  const vulnerability = {
    id: 'CVE-2026-1234', aliases: ['CVE-2026-1234', 'GHSA-test'],
    advisories: { 'GHSA-test': observation({ id: 'GHSA-test', aliases: ['CVE-2026-1234'], summary: 'Aviso de referencia', description: '<script>no se ejecuta</script>',
      references: ['javascript:alert(1)', 'https://osv.dev/'], cvss: { ...observation(null), status: 'NO_DISPONIBLE', diagnostic: 'CVSS global no publicado' },
      affected: [
        { ecosystem: 'Maven', name: 'demo:library', ranges: '[{"events":[{"fixed":"2"}]}]', versions: ['1'], fixedVersions: ['2'],
          cvss: observation([{ version: '3.1', vector: 'CVSS:3.1/AV:N', source: 'NVD' }]) },
        { ecosystem: 'Maven', name: 'demo:other', ranges: '[]', versions: ['1'], fixedVersions: [],
          cvss: observation([{ version: '4.0', vector: 'CVSS:4.0/AV:L', source: 'CNA' }]) },
      ], rawResponse: '{"id":"GHSA-test"}' }) },
    epssByCve: observation({ 'CVE-2026-1234': observation({ probability: .5, percentile: .9 }, 'https://api.first.org/') }),
    kevByCve: observation({ 'CVE-2026-1234': observation(false, 'https://www.cisa.gov/') }),
  };
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: {
    id, project: { name: 'Referencia UI' }, status: 'PARCIAL', configuration: { scopes: ['compile'] }, dependencyGraph: { rootsByModule: { '.': 'root' } },
    vulnerabilitySnapshot: { findings: [{ componentPurl: purl, vulnerabilityId: vulnerability.id }, { componentPurl: other.component.purl, vulnerabilityId: vulnerability.id }], vulnerabilities: [vulnerability], componentQueries: { [purl]: observation(['GHSA-test']) } },
  } }));
  await page.route(`**/api/analyses/${id}/components`, route => route.fulfill({ json: [item, other] }));
  await page.goto(`/#analysis/${id}/findings?component=${encodeURIComponent(purl)}`);
  await expect(page.getByRole('status')).toHaveText('1 hallazgos encontrados');
  await expect(page.getByText('Prioridad: PENDIENTE_REVISION · Sin puntuación concluyente', { exact: true })).toBeVisible();
  await expect(page.getByText(/Prioridad no evaluada en esta instantánea anterior/)).toBeVisible();
  const detail = page.getByText('Detalle de CVE-2026-1234', { exact: true });
  await detail.focus(); await page.keyboard.press('Enter');
  await expect(page.getByText('Aviso de referencia', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'CVSS del paquete demo:library' })).toBeVisible();
  await expect(page.getByText('CVSS:3.1/AV:N', { exact: true })).toBeVisible();
  await expect(page.getByText(/CVSS 3.1.*NVD/)).toBeVisible();
  await expect(page.getByText('CVSS:4.0/AV:L', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'CVSS del paquete demo:other' })).toHaveCount(0);
  await expect(page.getByText(/Ausente del catálogo consultado/)).toBeVisible();
  await expect(page.getByText(/Probabilidad: 50.0000 %/)).toBeVisible();
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(page.getByText('<script>no se ejecuta</script>', { exact: true })).toBeVisible();
  await page.getByLabel('Señal KEV').selectOption('true');
  await expect(page.getByRole('status')).toHaveText('0 hallazgos encontrados');
  await page.getByLabel('Señal KEV').selectOption('false');
  await expect(page.getByRole('status')).toHaveText('1 hallazgos encontrados');
  await page.getByLabel('Buscar componente o identificador').fill('GHSA-test');
  await expect(page.getByRole('status')).toHaveText('1 hallazgos encontrados');
  await page.getByLabel('Componente de los hallazgos').selectOption(other.component.purl);
  await detail.click();
  await expect(page.getByText(/CVSS 4.0.*CNA/)).toBeVisible();
  await expect(page.getByText('CVSS:3.1/AV:N', { exact: true })).toHaveCount(0);
});
