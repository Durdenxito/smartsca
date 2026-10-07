import { test, expect } from '@playwright/test';

test('shows reference repository evidence, real zero, missing checks, stale date and safe text after reload', async ({ page }) => {
  const id = '22222222-2222-2222-2222-222222222222', purl = 'pkg:maven/demo/library@1';
  const available = <T,>(value: T) => ({ source: 'https://api.deps.dev/v3/projects/github.com%2Fdemo%2Flibrary', collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-01-01T00:00:00Z', status: 'DISPONIBLE', value, diagnostic: null });
  const item = { component: { purl, name: 'demo:library', version: '1', ecosystem: 'maven', metadata: {} }, contexts: [{ module: '.', scope: 'compile', originalScope: 'compile', direct: true }] };
  const assessment = {
    componentPurl: purl, repository: available({ id: 'github.com/demo/library', method: 'SCM_POM_Y_PROYECTO_CONTRASTADOS' }),
    scorecard: available({ repository: 'github.com/demo/library', repositoryCommit: 'abc123', toolVersion: 'v5', toolCommit: 'tool123', stale: true, freshnessPolicy: 'scorecard-age-v1-90d' }),
    indicators: Object.fromEntries(['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'].map((name, index) => [name, index < 2
      ? available({ name, score: index ? 10 : 0, reason: '<script>alert(1)</script>', details: ['Detalle publicado'], documentationUrl: 'javascript:alert(1)' })
      : { ...available(null), status: index === 2 ? 'NO_DISPONIBLE' : 'ERROR', diagnostic: index === 2 ? 'Indicador no publicado' : 'Indicador duplicado' }])),
    associationEvidence: [available('<project>SCM conservado</project>')],
  };
  await page.route(`**/api/analyses/${id}/components`, async route => route.fulfill({ json: [item] }));
  await page.route(`**/api/analyses/${id}`, async route => route.fulfill({ json: {
    id, project: { name: 'Referencia HTTP de salud' }, status: 'PARCIAL', configuration: { scopes: ['compile'] },
    dependencyGraph: { rootsByModule: { '.': purl } }, vulnerabilitySnapshot: null, healthAssessments: { [purl]: assessment },
  } }));
  await page.goto(`/#analysis/${id}/components`);
  await page.getByText('Salud del repositorio · 2 de 4 indicadores disponibles', { exact: true }).click();
  await expect(page.getByText(/no constituye|no constituyen una prueba criptográfica/)).toBeVisible();
  await expect(page.getByText(/Informe antiguo/)).toBeVisible();
  await expect(page.getByText(/Cobertura: 2 \/ 4 \(50 %\)/)).toBeVisible();
  await expect(page.getByRole('cell', { name: '0 / 10', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Sin valor', exact: true })).toHaveCount(2);
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(page.locator('script').filter({ hasText: 'alert(1)' })).toHaveCount(0);
  await page.getByText('Respuestas de asociación y salud conservadas', { exact: true }).click();
  await expect(page.getByText('<project>SCM conservado</project>', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText('Salud del repositorio · 2 de 4 indicadores disponibles', { exact: true })).toBeVisible();
});
