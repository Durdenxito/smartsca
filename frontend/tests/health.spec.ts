import { test, expect } from '@playwright/test';

test('shows the recovered report first and keeps missing version metadata in technical diagnostics', async ({ page }) => {
  const id = '22222222-2222-2222-2222-222222222222', purl = 'pkg:maven/demo/library@1';
  const available = <T,>(value: T) => ({ source: 'https://api.deps.dev/v3/projects/github.com%2Fdemo%2Flibrary', collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-01-01T00:00:00Z', status: 'DISPONIBLE', value, diagnostic: null });
  const item = { component: { purl, name: 'demo:library', version: '1', ecosystem: 'maven', metadata: {} }, contexts: [{ module: '.', scope: 'compile', originalScope: 'compile', direct: true }] };
  const assessment = {
    componentPurl: purl, repository: available({ id: 'github.com/demo/library', method: 'SCM_POM_Y_PROYECTO_SIN_VERSION_DEPS_DEV' }),
    scorecard: available({ repository: 'github.com/demo/library', repositoryCommit: 'abc123', toolVersion: 'v5', toolCommit: 'tool123', stale: true, freshnessPolicy: 'scorecard-age-v1-90d' }),
    indicators: Object.fromEntries(['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'].map((name, index) => [name, index < 2
      ? available({ name, score: index ? 10 : 0, reason: '<script>alert(1)</script>', details: ['Detalle publicado'], documentationUrl: 'javascript:alert(1)' })
      : { ...available(null), status: index === 2 ? 'NO_DISPONIBLE' : 'ERROR', diagnostic: index === 2 ? 'Indicador no publicado' : 'Indicador duplicado' }])),
    associationEvidence: [{ ...available(null), status: 'NO_DISPONIBLE', source: 'https://api.deps.dev/v3/systems/maven/packages/demo%3Alibrary/versions/1',
      diagnostic: 'deps.dev no tiene registrada esta versión (HTTP 404); se consulta su POM publicado.' }, available('<project>SCM conservado</project>')],
  };
  await page.route(`**/api/analyses/${id}/inventory`, async route => route.fulfill({ json: {
    projectName: 'Referencia HTTP de salud', status: 'PARCIAL', scopes: ['compile'], rootsByModule: { '.': purl },
    items: [item], vulnerabilitiesAvailable: false, healthAssessments: { [purl]: assessment },
  } }));
  await page.goto(`/#analysis/${id}/components`);
  await page.getByText('Salud del repositorio · 2 de 4 indicadores disponibles', { exact: true }).click();
  await expect(page.getByText(/no constituye|no constituyen una prueba criptográfica/)).toBeVisible();
  await expect(page.getByText(/Informe antiguo/)).toBeVisible();
  await expect(page.getByText(/Cobertura: 2 \/ 4 \(50 %\)/)).toBeVisible();
  await expect(page.getByText('Informe obtenido mediante el POM de Maven Central y la identidad del repositorio en deps.dev.', { exact: true })).toBeVisible();
  await expect(page.getByText(/deps.dev no tiene registrada esta versión/)).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Asociación del repositorio', exact: true })).toBeHidden();
  await expect(page.getByRole('cell', { name: '0 / 10', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Sin valor', exact: true })).toHaveCount(2);
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(page.locator('script').filter({ hasText: 'alert(1)' })).toHaveCount(0);
  await page.getByText('Diagnóstico técnico y fuentes de asociación', { exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText(/deps.dev no tiene registrada esta versión/)).toBeVisible();
  await expect(page.getByText('<project>SCM conservado</project>', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText('Salud del repositorio · 2 de 4 indicadores disponibles', { exact: true })).toBeVisible();
  await page.getByText('Salud del repositorio · 2 de 4 indicadores disponibles', { exact: true }).click();
  await expect(page.getByRole('cell', { name: '0 / 10', exact: true })).toBeVisible();
  await expect(page.getByText(/deps.dev no tiene registrada esta versión/)).toBeHidden();
});

test('keeps the failure visible when no repository report was obtained', async ({ page }) => {
  const id = '22222222-2222-2222-2222-222222222223', purl = 'pkg:maven/demo/missing@1';
  const absent = { source: 'https://repo.maven.apache.org/maven2/demo/missing/1/missing-1.pom', collectedAt: '2026-10-07T00:00:00Z',
    sourceDate: null, status: 'NO_DISPONIBLE', value: null, diagnostic: 'El POM publicado tampoco está disponible (HTTP 404).' };
  const item = {
    component: { purl, name: 'demo:missing', version: '1', ecosystem: 'maven', metadata: {} },
    contexts: [{ module: '.', scope: 'compile', originalScope: 'compile', direct: true }],
  };
  await page.route(`**/api/analyses/${id}/inventory`, route => route.fulfill({ json: {
    projectName: 'Sin informe', status: 'PARCIAL', scopes: ['compile'], rootsByModule: { '.': purl }, items: [item], vulnerabilitiesAvailable: false,
    healthAssessments: { [purl]: { componentPurl: purl, repository: absent, scorecard: absent,
      indicators: Object.fromEntries(['Maintained', 'Security-Policy', 'Code-Review', 'Dependency-Update-Tool'].map(name => [name, absent])),
      associationEvidence: [absent] } },
  } }));
  await page.goto(`/#analysis/${id}/components`);
  await page.getByText('Salud del repositorio · 0 de 4 indicadores disponibles', { exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Asociación del repositorio', exact: true })).toBeVisible();
  await expect(page.getByText(/El POM publicado tampoco está disponible/).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Sin valor', exact: true })).toHaveCount(4);
  await expect(page.getByText(/Informe obtenido mediante/)).toHaveCount(0);
});
