import { test, expect } from '@playwright/test';

const item = (id: string, status = 'PARCIAL') => ({ id, projectId: 'retired-project', projectName: '<script>Proyecto antiguo</script>', sourceReference: 'catalog:retired-project', analyzedReference: 'fixture:original',
  configuration: { modules: ['.'], profiles: [], scopes: ['test'], environmentId: 'java-21', declaredDeployment: 'Contexto guardado' }, status,
  createdAt: '2026-01-01T00:00:00Z', startedAt: status === 'EN_COLA' ? null : '2026-01-01T00:00:00Z', finishedAt: status === 'EN_COLA' ? null : '2026-01-01T00:00:12Z' });

test('keeps project/status filters and pagination after reload, escapes metadata and opens the original identifier', async ({ page }) => {
  const urls: string[] = [];
  await page.route('**/api/analyses**', route => {
    const url = new URL(route.request().url()); urls.push(url.pathname + url.search);
    const offset = Number(url.searchParams.get('offset') ?? 0);
    return route.fulfill({ json: { items: [item(offset ? 'old-id' : 'new-id', 'FALLIDO')], offset, nextOffset: offset ? null : 20, navigationLimited: false } });
  });
  await page.goto('/#history?projectId=retired-project&status=FALLIDO');
  await expect(page.getByLabel('Filtrar por identificador de proyecto')).toHaveValue('retired-project');
  await expect(page.getByLabel('Filtrar por estado')).toHaveValue('FALLIDO');
  await expect(page.getByRole('table')).toContainText('<script>Proyecto antiguo</script>');
  await expect(page.getByRole('table')).toContainText('12.0 s');
  await expect(page.locator('script').filter({ hasText: 'Proyecto antiguo' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Siguiente', exact: true }).click();
  await expect(page).toHaveURL(/offset=20/);
  await expect(page.getByRole('table')).toContainText('old-id');
  await page.reload();
  await expect(page.getByRole('table')).toContainText('old-id');
  await expect(page.getByRole('button', { name: 'Siguiente', exact: true })).toBeDisabled();
  await expect(page.getByRole('link', { name: 'Estado y diagnóstico', exact: true })).toHaveAttribute('href', '#analysis/old-id');
  await expect(page.getByRole('link', { name: 'Resumen y cobertura', exact: true })).toHaveAttribute('href', '#analysis/old-id/summary');
  await page.getByLabel('Filtrar por estado').selectOption('PARCIAL');
  await page.getByRole('button', { name: 'Aplicar filtros' }).click();
  await expect(page).not.toHaveURL(/offset=20/);
  await expect(page.getByRole('table')).toContainText('new-id');
  expect(urls.every(url => url.startsWith('/api/analyses?'))).toBe(true);
});

test('distinguishes empty history from storage failure, retries and declares the navigation limit', async ({ page }) => {
  let mode = 'error';
  await page.route('**/api/analyses**', route => mode === 'error'
    ? route.fulfill({ status: 503, json: { detail: 'Almacenamiento temporalmente inaccesible' } })
    : route.fulfill({ json: { items: mode === 'empty' ? [] : [item('queued-id', 'EN_COLA')], offset: 10000, nextOffset: null, navigationLimited: mode === 'limited' } }));
  await page.goto('/#history');
  await expect(page.getByRole('alert')).toContainText('Almacenamiento temporalmente inaccesible');
  await expect(page.getByText('No hay análisis para los filtros seleccionados.')).toHaveCount(0);
  mode = 'empty';
  await page.getByRole('button', { name: 'Actualizar historial' }).click();
  await expect(page.getByText('No hay análisis para los filtros seleccionados.')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  mode = 'limited';
  await page.getByRole('button', { name: 'Actualizar historial' }).click();
  await expect(page.getByText(/esta lista no es exhaustiva/)).toBeVisible();
  await expect(page.getByRole('table')).toContainText('Duración: No disponible');
  await expect(page.getByRole('button', { name: 'Siguiente', exact: true })).toBeDisabled();
});

test('lists two real persisted runs of one project and reopens the earlier configuration without replacement', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Proyecto Maven').selectOption('maven-direct');
  await page.getByLabel('Contexto de despliegue declarado (opcional)').fill('Primera ejecución histórica');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  const first = page.url().split('#analysis/')[1];
  await page.getByRole('link', { name: 'Registrar otro análisis' }).click();
  await page.getByLabel('Proyecto Maven').selectOption('maven-direct');
  await page.getByLabel('Contexto de despliegue declarado (opcional)').fill('Segunda ejecución histórica');
  await page.getByRole('button', { name: 'Registrar análisis' }).click();
  await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
  const second = page.url().split('#analysis/')[1];
  expect(second).not.toBe(first);
  await page.getByRole('link', { name: 'Historial', exact: true }).click();
  await page.getByLabel('Filtrar por identificador de proyecto').fill('maven-direct');
  await page.getByLabel('Filtrar por estado').selectOption('PARCIAL');
  await page.getByRole('button', { name: 'Aplicar filtros' }).click();
  const earlier = page.getByRole('row').filter({ has: page.getByText(first, { exact: true }) });
  await expect(earlier).toContainText('Primera ejecución histórica');
  await expect(page.getByRole('row').filter({ has: page.getByText(second, { exact: true }) })).toContainText('Segunda ejecución histórica');
  await page.reload();
  await expect(earlier).toContainText('Primera ejecución histórica');
  await earlier.getByRole('link', { name: 'Estado y diagnóstico' }).click();
  await expect(page.getByText('Primera ejecución histórica', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Consultar resumen y cobertura' }).click();
  await expect(page.getByRole('heading', { name: 'Resumen y cobertura del análisis' })).toBeVisible();
  await expect(page.getByText(/Resultado parcial:/)).toBeVisible();
});
