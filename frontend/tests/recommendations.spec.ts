import { test, expect } from '@playwright/test';

const id = '66666666-6666-6666-6666-666666666666';
const component = (name: string, version = '1.0.0') => ({ purl: `pkg:maven/demo/${name}@${version}`, name: `demo:${name}`, version, ecosystem: 'maven', metadata: {} });
const root = component('root'), parent = component('parent'), library = component('library');
const observation = (status: string, value: unknown = null, source = 'https://api.osv.dev/v1/vulns/GHSA-reference') => ({ status, value, source, collectedAt: '2026-10-07T00:00:00Z', sourceDate: '2026-10-06', diagnostic: status === 'ERROR' ? 'El aviso no respondió' : null });
const affected = (name: string, fixedVersions: string[], ecosystem = 'Maven') => ({ name, ecosystem, fixedVersions, ranges: JSON.stringify([{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, ...fixedVersions.map(fixed => ({ fixed }))] }]), versions: ['1.0.0'], cvss: observation('NO_DISPONIBLE') });
const advisory = (packages: ReturnType<typeof affected>[]) => ({ id: 'GHSA-reference', affected: packages, aliases: ['CVE-2026-1010'], summary: 'Referencia', description: '', references: [], cvss: observation('NO_DISPONIBLE'), rawResponse: '{}' });
const edge = (from: typeof root, to: typeof root, module: string) => ({ parentPurl: from.purl, childPurl: to.purl, context: { module, originalScope: 'compile', normalizedContext: 'compile' } });
const edges = [edge(root, library, '.'), edge(root, parent, 'app'), edge(parent, library, 'app')];
function record(advisories: Record<string, ReturnType<typeof observation>>) {
  return { id, project: { name: 'Referencias RF10' }, status: 'PARCIAL', configuration: { scopes: ['compile'] },
    dependencyGraph: { rootsByModule: { '.': root.purl, app: root.purl }, components: Object.fromEntries([root, parent, library].map(value => [value.purl, value])), edges },
    vulnerabilitySnapshot: { findings: [{ componentPurl: library.purl, vulnerabilityId: 'CVE-2026-1010' }], componentQueries: { [library.purl]: observation('DISPONIBLE', Object.keys(advisories)) },
      vulnerabilities: [{ id: 'CVE-2026-1010', aliases: ['CVE-2026-1010', ...Object.keys(advisories)], advisories, epssByCve: observation('NO_DISPONIBLE'), kevByCve: observation('NO_DISPONIBLE') }] } };
}
const items = [{ component: library, contexts: [{ module: '.', scope: 'compile', direct: true }, { module: 'app', scope: 'compile', direct: false }] }];

test('keeps published fixes with their exact package/advisory source, migration limits and saved introduction routes after reload', async ({ page }) => {
  const requests: { method: string; path: string }[] = [];
  const data = record({ 'GHSA-reference': observation('DISPONIBLE', advisory([
    affected('demo:library', ['1.0.1', '2.0.0', '1.0.1']), affected('demo:other', ['9.9.9']), affected('demo:library', ['8.8.8'], 'PyPI'),
  ])) });
  await page.route('**/api/analyses/**', route => {
    const url = new URL(route.request().url()); requests.push({ method: route.request().method(), path: url.pathname });
    const value = url.pathname.endsWith('/components') ? items : url.pathname.endsWith('/graph')
      ? { module: '.', root, focus: library, neighbors: [root], edges: [edges[0]], offset: 0, totalNeighbors: 1, nextOffset: null }
      : url.pathname.endsWith('/routes') ? { routes: [{ module: '.', rootPurl: root.purl, steps: [edges[0]] }, { module: 'app', rootPurl: root.purl, steps: edges.slice(1) }], components: data.dependencyGraph.components, offset: 0, nextOffset: null, searchLimited: false } : data;
    return route.fulfill({ json: value });
  });
  await page.goto(`/#analysis/${id}/findings`);
  const toggle = page.getByText('Recomendaciones básicas de CVE-2026-1010', { exact: true });
  await toggle.focus(); await page.keyboard.press('Enter');
  const recommendations = toggle.locator('..');
  await expect(recommendations).toContainText('Versión instalada: demo:library @ 1.0.0');
  await expect(recommendations).toContainText('Versiones corregidas publicadas: 1.0.1, 2.0.0.');
  await expect(recommendations).not.toContainText('9.9.9'); await expect(recommendations).not.toContainText('8.8.8');
  await expect(recommendations).toContainText('ramas distintas');
  await expect(recommendations).toContainText('una versión patch o minor no demuestra bajo riesgo');
  await expect(recommendations).toContainText('No se garantiza compatibilidad, compilación ni ausencia de otras vulnerabilidades');
  await expect(page.getByText('. · compile · Directa; app · compile · Transitiva', { exact: true })).toBeVisible();
  await expect(recommendations.getByRole('link', { name: 'https://api.osv.dev/v1/vulns/GHSA-reference', exact: true })).toHaveAttribute('href', 'https://api.osv.dev/v1/vulns/GHSA-reference');
  await expect(recommendations).toContainText('Aviso de origen: GHSA-reference');
  await page.reload(); await toggle.click();
  await expect(recommendations).toContainText('Versiones corregidas publicadas: 1.0.1, 2.0.0.');
  await recommendations.getByRole('link', { name: 'Consultar rutas de introducción' }).click();
  await expect(page).toHaveURL(new RegExp(`graph\\?component=${encodeURIComponent(library.purl)}`));
  await expect(page.getByRole('heading', { name: 'Grafo de dependencias' })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: '2 rutas en esta página' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Pasos de la ruta 2' })).toContainText('demo:parent');
  expect(requests.every(value => value.method === 'GET' && value.path.startsWith(`/api/analyses/${id}`))).toBe(true);
});

test('distinguishes no published fixes, a different package, unavailable notices and absent stored notices without unsafe links', async ({ page }) => {
  let data = record({
    'GHSA-no-fix': observation('DISPONIBLE', advisory([affected('demo:library', [])])),
    'GHSA-other': observation('DISPONIBLE', advisory([affected('demo:other', ['9.9.9'])])),
    'GHSA-error': observation('ERROR'),
    'GHSA-unavailable': observation('NO_DISPONIBLE'),
    'GHSA-unsafe': observation('DISPONIBLE', advisory([affected('demo:library', ['<script>corrección</script>'])]), 'javascript:alert(1)'),
  });
  await page.route(`**/api/analyses/${id}`, route => route.fulfill({ json: data }));
  await page.route(`**/api/analyses/${id}/components`, route => route.fulfill({ json: items }));
  await page.goto(`/#analysis/${id}/findings`);
  const toggle = page.getByText('Recomendaciones básicas de CVE-2026-1010', { exact: true });
  await toggle.click();
  const recommendations = toggle.locator('..');
  await expect(recommendations.getByRole('region', { name: 'Correcciones publicadas en GHSA-no-fix', exact: true })).toContainText('El aviso no publica versiones corregidas para este paquete.');
  await expect(recommendations.getByRole('region', { name: 'Correcciones publicadas en GHSA-other', exact: true })).toContainText('no se ofrecen correcciones de otro paquete');
  await expect(recommendations.getByRole('region', { name: 'Correcciones publicadas en GHSA-error', exact: true })).toContainText('evidencia ERROR');
  await expect(recommendations.getByRole('region', { name: 'Correcciones publicadas en GHSA-unavailable', exact: true })).toContainText('evidencia NO_DISPONIBLE');
  await expect(recommendations).toContainText('<script>corrección</script>');
  await expect(page.locator('script').filter({ hasText: 'corrección' })).toHaveCount(0);
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  data = record({});
  await page.reload(); await toggle.click();
  await expect(recommendations).toContainText('No hay avisos guardados para consultar correcciones');
  await expect(recommendations).not.toContainText('Versiones corregidas publicadas:');
});
