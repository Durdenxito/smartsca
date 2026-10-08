import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('imports a real ZIP, selects its saved project and resolves/downloads the same snapshot', async ({ page, request }) => {
  const root = await mkdtemp(join(tmpdir(), 'smartsca-import-e2e-'));
  try {
    await writeFile(join(root, 'pom.xml'), '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>uploaded-e2e</artifactId><version>1</version><name>Proyecto ZIP E2E</name><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>');
    const file = join(root, 'project.zip');
    execFileSync('jar', ['--create', '--file', file, '--no-manifest', '-C', root, 'pom.xml']);
    await page.goto('/');
    await page.getByLabel('Archivo ZIP del proyecto').setInputFiles(file);
    await page.getByRole('button', { name: 'Importar proyecto', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('Proyecto importado: Proyecto ZIP E2E');
    const projectId = await page.getByLabel('Proyecto Maven', { exact: true }).inputValue();
    expect(projectId).toMatch(/^import-[a-f0-9]{32}$/);
    await expect(page.getByText(/zip:project.zip;sha256:/)).toBeVisible();
    await page.reload();
    await page.getByLabel('Proyecto Maven', { exact: true }).selectOption(projectId);
    await page.getByRole('button', { name: 'Registrar análisis' }).click();
    await expect(page.getByRole('status')).toHaveText('PARCIAL', { timeout: 120_000 });
    const id = page.url().split('/').at(-1)!;
    const analysis = await (await request.get(`/api/analyses/${id}`)).json();
    expect(analysis.project.id).toBe(projectId);
    expect(analysis.project.sourceReference).toMatch(/^zip:project.zip;sha256:[a-f0-9]{64}$/);
    await page.getByRole('link', { name: 'Consultar resumen y cobertura' }).click();
    const event = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Descargar resultados JSON' }).click();
    expect(JSON.parse(await readFile((await (await event).path())!, 'utf8')).analysis).toEqual(analysis);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('imports a GitHub reference through the UI and preserves the catalog when import fails', async ({ page }) => {
  const inputWarnings: string[] = [];
  page.on('console', message => { if (/uncontrolled.*controlled|controlled.*uncontrolled/.test(message.text())) inputWarnings.push(message.text()); });
  const project = { id: 'import-' + 'a'.repeat(32), name: 'Repositorio de referencia', sourceReference: 'git+https://github.com/demo/repo@' + 'b'.repeat(40), analyzedReference: 'fixture-sha256:' + 'c'.repeat(64), modules: ['.'], profiles: [] };
  let failed = true; let requests = 0;
  await page.route('**/api/projects/import/git', route => {
    requests++; expect(route.request().postDataJSON()).toEqual({ url: 'https://github.com/demo/repo' });
    return failed ? route.fulfill({ status: 400, json: { detail: 'Repositorio no disponible o no público' } }) : route.fulfill({ status: 201, json: project });
  });
  await page.goto('/');
  await page.getByLabel('Tipo de entrada').selectOption('git');
  await page.getByLabel('URL del repositorio público').fill('https://github.com/demo/repo');
  await page.getByRole('button', { name: 'Importar proyecto', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Repositorio no disponible o no público');
  await expect(page.getByRole('button', { name: 'Registrar análisis' })).toBeEnabled();
  failed = false; await page.getByRole('button', { name: 'Importar proyecto', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Proyecto importado: Repositorio de referencia');
  await expect(page.getByLabel('Proyecto Maven', { exact: true })).toHaveValue(project.id);
  await expect(page.getByText(project.sourceReference, { exact: true })).toBeVisible();
  expect(requests).toBe(2);
  expect(inputWarnings).toEqual([]);
});
