"""Semgrep CE source scan and Snyk Open Source dependency scan."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
from report import finding, previous, snapshot, write

SEMGREP_VERSION = '1.180.0'
SNYK_VERSION = '1.1307.4'
SOURCE_SCOPE = ['backend/src/main', 'frontend/src', 'infra', 'scripts', '.github/workflows']
DEPENDENCY_SCOPE = ['backend/pom.xml', 'frontend/package-lock.json']


def normalize_semgrep(raw, root):
    if not isinstance(raw.get('results'), list) or not isinstance(raw.get('errors'), list):
        raise ValueError('Semgrep devolvió un JSON sin resultados/errores verificables.')
    root = Path(root).resolve()
    results = []
    for item in raw['results']:
        extra = item['extra']
        source = (root / item['path']).resolve()
        if not any(source.is_relative_to((root / directory).resolve()) for directory in SOURCE_SCOPE):
            raise ValueError('Ruta del analizador fuera del alcance permitido.')
        content = source.read_bytes()
        start, end = item['start']['offset'], item['end']['offset']
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(content):
            raise ValueError('Ubicación del analizador fuera del archivo.')
        # CE emits "requires login" instead of a fingerprint; source bytes retain distinct matches.
        identity = content[start:end].decode('utf-8')
        results.append(finding('SECURITY', item['check_id'], item['path'], item['start']['line'],
                               extra['message'], extra['severity'], identity))
    return results


def semgrep(output):
    rules = output / 'rules.yml'
    request = urllib.request.Request('https://semgrep.dev/c/p/default', headers={'User-Agent': 'Semgrep/' + SEMGREP_VERSION})
    with urllib.request.urlopen(request, timeout=60) as response:
        rules.write_bytes(response.read())
    result = snapshot('semgrep', SEMGREP_VERSION, SOURCE_SCOPE,
                      dict(rulesSha=hashlib.sha256(rules.read_bytes()).hexdigest(), nosems=False, gitIgnore=False))
    raw_path = output / 'raw-semgrep.json'
    command = ['semgrep', 'scan', '--config', str(rules), '--json-output', str(raw_path), '--strict',
               '--metrics=off', '--disable-version-check', '--disable-nosem', '--no-git-ignore',
               '--exclude=target', '--exclude=node_modules', '--exclude=dist', '--exclude=__pycache__', *SOURCE_SCOPE]
    with (output / 'scan.log').open('w', encoding='utf-8') as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    result['exitCode'] = process.returncode
    if raw_path.exists():
        raw = json.loads(raw_path.read_text(encoding='utf-8'))
        result['findings'] = normalize_semgrep(raw, Path.cwd())
        result['errors'] = [str(error.get('message', error.get('type', 'Error Semgrep'))) for error in raw['errors']]
        result['coverage'] = raw.get('paths', {})
        result['status'] = 'COMPLETO' if process.returncode == 0 and not result['errors'] else 'INCOMPLETO'
    else:
        result['errors'] = ['Semgrep no produjo JSON. Consulta scan.log.']
    return result


def snyk(output):
    result = snapshot('snyk', SNYK_VERSION, DEPENDENCY_SCOPE, dict(dev=True, ignorePolicy=True))
    if not os.getenv('SNYK_TOKEN') or os.getenv('GITHUB_EVENT_NAME') == 'pull_request':
        result['status'] = 'NO_EJECUTADO'
        result['errors'] = ['Falta SNYK_TOKEN o la ejecución es un pull request; no se exponen secretos al código de PR.']
        return result
    executable = shutil.which('snyk')
    if not executable:
        raise ValueError('Snyk CLI no está instalado.')
    findings = {}
    for directory, manifest in [('backend', 'pom.xml'), ('frontend', 'package-lock.json')]:
        target = directory + '/' + manifest
        raw_path = (output / f'raw-snyk-{directory}.json').resolve()
        with (output / f'scan-{directory}.log').open('w', encoding='utf-8') as log:
            process = subprocess.run([executable, 'test', '--file=' + manifest, '--dev', '--ignore-policy',
                                      '--json-file-output=' + str(raw_path)], cwd=directory,
                                     stdout=log, stderr=subprocess.STDOUT, timeout=600)
        result.setdefault('exitCodes', {})[target] = process.returncode
        if not raw_path.exists():
            result['errors'].append(f'{target}: sin JSON; consulta el log del analizador.')
            continue
        raw = json.loads(raw_path.read_text(encoding='utf-8'))
        if process.returncode not in (0, 1) or not isinstance(raw.get('vulnerabilities'), list) or raw.get('error'):
            result['errors'].append(f'{target}: análisis incompleto, código {process.returncode}.')
            continue
        result['coverage'][target] = dict(dependencies=raw.get('dependencyCount'), packageManager=raw.get('packageManager'))
        for item in raw['vulnerabilities']:
            issue = finding('LICENSE' if item.get('type') == 'license' else 'VULNERABILITY', item['id'], target, None, item['title'], item['severity'], item['packageName'],
                            package=item['packageName'], version=item['version'], identifiers=item.get('identifiers', {}),
                            fixedIn=item.get('fixedIn', []), paths=[])
            findings.setdefault(issue['id'], issue)['paths'].append(item.get('from', []))
    result['findings'] = list(findings.values())
    result['status'] = 'COMPLETO' if not result['errors'] and len(result['coverage']) == 2 else 'INCOMPLETO'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=['semgrep', 'snyk'])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        result = semgrep(output) if args.tool == 'semgrep' else snyk(output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result = snapshot(args.tool, SEMGREP_VERSION if args.tool == 'semgrep' else SNYK_VERSION, [], 'failed')
        result['errors'] = [f'{type(error).__name__}: no se completó el análisis. Consulta el log; no se publica información de autenticación.']
    write(result, output, previous(output))
    return 0 if result['status'] == 'COMPLETO' else 2


if __name__ == '__main__':
    raise SystemExit(main())
