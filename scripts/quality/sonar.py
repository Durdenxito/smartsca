"""Backend-only analysis and paginated SonarQube evidence, bound to this scan."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from report import digest, finding, previous, snapshot, write

SCANNER_VERSION = '5.8.0.7211'
SCOPE = ['backend/src/main', 'backend/src/test', 'backend/pom.xml']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise ValueError('Redirección Sonar rechazada; configura la URL final del servidor.')


class Sonar:
    def __init__(self, host, token):
        uri = urllib.parse.urlsplit(host)
        if uri.username or uri.password or uri.query or uri.fragment or not uri.hostname:
            raise ValueError('SONAR_HOST_URL no debe incluir credenciales ni parámetros.')
        if uri.scheme != 'https' and not (uri.scheme == 'http' and uri.hostname in ('localhost', '127.0.0.1')):
            raise ValueError('Sonar remoto requiere HTTPS.')
        self.host, self.token = host.rstrip('/'), token
        self.client = urllib.request.build_opener(NoRedirect())

    def get(self, endpoint, **parameters):
        url = self.host + '/api/' + endpoint + '?' + urllib.parse.urlencode(parameters)
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + self.token})
        with self.client.open(request, timeout=60) as response:
            return json.load(response)

    def pages(self, endpoint, field, **parameters):
        items, components = [], {}
        for page in range(1, 21):
            value = self.get(endpoint, p=page, ps=500, **parameters)
            total = value['paging']['total']
            if total > 10_000:
                raise ValueError('Sonar supera el límite paginado de 10000; reporte incompleto.')
            if not isinstance(value.get(field), list):
                raise ValueError('Respuesta Sonar sin colección esperada.')
            items.extend(value[field])
            components.update({item['key']: item for item in value.get('components', [])})
            if len(items) >= total:
                return items, components
            if not value[field]:
                raise ValueError('Paginación Sonar incompleta.')
        raise ValueError('Paginación Sonar incompleta.')


def normalize(item, components, category):
    component = item['component']
    path = components.get(component, {}).get('path') or component.split(':', 1)[-1]
    if path != 'pom.xml' and not path.startswith(('src/main/', 'src/test/')):
        return None  # Historic resolutions outside the selected backend are not passed findings.
    rule = item.get('rule', item.get('securityCategory', 'SECURITY_HOTSPOT'))
    identity = item.get('hash') or item.get('lineHash') or item['message']
    return finding(category, rule, 'backend/' + path, item.get('line', item.get('textRange', {}).get('startLine')),
                   item['message'], item.get('severity', item.get('vulnerabilityProbability', 'UNKNOWN')), identity,
                   sonarKey=item['key'], status=item.get('status'), resolution=item.get('resolution'),
                   impacts=item.get('impacts', []))


def collect(client, key, task_id, result):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        task = client.get('ce/task', id=task_id)['task']
        if task['status'] == 'SUCCESS':
            break
        if task['status'] in ('FAILED', 'CANCELED'):
            raise ValueError('Sonar no completó la tarea de análisis.')
        time.sleep(5)
    else:
        raise ValueError('Sonar no terminó el análisis en diez minutos.')
    analysis_id = task['analysisId']
    if task['componentKey'] != key:
        raise ValueError('La tarea Sonar pertenece a otro proyecto.')

    def current_analysis():
        latest = client.get('project_analyses/search', project=key, ps=1)['analyses'][0]
        if latest['key'] != analysis_id or latest.get('revision') != result['commit']:
            raise ValueError('Otra ejecución sustituyó este análisis; no se mezclan resultados.')
    current_analysis()
    profiles = client.get('qualityprofiles/search', project=key)['profiles']
    result['configuration'] = digest([result['configuration'], sorted([
        {name: profile.get(name) for name in ('key', 'language', 'name', 'rulesUpdatedAt', 'activeRuleCount')} for profile in profiles
    ], key=lambda profile: (profile['language'], profile['key']))])
    result['analysisId'] = analysis_id
    result['qualityGate'] = client.get('qualitygates/project_status', analysisId=analysis_id)['projectStatus']
    result['metrics'] = client.get('measures/component', component=key,
        metricKeys='bugs,vulnerabilities,security_hotspots,code_smells,ncloc,coverage,duplicated_lines_density')['component']['measures']
    for resolved in ('false', 'true'):
        issues, components = client.pages('issues/search', 'issues', componentKeys=key, resolved=resolved)
        for item in issues:
            normalized = normalize(item, components, item.get('type', 'UNKNOWN'))
            if normalized is None:
                continue
            if resolved == 'false':
                result['findings'].append(normalized)
            elif item.get('resolution') == 'FIXED' or item.get('issueStatus') == 'FIXED':
                result['nativeFixed'].append(normalized)
    version = tuple(int(part) for part in result['serverVersion'].split('.')[:2])
    project_parameter = 'project' if version >= (10, 2) else 'projectKey'
    # Some servers default to TO_REVIEW, silently excluding reviewed hotspots.
    for status in ('TO_REVIEW', 'REVIEWED'):
        hotspots, components = client.pages('hotspots/search', 'hotspots', status=status, **{project_parameter: key})
        for item in hotspots:
            detail = client.get('hotspots/show', hotspot=item['key'])
            item['rule'] = detail['rule']['key']
            normalized = normalize(item, components, 'SECURITY_HOTSPOT')
            if normalized is None:
                continue
            if item.get('status') == 'REVIEWED' and item.get('resolution') == 'FIXED':
                result['nativeFixed'].append(normalized)
            elif item.get('status') == 'REVIEWED' and item.get('resolution') == 'SAFE':
                result['reviewedSafe'].append(normalized)
            else:
                result['findings'].append(normalized)
    current_analysis()
    result['status'] = 'COMPLETO'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = snapshot('sonarqube', SCANNER_VERSION, SCOPE, dict(scanAll=False, sources='src/main', tests='src/test'))
    host, token, key = (os.getenv(name) for name in ('SONAR_HOST_URL', 'SONAR_TOKEN', 'SONAR_PROJECT_KEY'))
    if not all((host, token, key)) or os.getenv('GITHUB_EVENT_NAME') == 'pull_request':
        result['status'] = 'NO_EJECUTADO'
        result['errors'] = ['Faltan SONAR_HOST_URL/SONAR_TOKEN/SONAR_PROJECT_KEY o es un PR: no se publican credenciales ni se sobrescribe el proyecto desde PR.']
    else:
        try:
            client = Sonar(host, token)
            result['serverVersion'] = client.get('system/status')['version']
            result['scannerVersion'] += '/server-' + result['serverVersion']
            wrapper = str(Path('backend/mvnw.cmd').resolve()) if os.name == 'nt' else './mvnw'
            command = [wrapper, '-B', '-ntp', 'test-compile',
                       f'org.sonarsource.scanner.maven:sonar-maven-plugin:{SCANNER_VERSION}:sonar',
                       '-Dsonar.projectKey=' + key, '-Dsonar.sources=src/main', '-Dsonar.tests=src/test',
                       '-Dsonar.scanner.scanAll=false', '-Dsonar.scm.revision=' + result['commit']]
            with (output / 'scan.log').open('w', encoding='utf-8') as log:
                process = subprocess.run(command, cwd='backend', stdout=log, stderr=subprocess.STDOUT, timeout=1200)
            result['exitCode'] = process.returncode
            if process.returncode != 0:
                raise ValueError('Scanner Maven falló; consulta scan.log.')
            metadata = dict(line.split('=', 1) for line in Path('backend/target/sonar/report-task.txt').read_text().splitlines() if '=' in line)
            collect(client, key, metadata['ceTaskId'], result)
        except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
            result['errors'].append('No se completó la consulta/compilación/análisis Sonar. Revisa permisos, accesibilidad y scan.log. No se afirman resoluciones con evidencia incompleta.')
    result['evidenceFormat'] = 'Sonar API fields normalized; user assignments/comments omitted'
    (output / 'raw-sonarqube.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    write(result, output, previous(output))
    return 0 if result['status'] == 'COMPLETO' else 2


if __name__ == '__main__':
    raise SystemExit(main())
