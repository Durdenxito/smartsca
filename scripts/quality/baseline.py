"""Download only an ancestor main scan from this workflow/repository."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def restore(tool, output):
    if not os.getenv('GITHUB_REPOSITORY'):
        return
    repo = os.environ['GITHUB_REPOSITORY']
    runs = json.loads(subprocess.check_output([
        'gh', 'run', 'list', '--repo', repo, '--workflow', f'quality-{tool}.yml', '--branch', 'main',
        '--status', 'success', '--limit', '50', '--json', 'databaseId,headSha,event'], text=True))
    for run in runs:
        if str(run['databaseId']) == os.environ['GITHUB_RUN_ID'] or run['event'] not in ('push', 'workflow_dispatch'):
            continue
        if subprocess.run(['git', 'merge-base', '--is-ancestor', run['headSha'], 'HEAD'], capture_output=True).returncode:
            continue
        target = Path(output) / 'baseline'
        target.mkdir(parents=True, exist_ok=True)
        download = subprocess.run(['gh', 'run', 'download', str(run['databaseId']), '--repo', repo,
                                   '--name', f'quality-{tool}', '--dir', str(target)], capture_output=True)
        if download.returncode:
            print('Artefacto anterior no disponible; no se afirmarán hallazgos superados.')
            return
        if not (target / 'report.json').is_file():
            raise ValueError('El artefacto anterior no contiene report.json.')
        evidence = json.loads((target / 'report.json').read_text(encoding='utf-8'))
        if evidence.get('commit') != run['headSha'] or evidence.get('repository') != repo or evidence.get('status') != 'COMPLETO':
            raise ValueError('La procedencia del reporte anterior no coincide con su ejecución.')
        return
    print('Sin análisis anterior compatible por procedencia; primera línea base.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=['semgrep', 'snyk', 'sonarqube'])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    restore(args.tool, args.output)
