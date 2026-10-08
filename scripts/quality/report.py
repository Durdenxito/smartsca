"""Comparable scan snapshots and readable reports; missing evidence is never zero."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def finding(category, rule, path, line, message, severity, identity, **details):
    return dict(id=digest([category, rule, path, identity]), category=category, rule=rule,
                file=path, line=line, message=message, severity=severity, **details)


def snapshot(tool, version, scope, configuration):
    runner = 'sonar.py' if tool == 'sonarqube' else 'scan.py'
    sources = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
               for name in ('report.py', runner)}
    return dict(schemaVersion=1, tool=tool, scannerVersion=version, scope=scope,
                configuration=digest([configuration, sources]), repository=os.getenv('GITHUB_REPOSITORY', 'local'),
                commit=os.getenv('GITHUB_SHA') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                date=datetime.now(timezone.utc).isoformat(), status='INCOMPLETO', findings=[], errors=[],
                nativeFixed=[], reviewedSafe=[], coverage={}, baseline=None,
                changes=dict(new=None, persistent=None, resolved=None))


def compare(current, previous):
    if current['status'] != 'COMPLETO':
        current['comparison'] = 'NO_EVALUABLE: análisis incompleto o no ejecutado.'
        return
    keys = ('schemaVersion', 'tool', 'scannerVersion', 'scope', 'configuration', 'repository')
    if not previous:
        current['comparison'] = 'SIN_HISTORIAL: primera ejecución o artefacto anterior no disponible.'
        return
    if previous.get('status') != 'COMPLETO' or any(previous.get(key) != current[key] for key in keys):
        current['comparison'] = 'NO_COMPARABLE: cambió herramienta, reglas, alcance o formato.'
        return
    old = {item['id']: item for item in previous['findings']}
    new = {item['id']: item for item in current['findings']}
    current['baseline'] = dict(commit=previous['commit'], date=previous['date'])
    current['changes'] = dict(new=[new[key] for key in sorted(new.keys() - old.keys())],
                              persistent=[new[key] for key in sorted(new.keys() & old.keys())],
                              resolved=[old[key] for key in sorted(old.keys() - new.keys())])
    current['comparison'] = 'COMPARABLE: no detectados frente al análisis anterior; no certifica una corrección.'


def cell(value):
    value = html.escape(str(value)).replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ').replace('\\', '\\\\')
    for character in '`[]!*_':
        value = value.replace(character, '\\' + character)
    return value


def table(items):
    lines = ['| Categoría | Regla/aviso | Archivo | Línea | Severidad | Descripción |',
             '| --- | --- | --- | --- | --- | --- |']
    for item in items:
        lines.append('| ' + ' | '.join(cell(item.get(key, '')) for key in
                     ('category', 'rule', 'file', 'line', 'severity', 'message')) + ' |')
    return lines if items else ['Sin elementos registrados en esta sección.']


def write(report, output, previous=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    groups = {}
    for item in report['findings']:
        groups.setdefault(item['id'], {**item, 'occurrences': []})['occurrences'].append(dict(file=item['file'], line=item['line']))
    report['findings'] = list(groups.values())
    compare(report, previous)
    text = [f"# Análisis {report['tool']}", '', f"Estado: **{report['status']}** · Commit: `{report['commit']}`",
            f"Versión: {cell(report['scannerVersion'])} · Fecha: {report['date']}",
            f"Alcance: {cell(', '.join(report['scope']))}", '', report['comparison'], '']
    if report['errors']:
        text += ['## Diagnóstico', ''] + ['- ' + cell(error) for error in report['errors']] + ['']
    if report.get('qualityGate'):
        text += ['## Quality Gate', '', cell(json.dumps(report['qualityGate'], ensure_ascii=False)), '']
    text += ['## Hallazgos actuales', '', f"Total: {len(report['findings']) if report['status'] == 'COMPLETO' else 'desconocido; datos parciales abajo'}", '']
    text += table(report['findings']) + ['', '## Hallazgos superados por comparación', '']
    resolved = report['changes']['resolved']
    text += table(resolved) if resolved is not None else ['Sin evidencia comparable; no se afirma que haya cero hallazgos superados.']
    text += ['', '## Bugs, Vulnerabilities y Security Hotspots superados', '',
             '| Categoría | Ya no detectados | Marcados FIXED por Sonar |', '| --- | --- | --- |']
    for category in ('BUG', 'VULNERABILITY', 'SECURITY_HOTSPOT'):
        count = sum(item['category'] == category for item in resolved) if resolved is not None else 'Sin historial comparable'
        native = sum(item['category'] == category for item in report['nativeFixed']) if report['status'] == 'COMPLETO' else 'Desconocido'
        text.append(f'| {category} | {count} | {native if report["tool"] == "sonarqube" else "No aplica"} |')
    if report['tool'] == 'sonarqube':
        text += ['', '## Resoluciones FIXED registradas en Sonar', ''] + table(report['nativeFixed'])
        text += ['', '## Hotspots revisados como SAFE', ''] + table(report['reviewedSafe'])
    text += ['', 'Los conteos agrupan hallazgos por fingerprint; las ubicaciones y rutas se conservan en JSON.',
             'Hotspot no equivale a vulnerabilidad confirmada. SAFE/ACKNOWLEDGED/aceptado no se cuentan como FIXED.',
             'La ausencia puede deberse a eliminación o cambio de código. No demuestra ausencia de vulnerabilidades.',
             'Se conservan JSON del analizador y evidencia normalizada como artefactos; los reportes no modifican el repositorio.', '']
    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    rendered = '\n'.join(text)
    (output / 'report.md').write_text(rendered, encoding='utf-8')
    if os.getenv('GITHUB_STEP_SUMMARY'):
        # ponytail: full report is an artifact; cap the Actions summary to its 1 MiB limit.
        summary = rendered.encode()[:900_000].decode('utf-8', errors='ignore')
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(summary)


def previous(output):
    path = Path(output) / 'baseline' / 'report.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=['semgrep', 'snyk', 'sonarqube'])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    # Called with always() when installation/checkout/build failed before the scanner ran.
    if not (Path(args.output) / 'report.json').exists():
        result = snapshot(args.tool, 'No ejecutado', [], 'unavailable')
        result['status'] = 'NO_EJECUTADO'
        result['errors'] = ['El job falló antes de producir evidencia del analizador. Revisa el log de Actions.']
        write(result, args.output)
