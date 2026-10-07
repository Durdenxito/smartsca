"""Generate README diagrams from compiler declarations, migrated schema and Compose."""
import argparse
import html
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET

START = '<!-- smartsca:generated:start -->'
END = '<!-- smartsca:generated:end -->'


def text(value):
    return html.escape(str(value or ''), quote=True).replace('\n', ' ').replace('|', '&#124;')


def identifier(value):
    return re.sub(r'[^a-zA-Z0-9_]', '_', str(value)) or 'value'


def mermaid_type(value):
    return re.sub(r'[{};"\n\r]', '', value).replace('<', '~').replace('>', '~')


def class_diagram(classes):
    lines = ['classDiagram']
    ids = {c.get('package') + '.' + c.get('name'): f'c{i}' for i, c in enumerate(classes)}
    for c in classes:
        key = c.get('package') + '.' + c.get('name')
        lines.append(f'  class {ids[key]}["{text(key)}"] {{')
        if c.get('kind') in {'INTERFACE', 'ENUM', 'RECORD'}:
            lines.append('    <<' + c.get('kind').lower() + '>>')
        for member in c:
            if member.tag not in {'field', 'method'}:
                continue
            modifiers = member.get('modifiers', '')
            visibility = '+' if 'public' in modifiers else '-' if 'private' in modifiers else '#' if 'protected' in modifiers else '~'
            name = member.get('name')
            if member.tag == 'method':
                parameters = ', '.join(mermaid_type(p.get('type')) + ' ' + p.get('name') for p in member)
                lines.append(f'    {visibility}{name}({parameters}) {mermaid_type(member.get("type"))}')
            else:
                lines.append(f'    {visibility}{mermaid_type(member.get("type"))} {name}')
        lines.append('  }')
        for base in list(c.findall('extends')) + list(c.findall('implements')):
            name = base.get('type').split('<')[0]
            fq = name if name in ids else c.get('package') + '.' + name
            if fq not in ids:
                fq = next((i.get('name') for i in c.findall('import') if i.get('name').endswith('.' + name)), '')
            if fq in ids:
                arrow = '<|--' if base.tag == 'extends' else '<|..'
                lines.append(f'  {ids[fq]} {arrow} {ids[key]}')
    return '\n'.join(lines) if classes else 'flowchart LR\n  empty["Sin clases Java declaradas"]'


def database_docs(tables):
    if not tables:
        return ('Todavía no hay tablas de aplicación definidas por migraciones. Se generará el diccionario al añadirlas.',
                'flowchart LR\n  empty["Sin tablas de aplicación: migraciones pendientes"]')
    ids = {(t['schema'], t['name']): f't{i}' for i, t in enumerate(tables)}
    diagram = ['erDiagram']
    dictionary = []
    for table in tables:
        key = (table['schema'], table['name'])
        dictionary.extend([f'### `{text(".".join(key))}`', '', text(table.get('description')), '',
            '| Columna | Tipo | Nulo | Clave | Valor por defecto | Descripción |',
            '|---|---|---|---|---|---|'])
        diagram.append(f'  {ids[key]}["{text(".".join(key))}"] {{')
        foreign = {col for fk in table['foreign_keys'] for col in fk['columns']}
        for column in table['columns']:
            keys = [label for flag, label in [(column['primary_key'], 'PK'), (column['name'] in foreign, 'FK'), (column.get('unique'), 'UK')] if flag]
            dictionary.append('| ' + ' | '.join(map(text, [column['name'], column['type'], 'Sí' if column['nullable'] else 'No', ', '.join(keys), column.get('default'), column.get('description')])) + ' |')
            suffix = ' ' + ','.join(keys) if keys else ''
            diagram.append(f'    {identifier(column["type"])} {identifier(column["name"])}{suffix}')
        diagram.append('  }')
        for fk in table['foreign_keys']:
            target = (fk['target_schema'], fk['target_table'])
            if target not in ids:
                raise ValueError(f'Foreign key target excluded from schema: {target}')
            parent = '|o' if fk['nullable'] else '||'
            child = 'o|' if fk['unique'] else 'o{'
            diagram.append(f'  {ids[target]} {parent}--{child} {ids[key]} : "{text(fk["name"])}"')
            dictionary.extend(['', f'FK `{text(fk["name"])}`: `{text(", ".join(fk["columns"]))}` → `{text(".".join(target))} ({text(", ".join(fk["target_columns"]))})`.', ''])
        dictionary.append('')
    return '\n'.join(dictionary), '\n'.join(diagram)


def components(classes):
    packages = sorted({c.get('package') for c in classes})
    ids = {p: f'p{i}' for i, p in enumerate(packages)}
    lines = ['flowchart TB', '  frontend["Frontend React · frontend/src"]', '  subgraph backend["Backend Java · clases implementadas"]']
    for package in packages:
        names = ', '.join(c.get('name') for c in classes if c.get('package') == package)
        lines.append(f'    {ids[package]}["{text(package)}<br/>{text(names)}"]')
    lines.append('  end')
    links = set()
    for c in classes:
        for imported in c.findall('import'):
            target = imported.get('name').rsplit('.', 1)[0]
            if target in ids and target != c.get('package'):
                links.add((ids[c.get('package')], ids[target]))
    lines.extend(f'  {a} -->|importa| {b}' for a, b in sorted(links))
    return '\n'.join(lines)


def deployment(compose, maven_image=None):
    lines = ['flowchart TB', '  subgraph local["Procesos de desarrollo"]',
             '    browser["Navegador"] --> ui["React / Vite · npm run dev"]',
             '    api["Spring Boot · mvnw spring-boot:run"]', '    ui -->|/api| api', '  end',
             '  subgraph docker["Servicios definidos en infra/compose.yml"]']
    for i, (name, service) in enumerate(sorted(compose.get('services', {}).items())):
        ports = ', '.join(f'{p.get("published", "")}: {p["target"]}' for p in service.get('ports', []))
        image = service.get('image', 'build local')
        lines.append(f'    s{i}["{text(name)}<br/>{text(image)}<br/>{text(ports)}"]')
        if image.startswith('postgres:'):
            lines.append(f'    api -->|JDBC| s{i}')
        for j, volume in enumerate(service.get('volumes', [])):
            if volume.get('type') == 'volume':
                lines.append(f'    s{i} --- v{i}_{j}[("{text(volume.get("source"))}")]')
    lines.append('  end')
    if maven_image:
        lines.extend(['  subgraph analysis["Docker · ejecución efímera con límites"]',
                      f'    maven["{text(maven_image)}"]', '  end',
                      '  api -->|CLI Docker · copia de fixture| maven',
                      '  maven -->|JSON y TGF| api'])
    return '\n'.join(lines)


def update_readme(original, generated):
    block = START + '\n' + generated.rstrip() + '\n' + END
    if START not in original and END not in original:
        return original.rstrip() + '\n\n' + block + '\n'
    if original.count(START) != 1 or original.count(END) != 1 or original.index(START) > original.index(END):
        raise ValueError('README generation markers are invalid; refusing to overwrite manual content')
    before, rest = original.split(START, 1)
    _, after = rest.split(END, 1)
    return before + block + after


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--readme', type=Path, default=Path('README.md'))
    parser.add_argument('--inputs', type=Path, default=Path('build/docs'))
    args = parser.parse_args()
    classes = list(ET.parse(args.inputs / 'java.xml').getroot().iter('class'))
    tables = json.loads((args.inputs / 'schema.json').read_text(encoding='utf-8'))['tables']
    compose = json.loads((args.inputs / 'compose.json').read_text(encoding='utf-8'))
    resolver = Path('backend/src/main/java/com/smartsca/adapter/outbound/maven/MavenDependencyResolver.java').read_text(encoding='utf-8')
    maven_image = re.search(r'IMAGE\s*=\s*"([^"]+)"', resolver).group(1)
    dictionary, er = database_docs(tables)
    parts = ['## SmartSCA — documentación generada', '',
        'Generada desde declaraciones Java, migraciones aplicadas en PostgreSQL y Compose. El diseño previsto y los paquetes vacíos no se presentan como clases implementadas.', '',
        'Para ejecutar: backend `cd backend && ./mvnw spring-boot:run`; frontend `cd frontend && npm ci && npm run dev`. PostgreSQL requiere `POSTGRES_PASSWORD` y `docker compose -f infra/compose.yml up -d`.', '',
        f'Antes de ejecutar análisis, construir el entorno aislado desde la raíz: `docker build -t {maven_image} infra/analysis`. Docker debe estar activo y accesible desde el backend.', '',
        'Los comentarios Javadoc/TSDoc aportan las descripciones de clases, métodos y propiedades; sin comentarios se documentan las firmas disponibles.', '',
        '### Diccionario de datos', '', dictionary]
    for title, diagram in [('Diagrama de entidad relación', er), ('Diagrama de clases Java', class_diagram(classes)),
                           ('Diagrama de componentes', components(classes)), ('Diagrama de despliegue', deployment(compose, maven_image))]:
        parts.extend(['', '### ' + title, '', '```mermaid', diagram, '```'])
    parts.extend(['', 'Los componentes muestran dependencias por imports. El despliegue muestra procesos locales, servicios de Compose y el entorno Maven efímero.', '',
        '### Automatizaciones', '',
        '- `project-readme.yml`: actualiza únicamente este bloque después de cambios del proyecto; preserva el texto manual.',
        '- `technical-pages.yml`: genera Javadoc (incluye miembros privados) y TypeDoc para el frontend, y publica en GitHub Pages.',
        '- Ambos permiten ejecución manual desde **Actions**. Pages requiere **Settings → Pages → Source: GitHub Actions**, un plan compatible con repositorios privados y autorización de administración.',
        '- El diccionario y ER proceden de migraciones Flyway, no de entidades de dominio. En CI se usa una base efímera; nunca la base de producción.', ''])
    args.readme.write_text(update_readme(args.readme.read_text(encoding='utf-8') if args.readme.exists() else '# SmartSCA\n', '\n'.join(parts)), encoding='utf-8')


if __name__ == '__main__':
    main()
