import unittest
import xml.etree.ElementTree as ET
import json
import os
from pathlib import Path
import subprocess
import tempfile

from generate import START, END, class_diagram, database_docs, deployment, update_readme


class DocumentationChecks(unittest.TestCase):
    def test_manual_text_is_preserved_and_updates_are_idempotent(self):
        self.assertTrue(update_readme('# Original\n', 'new').startswith('# Original\n\n' + START))
        original = '# Manual\n\n' + START + '\nold\n' + END + '\nFooter\n'
        generated = update_readme(original, 'new')
        self.assertEqual(generated, '# Manual\n\n' + START + '\nnew\n' + END + '\nFooter\n')
        self.assertEqual(update_readme(generated, 'new'), generated)
        with self.assertRaises(ValueError):
            update_readme('# Manual\n' + START, 'new')

    def test_empty_schema_is_not_invented(self):
        dictionary, diagram = database_docs([])
        self.assertIn('no hay tablas', dictionary)
        self.assertNotIn('erDiagram', diagram)

    def test_composite_fk_and_unique_nullable_relationship(self):
        def column(name):
            return {'name': name, 'type': 'integer', 'nullable': False, 'primary_key': True, 'unique': False}
        tables = [
            {'schema': 'public', 'name': 'parent', 'columns': [column('id'), column('version')], 'foreign_keys': []},
            {'schema': 'public', 'name': 'child', 'columns': [column('id'), column('version')],
             'foreign_keys': [{'name': 'composite', 'columns': ['id', 'version'], 'target_schema': 'public',
                              'target_table': 'parent', 'target_columns': ['id', 'version'], 'nullable': True, 'unique': True}]},
        ]
        dictionary, diagram = database_docs(tables)
        self.assertIn('id, version', dictionary)
        self.assertIn('PK,FK', diagram)
        self.assertIn('t0 |o--o| t1', diagram)

    def test_inventory_generics_and_deployment_does_not_disclose_password(self):
        classes = ET.fromstring('<inventory><class package="demo" name="A" kind="CLASS"><field name="items" type="List&lt;String&gt;" modifiers="[private]"/></class></inventory>')
        self.assertIn('-List~String~ items', class_diagram(list(classes)))
        compose = {'services': {'db': {'image': 'postgres:17', 'environment': {'POSTGRES_PASSWORD': 'never-output-this'}}}}
        self.assertNotIn('never-output-this', deployment(compose))
        self.assertIn('Docker · ejecución efímera', deployment(compose, 'smartsca-maven:test'))
        self.assertIn('api -->|JDBC| s0', deployment(compose))

    def test_jdk_inventory_preserves_records_interfaces_and_nested_members(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            (source / 'R.java').write_text('package demo; interface I { void work(); } public record R(String name) implements I { public void work() {} static class Nested { private int field; } }')
            output = source / 'inventory.xml'
            command = ['java', str(Path(__file__).parent / 'JavaInventory.java'), str(source), str(output)]
            subprocess.run(command, check=True, capture_output=True)
            classes = {c.get('name'): c for c in ET.parse(output).getroot().iter('class')}
            self.assertEqual(classes['R'].get('kind'), 'RECORD')
            self.assertEqual(classes['R'].find('field').get('name'), 'name')
            self.assertEqual(classes['I'].find('method').get('name'), 'work')
            self.assertEqual(classes['R.Nested'].find('field').get('name'), 'field')
            (source / 'R.java').write_text('public class R { invalid syntax')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    @unittest.skipUnless(os.environ.get('PGDATABASE') == 'smartsca_docs', 'Needs the disposable CI database')
    def test_live_postgresql_composite_foreign_key(self):
        def psql(sql):
            return subprocess.check_output(['psql', '--no-psqlrc', '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql], text=True)
        try:
            psql('CREATE SCHEMA docs_check; CREATE TABLE docs_check.parent(id integer, version integer, PRIMARY KEY(id,version)); CREATE TABLE docs_check.child(id integer, version integer, UNIQUE(id,version), FOREIGN KEY(id,version) REFERENCES docs_check.parent(id,version));')
            schema = json.loads(psql((Path(__file__).parent / 'schema.sql').read_text()))
            child = next(t for t in schema['tables'] if t['schema'] == 'docs_check' and t['name'] == 'child')
            fk = child['foreign_keys'][0]
            self.assertEqual(fk['columns'], ['id', 'version'])
            self.assertEqual(fk['target_columns'], ['id', 'version'])
            self.assertTrue(fk['unique'])
            self.assertTrue(fk['nullable'])
        finally:
            psql('DROP SCHEMA IF EXISTS docs_check CASCADE;')


if __name__ == '__main__':
    unittest.main()
