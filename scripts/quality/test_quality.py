import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from report import compare, finding, snapshot, write
from scan import normalize_semgrep, snyk
from sonar import Sonar, collect, normalize


class QualityReportsTests(unittest.TestCase):
    def result(self, tool='semgrep'):
        result = snapshot(tool, 'version', ['backend'], 'same-config')
        result['status'] = 'COMPLETO'
        return result

    def issue(self, text='unsafe', category='SECURITY'):
        return finding(category, 'rule', 'backend/src/main/java/Demo.java', 10, text, 'HIGH', text)

    def test_first_scan_has_no_claimed_resolutions(self):
        current = self.result()
        compare(current, None)
        self.assertIsNone(current['changes']['resolved'])
        self.assertIn('SIN_HISTORIAL', current['comparison'])

    def test_compatible_completed_scans_separate_new_persistent_and_resolved(self):
        old, current = self.result(), self.result()
        old['findings'] = [self.issue('kept'), self.issue('removed')]
        current['findings'] = [self.issue('kept'), self.issue('new')]
        compare(current, old)
        self.assertEqual(['removed'], [item['message'] for item in current['changes']['resolved']])
        self.assertEqual(['new'], [item['message'] for item in current['changes']['new']])
        self.assertEqual(['kept'], [item['message'] for item in current['changes']['persistent']])

    def test_incomplete_scan_and_changed_rules_scope_version_repository_never_clear_findings(self):
        old = self.result()
        old['findings'] = [self.issue()]
        for key, value in [('status', 'INCOMPLETO'), ('configuration', 'other'), ('scope', ['frontend']),
                           ('scannerVersion', 'other'), ('repository', 'other'), ('schemaVersion', 2)]:
            with self.subTest(key=key):
                current = self.result()
                current[key] = value
                compare(current, old)
                self.assertIsNone(current['changes']['resolved'])
        old['status'] = 'INCOMPLETO'
        current = self.result()
        compare(current, old)
        self.assertIsNone(current['changes']['resolved'])

    def test_line_moves_preserve_identity(self):
        old, current = self.result(), self.result()
        old['findings'] = [self.issue()]
        moved = self.issue()
        moved['line'] = 150
        current['findings'] = [moved]
        compare(current, old)
        self.assertEqual([], current['changes']['resolved'])

    def test_semgrep_login_placeholders_cannot_merge_distinct_fragments_or_change_after_line_moves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / '.github/workflows/demo.yml'
            path.parent.mkdir(parents=True)
            contents = b'uses: actions/checkout@v7\nuses: actions/setup-java@v6\n'
            path.write_bytes(contents)
            split = contents.index(b'\n') + 1
            def match(start, end):
                return dict(path='.github/workflows/demo.yml', check_id='unpinned', start=dict(offset=start, line=1),
                            end=dict(offset=end), extra=dict(fingerprint='requires login', lines='requires login', message='Pin action', severity='WARNING'))
            raw = dict(results=[match(0, split - 1), match(split, len(contents) - 1)], errors=[])
            first = normalize_semgrep(raw, root)
            self.assertNotEqual(first[0]['id'], first[1]['id'])
            path.write_bytes(b'\n\n' + contents)
            moved = copy.deepcopy(raw)
            for item in moved['results']:
                item['start']['offset'] += 2
                item['end']['offset'] += 2
                item['start']['line'] += 2
            self.assertEqual([item['id'] for item in first], [item['id'] for item in normalize_semgrep(moved, root)])
            malformed = copy.deepcopy(raw)
            malformed['results'][0]['path'] = '../outside-secret'
            with self.assertRaises(ValueError):
                normalize_semgrep(malformed, root)

    def test_render_escapes_findings_groups_duplicates_and_keeps_unknown_counts(self):
        result = self.result()
        item = self.issue('<script>bad</script> | ![image](https://evil.example/)')
        result['findings'] = [item, {**item, 'line': 20}]
        with tempfile.TemporaryDirectory() as directory:
            write(result, directory)
            report = json.loads((Path(directory) / 'report.json').read_text())
            text = (Path(directory) / 'report.md').read_text()
            self.assertEqual(1, len(report['findings']))
            self.assertEqual(2, len(report['findings'][0]['occurrences']))
            self.assertNotIn('<script>', text)
            self.assertNotIn('![image]', text)
            self.assertIn('Sin evidencia comparable', text)
            self.assertIsNone(report['changes']['resolved'])

    def test_missing_snyk_token_is_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SNYK_TOKEN': ''}):
            result = snyk(Path(directory))
        self.assertEqual('NO_EJECUTADO', result['status'])
        self.assertTrue(result['errors'])

    def test_snyk_complete_findings_are_grouped_and_a_failed_manifest_prevents_resolution(self):
        from types import SimpleNamespace
        def scan_command(command, **kwargs):
            output = Path(next(value.split('=', 1)[1] for value in command if value.startswith('--json-file-output=')))
            self.assertNotIn('unit-test-token', command)
            issue = dict(id='SNYK-DEMO', title='Reference', packageName='demo', version='1', severity='high', **{'from': ['project', 'demo@1']})
            output.write_text(json.dumps(dict(vulnerabilities=[issue, issue], dependencyCount=2, packageManager='test')))
            return SimpleNamespace(returncode=1 if kwargs['cwd'] == 'backend' else frontend_code)
        for frontend_code in (1, 2):
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SNYK_TOKEN': 'unit-test-token', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_SHA': 'unit-test-commit'}), \
                    patch('scan.shutil.which', return_value='snyk-test'), patch('scan.subprocess.run', side_effect=scan_command):
                result = snyk(Path(directory))
            self.assertEqual('COMPLETO' if frontend_code == 1 else 'INCOMPLETO', result['status'])
            self.assertEqual(2 if frontend_code == 1 else 1, len(result['findings']))
            self.assertEqual(2, len(result['findings'][0]['paths']))

    def test_sonar_refuses_credentials_in_urls_and_remote_http(self):
        for url in ('https://admin:password@example.org', 'http://example.org', 'https://example.org?token=x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Sonar(url, 'test-token')

    def test_sonar_paginates_and_rejects_incomplete_or_excessive_collections(self):
        client = Sonar('https://example.org', 'test-token')
        pages = [dict(paging=dict(total=2), issues=[dict(key='one')], components=[]),
                 dict(paging=dict(total=2), issues=[dict(key='two')], components=[])]
        with patch.object(client, 'get', side_effect=pages):
            items, _ = client.pages('issues/search', 'issues')
        self.assertEqual(['one', 'two'], [item['key'] for item in items])
        for page in (dict(paging=dict(total=10001), issues=[]), dict(paging=dict(total=2), issues=[])):
            with patch.object(client, 'get', return_value=page), self.assertRaises(ValueError):
                client.pages('issues/search', 'issues')

    def test_native_sonar_fixed_and_safe_hotspots_are_separate_from_current_findings(self):
        issue = dict(component='project:src/main/java/Demo.java', rule='java:S1', key='bug', type='BUG',
                     message='Bug', severity='MAJOR', line=5, status='OPEN')
        hotspot = dict(component=issue['component'], key='hotspot', message='Review', securityCategory='other',
                       vulnerabilityProbability='HIGH', status='TO_REVIEW', line=9)
        searched_statuses = []
        expected_project_parameter = 'project'
        class Client:
            def get(self, endpoint, **parameters):
                if endpoint == 'ce/task':
                    return dict(task=dict(status='SUCCESS', analysisId='analysis', componentKey='project'))
                if endpoint == 'project_analyses/search':
                    return dict(analyses=[dict(key='analysis', revision=result['commit'])])
                if endpoint == 'qualityprofiles/search':
                    return dict(profiles=[dict(key='java-profile', language='java', name='Default', rulesUpdatedAt='date', activeRuleCount=100)])
                if endpoint == 'qualitygates/project_status':
                    return dict(projectStatus=dict(status='ERROR'))
                if endpoint == 'measures/component':
                    return dict(component=dict(measures=[]))
                if endpoint == 'hotspots/show':
                    return dict(rule=dict(key='java:S2'))
                raise AssertionError(endpoint)
            def pages(self, endpoint, field, **parameters):
                if field == 'issues':
                    values = [issue] if parameters['resolved'] == 'false' else [
                        dict(issue, key='fixed', resolution='FIXED'), dict(issue, key='ignored', resolution='FALSE-POSITIVE')]
                else:
                    assert parameters.get(expected_project_parameter) == 'project'
                    assert ('projectKey' if expected_project_parameter == 'project' else 'project') not in parameters
                    searched_statuses.append(parameters['status'])
                    values = [hotspot] if parameters['status'] == 'TO_REVIEW' else [dict(hotspot, key='safe', status='REVIEWED', resolution='SAFE'),
                              dict(hotspot, key='fixed-hotspot', status='REVIEWED', resolution='FIXED'),
                              dict(hotspot, key='ack', status='REVIEWED', resolution='ACKNOWLEDGED')]
                return copy.deepcopy(values), {}
        for version, expected_project_parameter in [('9.9.8.100196', 'projectKey'), ('10.2.0.77647', 'project'), ('26.9.0.129388', 'project')]:
            with self.subTest(serverVersion=version):
                result = self.result('sonarqube')
                result['serverVersion'] = version
                searched_statuses.clear()
                collect(Client(), 'project', 'task', result)
                self.assertEqual(['TO_REVIEW', 'REVIEWED'], searched_statuses)
                self.assertEqual('COMPLETO', result['status'])
                self.assertEqual(['bug', 'hotspot', 'ack'], [item['sonarKey'] for item in result['findings']])
                self.assertEqual(['fixed', 'fixed-hotspot'], [item['sonarKey'] for item in result['nativeFixed']])
                self.assertEqual(['safe'], [item['sonarKey'] for item in result['reviewedSafe']])
                self.assertEqual('ERROR', result['qualityGate']['status'])

    def test_wrong_sonar_revision_and_nonbackend_historical_issues_are_rejected(self):
        class Client:
            def get(self, endpoint, **parameters):
                if endpoint == 'ce/task':
                    return dict(task=dict(status='SUCCESS', analysisId='analysis', componentKey='project'))
                return dict(analyses=[dict(key='another-analysis', revision='other')])
        with self.assertRaises(ValueError):
            collect(Client(), 'project', 'task', self.result('sonarqube'))
        self.assertIsNone(normalize(dict(component='project:frontend/src/App.tsx'), {}, 'BUG'))


if __name__ == '__main__':
    unittest.main()
