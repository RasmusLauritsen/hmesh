"""Offline regression tests using synthetic secrets and isolated repositories."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('gitleaks'), 'install Gitleaks 8.30.1')
class ScannerTests(unittest.TestCase):
    def scan(self, text, path='example.txt'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            target = source / path
            target.parent.mkdir(parents=True)
            target.write_text(text)
            report = root / 'report.json'
            result = subprocess.run(
                ['gitleaks', 'dir', '.', '--config', str(ROOT / '.gitleaks.toml'),
                 '--redact', '--no-banner', '--exit-code', '42',
                 '--report-format', 'json', '--report-path', str(report)],
                cwd=source, capture_output=True, text=True)
            self.assertIn(result.returncode, (0, 42), result.stderr)
            findings = json.loads(report.read_text()) if report.exists() else []
            return {finding['RuleID'] for finding in findings}

    def test_router_password_assignments(self):
        for key in ['HMESH_PASSWORD', 'router_password', 'Password', 'pwd', 'WpaPreSharedKey']:
            with self.subTest(key=key):
                text = json.dumps({key: 'synthetic-' + 'credential-9274'})
                self.assertIn('router-credential-literal', self.scan(text))

    def test_unquoted_environment_assignment(self):
        text = 'export ' + '='.join(['HMESH_PASSWORD', 'synthetic-credential-9274'])
        self.assertIn('router-password-env', self.scan(text))

    def test_session_and_csrf_values(self):
        for key in ['SessionID_R3', 'csrf_param', 'csrf_token']:
            for value in ['synthetic-session-9274', '9274a1']:
                with self.subTest(key=key, value=value):
                    self.assertIn('router-session-literal', self.scan(json.dumps({key: value})))
        self.assertIn('router-session-literal', self.scan('Cookie: ' + '='.join(['SessionID_R3', 'synthetic9274'])))

    def test_standard_rules_remain_enabled(self):
        token = 'ghp_' + 'Ab9cD2eF5gH8jK1mN4pQ7rS0tU3vW6xY9zB2'
        self.assertIn('github-pat', self.scan(token))

    def test_captured_login_page(self):
        for key in ['csrf_param', 'csrf_token']:
            text = f'<meta name="{key}" content="synthetic-session-9274"/>'
            self.assertIn('router-csrf-html', self.scan(text, 'capture.html'))

    def test_narrow_fixture_exceptions(self):
        key = 'csrf_token'
        text = json.dumps({key: 't1'})
        self.assertFalse(self.scan(text, 'internal/router/client_test.go'))
        self.assertIn('router-session-literal', self.scan(text, 'production.json'))
        text = json.dumps({key: 'synthetic-new-secret-9274'})
        self.assertIn('router-session-literal', self.scan(text, 'internal/router/client_test.go'))
        self.assertFalse(self.scan(json.dumps({'password': '<router password>'})))
        key = 'password'
        self.assertIn('router-credential-literal', self.scan(
            json.dumps({key: 'synthetic-new-secret-9274'}), 'internal/cli/cli_test.go'))

    def test_hook_checks_index_not_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.run(['git', *args], cwd=root, check=True,
                                      capture_output=True, text=True)
            git('init', '-q')
            shutil.copy(ROOT / '.gitleaks.toml', root)
            target = root / 'example.txt'
            target.write_text('ordinary content\n')
            git('add', '.')
            git('-c', 'user.name=Security Test', '-c', 'user.email=test@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic baseline')
            key = 'HMESH_PASSWORD'
            secret = json.dumps({key: 'synthetic-' + 'credential-9274'})
            target.write_text(secret)
            git('add', 'example.txt')
            target.write_text('ordinary content\n')
            def hook():
                return subprocess.run(['sh', str(ROOT / '.githooks/pre-commit')], cwd=root,
                                      capture_output=True, text=True)
            self.assertNotEqual(hook().returncode, 0, 'staged secret was missed')
            git('add', 'example.txt')
            target.write_text(secret)
            self.assertEqual(hook().returncode, 0, 'unstaged content should not be scanned')
