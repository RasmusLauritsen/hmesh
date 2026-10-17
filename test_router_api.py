"""Offline protocol tests. The SCRAM fixture comes from the router's CryptoJS code.

Fixture inputs are deliberately fake, public test data; no actual secrets captured.
"""
import io
import json
import unittest
from unittest.mock import Mock, patch

from router_api import ENDPOINTS, Router, bws_password, schema


FIRST = 'ab' * 32
FINAL = FIRST + 'cd' * 32
PROOF = 'c1daf607086590326ab83269758703d7f89587019320b4d848226083d8e28638'
SERVER_SIGNATURE = 'c62f0b60a9a809f63c6caf086800d923195d68e3dadeab0f590c482b19d0d8f9'
RSA_SIGNATURE = '11c28c41671a287104233d2767a9f3170a26f0b142dfcbc7cfdfcc02d69c5f46'


class ProtocolTests(unittest.TestCase):
    def router(self, nonce_error=False, server_signature=SERVER_SIGNATURE,
               rsa_signature=RSA_SIGNATURE, final=FINAL, proof_error=False):
        r = Router()
        replies = [
            b'<meta name="csrf_param" content="param-one"/>'
            b'<meta name="csrf_token" content="token-one"/>',
            json.dumps({'err': 1 if nonce_error else 0, 'salt': '00112233445566778899aabbccddeeff',
                        'iterations': 1000, 'servernonce': final,
                        'csrf_param': 'param-two', 'csrf_token': 'token-two'}).encode(),
            json.dumps({'err': 1 if proof_error else 0, 'serversignature': server_signature,
                        'rsan': 'a1b2c3d4', 'rsae': '010001', 'level': 1,
                        'rsapubkeysignature': rsa_signature}).encode(),
        ]
        r.http = Mock()
        r.http.open.side_effect = [io.BytesIO(b) for b in replies]
        return r

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_login_matches_actual_router_javascript_fixture(self, _):
        r = self.router()
        r.login('test-password-not-a-secret')
        requests = [c.args[0] for c in r.http.open.call_args_list]
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[0].get_method(), 'GET')
        nonce = json.loads(requests[1].data)
        self.assertEqual(nonce, {'data': {'username': 'admin', 'firstnonce': FIRST},
                                 'csrf': {'csrf_param': 'param-one', 'csrf_token': 'token-one'}})
        proof = json.loads(requests[2].data)
        self.assertEqual(proof, {'data': {'clientproof': PROOF, 'finalnonce': FINAL},
                                 'csrf': {'csrf_param': 'param-two', 'csrf_token': 'token-two'}})

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_rejected_challenge_is_not_retried(self, _):
        r = self.router(nonce_error=True)
        with self.assertRaisesRegex(RuntimeError, 'challenge rejected'):
            r.login('test-password-not-a-secret')
        self.assertEqual(r.http.open.call_count, 2)

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_rejected_proof_is_not_retried(self, _):
        r = self.router(proof_error=True)
        with self.assertRaisesRegex(RuntimeError, 'proof rejected'):
            r.login('test-password-not-a-secret')
        self.assertEqual(r.http.open.call_count, 3)

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_bad_nonce_is_rejected_before_proof(self, _):
        r = self.router(final='unrelated-nonce')
        with self.assertRaisesRegex(RuntimeError, 'nonce does not extend'):
            r.login('test-password-not-a-secret')
        self.assertEqual(r.http.open.call_count, 2)

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_server_signature_is_verified(self, _):
        r = self.router(server_signature='00' * 32)
        with self.assertRaisesRegex(RuntimeError, 'Server signature'):
            r.login('test-password-not-a-secret')

    @patch('router_api.secrets.token_hex', return_value=FIRST)
    def test_rsa_signature_is_verified(self, _):
        r = self.router(rsa_signature='00' * 32)
        with self.assertRaisesRegex(RuntimeError, 'RSA public key signature'):
            r.login('test-password-not-a-secret')

    def test_non_authentication_post_blocked_before_network(self):
        r = self.router()
        with self.assertRaises(ValueError):
            r.request('/api/service/reboot.cgi', {'anything': True})
        r.http.open.assert_not_called()

    def test_get_uses_only_allowlist(self):
        r = self.router()
        with self.assertRaises(KeyError):
            r.get('/api/service/reboot.cgi')
        r.http.open.assert_not_called()

    def test_get_has_no_body_and_uses_exact_query(self):
        r = self.router()
        r.http.open.side_effect = [io.BytesIO(b'{"WifiConfig":[]}')]
        self.assertEqual(r.get('WlanGuideBasic'), {'WifiConfig': []})
        req = r.http.open.call_args.args[0]
        self.assertEqual(req.get_method(), 'GET')
        self.assertIsNone(req.data)
        self.assertTrue(req.full_url.endswith('/api/' + ENDPOINTS['WlanGuideBasic']))


class SafetyTests(unittest.TestCase):
    def test_schema_retains_types_not_private_values(self):
        result = schema({'pwd': 'never-save-me', 'clients': [{'active': True, 'rate': 2}],
                         'other': None, 'empty': []})
        self.assertNotIn('never-save-me', json.dumps(result))
        self.assertEqual(result['properties']['pwd'], {'type': 'string'})
        self.assertEqual(result['properties']['empty']['items_observed'], [])
        self.assertEqual(result['properties']['clients']['items_observed'][0]
                         ['properties']['active'], {'type': 'boolean'})

    def test_schema_redacts_address_keys(self):
        result = json.dumps(schema({'aa:bb:cc:dd:ee:ff': True, '192.0.2.1': 1}))
        self.assertNotIn('aa:bb:cc:dd:ee:ff', result)
        self.assertNotIn('192.0.2.1', result)

    @patch('router_api.subprocess.run')
    def test_bws_selects_exact_key(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps([
            {'key': 'unrelated', 'value': 'do-not-use'},
            {'key': 'router_password', 'value': 'fake-test-password'}]))
        self.assertEqual(bws_password(), 'fake-test-password')

    @patch('router_api.subprocess.run')
    def test_duplicate_bws_key_is_rejected(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps([
            {'key': 'router_password', 'value': 'fake-one'},
            {'key': 'router_password', 'value': 'fake-two'}]))
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            bws_password()

    @patch('router_api.subprocess.run')
    def test_bws_error_does_not_expose_output(self, run):
        run.return_value = Mock(returncode=1, stderr='sensitive-test-output')
        with self.assertRaises(RuntimeError) as error:
            bws_password()
        self.assertNotIn('sensitive-test-output', str(error.exception))


if __name__ == '__main__':
    unittest.main()
