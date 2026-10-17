"""Offline safety tests; never access BWS or a router."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import router_api


class OutputTests(unittest.TestCase):
    def invoke(self, *flags):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(router_api, 'Router') as router, \
                patch.object(router_api, 'bws_password', return_value='synthetic'), \
                patch('sys.argv', ['router_api.py', 'backhaul', *flags]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            router.return_value.get.return_value = {'pwd': 'private-fixture'}
            router_api.main()
        return json.loads(out.getvalue()), err.getvalue()

    def test_default_and_schema_are_value_free(self):
        for flags in [(), ('--schema',)]:
            value, warning = self.invoke(*flags)
            self.assertEqual(value['properties']['pwd'], {'type': 'string'})
            self.assertNotIn('private-fixture', json.dumps(value))
            self.assertEqual(warning, '')

    def test_raw_requires_opt_in_and_warns(self):
        value, warning = self.invoke('--unsafe-raw')
        self.assertEqual(value['pwd'], 'private-fixture')
        self.assertIn('WARNING', warning)
        self.assertNotIn('private-fixture', warning)

    def test_output_flags_conflict(self):
        with patch('sys.argv', ['router_api.py', 'backhaul', '--schema', '--unsafe-raw']), \
                patch.object(router_api, 'Router') as router, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                router_api.main()
            self.assertEqual(error.exception.code, 2)
            router.assert_not_called()
