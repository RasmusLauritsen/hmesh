#!/usr/bin/env python3
"""Collect value-free observations for the client's reviewed GET allowlist."""
import datetime
import json
from pathlib import Path
import time
import urllib.error

from router_api import ENDPOINTS, Router, bws_password, schema


def observe(router, name):
    try:
        value = router.get(name)
        result = {'http_status': 200, 'schema': schema(value)}
        if isinstance(value, dict):
            result['result_codes'] = {k: value[k] for k in ('err', 'errcode', 'error')
                                      if k in value and isinstance(value[k], (int, bool))}
        result['empty'] = value in (None, {}, [])
        return result
    except urllib.error.HTTPError as error:
        return {'http_status': error.code}
    except Exception as error:
        # Exception messages may contain response content, so retain class only.
        return {'exception': type(error).__name__}


def main():
    router = Router(insecure=True)
    anonymous = {}
    for name in ENDPOINTS:
        anonymous[name] = observe(router, name)
        time.sleep(0.1)
    router.login(bws_password())
    observations = {}
    for name, path in ENDPOINTS.items():
        result = observe(router, name)
        observations[name] = {'method': 'GET', 'path': '/api/' + path,
                              'anonymous': anonymous[name], 'authenticated': result}
        print(name, result.get('http_status', result.get('exception')), result.get('result_codes', {}),
              'empty' if result.get('empty') else '')
        time.sleep(0.2)
    report = {'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'base_url': router.base, 'endpoints': observations}
    output = Path(__file__).resolve().parent / 'docs' / 'observations.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print('Saved docs/observations.json (types and result codes only)')


if __name__ == '__main__':
    main()
