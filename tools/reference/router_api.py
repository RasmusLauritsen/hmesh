#!/usr/bin/env python3
"""Historical read-only API reference. Use hmesh for normal router management."""
import argparse
import hashlib
import hmac
import http.cookiejar
import json
import re
import secrets
import ssl
import subprocess
import sys
import urllib.error
import urllib.request


# Explicitly reviewed retrieval endpoints, not an arbitrary GET proxy.
ENDPOINTS = {
    'routerstatus': 'system/routerstatus',
    'deviceinfo': 'system/deviceinfo',
    'wlanmode': 'system/wlanmode',
    'device_count': 'system/device_count',
    'HostInfo': 'system/HostInfo',
    'MultiHostInfo': 'system/MultiHostInfo',
    'onlinestate': 'system/onlinestate',
    'onlinestate_all': 'system/onlinestate?devid=all',
    'topology': 'device/topology',
    'l2topo': 'device/l2topo',
    'slavedevinfo': 'hilink/slavedevinfo',
    'hilink_status': 'hilink/hilink_status',
    'wan': 'ntwk/wan?type=active',
    'hilinkwaninfo': 'ntwk/hilinkwaninfo',
    'wandiagnose': 'ntwk/wandiagnose',
    'getmacaddress': 'ntwk/getmacaddress',
    'lan': 'ntwk/lan',
    'lan_host': 'ntwk/lan_host',
    'lan_all': 'ntwk/lan_all',
    'lan_server': 'ntwk/lan_server',
    'lan_ipaddressreserve': 'ntwk/lan_ipaddressreserve',
    'wlanradio': 'ntwk/wlanradio',
    'WlanGuideBasic': 'ntwk/WlanGuideBasic?type=notshowpassall',
    'guest_network': 'ntwk/guest_network?type=notshowpassall',
    'guest_network_resttime': 'ntwk/guest_network_resttime',
    'guest_network_limitrate': 'ntwk/guest_network_limitrate',
    'wlandbho': 'ntwk/wlandbho',
    'wlanwifisync': 'ntwk/wlanwifisync',
    'wlanintelligent': 'ntwk/wlanintelligent',
    'wlanaccess': 'ntwk/wlanfilterenhance',
    'wlantimeswitch': 'ntwk/wlantimeswitch',
    'wlan_time_switch_list': 'ntwk/wlan_time_switch_list',
    'backhaul': 'ntwk/backhaul',
    'repeaterinfo': 'ntwk/repeaterinfo',
    'repeaterstate': 'ntwk/repeaterstate',
    'lan_upnp': 'ntwk/lan_upnp',
    'lan_upnp_portmapping': 'ntwk/lan_upnp_portmapping',
    'ipv6_enable': 'ntwk/ipv6_enable',
    'ipv6_wan': 'ntwk/ipv6_wan',
    'ipv6_lan': 'ntwk/ipv6_lan',
    'firewall': 'ntwk/firewall',
    'dmz': 'ntwk/dmz',
    'portmapping': 'ntwk/portmapping',
    'application': 'app/application',
    'applicationitems': 'app/applicationitems',
    'porttrigger': 'ntwk/porttrigger',
    'timecontrol': 'ntwk/timecontrol',
    'urlfilter': 'ntwk/urlfilter',
    'sntp': 'ntwk/sntp',
    'qos': 'app/qos',
    'qosclass_host': 'app/qosclass_host',
    'ethportmode': 'app/ethportmode',
    'ethnegotiation': 'ntwk/ethnegotiation',
    'iptv': 'ntwk/iptv',
    'autoupgrade': 'system/autoupgrade',
    'rebootplan': 'system/rebootplan',
    'nfc_switch': 'bsp/nfc_switch',
}


def bws_password():
    result = subprocess.run(['bws', 'secret', 'list'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('BWS lookup failed; CLI output withheld for secret safety')
    matches = [s for s in json.loads(result.stdout) if s.get('key') == 'router_password']
    if len(matches) != 1:
        raise RuntimeError('Expected exactly one BWS secret named router_password')
    return matches[0]['value']


class Router:
    def __init__(self, base='https://192.168.50.1', insecure=False):
        self.base = base.rstrip('/')
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.cookies = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = {}

    def request(self, path, data=None):
        headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest',
                   '_ResponseFormat': 'JSON', 'Referer': self.base + '/html/index.html'}
        body = None
        if data is not None:
            # Only authentication may use POST, even when called programmatically.
            if path not in ('/api/system/user_login_nonce', '/api/system/user_login_proof'):
                raise ValueError('Non-authentication POST is prohibited')
            body = json.dumps({'data': data, 'csrf': self.csrf}).encode()
            headers['Content-Type'] = 'application/json; charset=utf-8'
        req = urllib.request.Request(self.base + path, data=body, headers=headers)
        with self.http.open(req, timeout=20) as response:
            raw = response.read().decode()
        if path == '/html/index.html':
            return raw
        value = json.loads(raw)
        if isinstance(value, dict) and value.get('csrf_param'):
            self.csrf = {k: value[k] for k in ('csrf_param', 'csrf_token')}
        return value

    def login(self, password):
        html = self.request('/html/index.html')
        self.csrf = {k: re.search(r'name="' + k + r'" content="([^"]+)"', html)[1]
                     for k in ('csrf_param', 'csrf_token')}
        first = secrets.token_hex(32)
        challenge = self.request('/api/system/user_login_nonce',
                                 {'username': 'admin', 'firstnonce': first})
        if challenge.get('err') != 0:
            raise RuntimeError('Login challenge rejected; no retries attempted')
        final = challenge['servernonce']
        if not final.startswith(first):
            raise RuntimeError('Server nonce does not extend client nonce')
        salted = hashlib.pbkdf2_hmac('sha256', password.encode(),
                                    bytes.fromhex(challenge['salt']), int(challenge['iterations']), 32)
        # Huawei's CryptoJS code reverses conventional SCRAM HMAC arguments.
        client_key = hmac.digest(b'Client Key', salted, 'sha256')
        server_key = hmac.digest(b'Server Key', salted, 'sha256')
        auth = (first + ',' + final + ',' + final).encode()
        signature = hmac.digest(auth, hashlib.sha256(client_key).digest(), 'sha256')
        proof = bytes(a ^ b for a, b in zip(client_key, signature)).hex()
        result = self.request('/api/system/user_login_proof',
                              {'clientproof': proof, 'finalnonce': final})
        if result.get('err') != 0:
            raise RuntimeError('Login proof rejected; no retries attempted')
        if not hmac.compare_digest(result['serversignature'], hmac.digest(auth, server_key, 'sha256').hex()):
            raise RuntimeError('Server signature verification failed')
        expected = hmac.digest(server_key, bytes.fromhex(result['rsan']), 'sha256').hex()
        if not hmac.compare_digest(result['rsapubkeysignature'], expected):
            raise RuntimeError('RSA public key signature verification failed')

    def get(self, name):
        return self.request('/api/' + ENDPOINTS[name])


def schema(value):
    """Describe observed shapes without retaining private response values."""
    if value is None:
        return {'type': 'null'}
    if isinstance(value, dict):
        def safe_key(key):
            if re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', key):
                return '<MAC-address>'
            if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', key):
                return '<IP-address>'
            return key
        return {'type': 'object', 'properties': {safe_key(k): schema(v) for k, v in value.items()}}
    if isinstance(value, list):
        variants = []
        for item in value:
            shape = schema(item)
            if shape not in variants:
                variants.append(shape)
        return {'type': 'array', 'items_observed': variants}
    return {'type': 'boolean' if isinstance(value, bool) else
            'integer' if isinstance(value, int) else 'number' if isinstance(value, float) else 'string'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('endpoint', choices=sorted(ENDPOINTS))
    parser.add_argument('--base', default='https://192.168.50.1')
    parser.add_argument('--insecure', action='store_true', help='Trust the local self-signed TLS certificate')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--schema', action='store_true', help='Print types only (the default)')
    output.add_argument('--unsafe-raw', action='store_true',
                        help='Print unfiltered responses, potentially including credentials')
    args = parser.parse_args()
    if args.unsafe_raw:
        print('WARNING: raw router output may contain passwords, session tokens and private network data. '
              'Do not publish or commit it.', file=sys.stderr)
    router = Router(args.base, args.insecure)
    router.login(bws_password())
    value = router.get(args.endpoint)
    print(json.dumps(value if args.unsafe_raw else schema(value), indent=2))


if __name__ == '__main__':
    main()
