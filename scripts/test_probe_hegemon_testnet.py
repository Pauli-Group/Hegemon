import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import probe_hegemon_testnet as probe


def responses():
    release = json.loads(probe.RELEASE.read_text())
    return {
        'chain_getBlockHash': release['genesis_hash'],
        'hegemon_nodeConfig': {
            'networkProfile': 'pre-mainnet',
            'chainId': release['chain_id'],
            # Canonical digest in the release's source-owned capability tuple.
            'networkManifestDigest': ('0x19e8d3b3d9fc14b762288f0fe63e8d7d55b14d4a9e4f5278'
                                      '3b26d7a9e4785da6fb78319fed1a8b2f60ebc21f0e142dc0'
                                      '7b20d0c09ed37a9e28c7af865e6f50a0'),
            'networkManifest': json.loads(probe.MANIFEST.read_text()),
        },
        'system_health': {'isSyncing': False, 'peers': 4},
        'rpc_methods': {'methods': list(probe.REQUIRED)},
        'chain_getHeader': {'number': '0x123'},
        'hegemon_privateSpendParameters': {
            'relation_digest': probe.RELATION, 'action_id': 15,
            'public_words': 86, 'ciphertext_bytes': 2608,
        },
    }


class HegemonProbeTest(unittest.TestCase):
    def run_probe(self, values):
        calls = []
        def read(url, method, params):
            calls.append((method, params))
            return values[method]
        result = probe.probe('http://127.0.0.1:19944', read)
        self.assertNotIn('hegemon_submitAction', [method for method, _ in calls])
        self.assertEqual(calls[0], ('chain_getBlockHash', [0]))
        return result

    def test_trusted_matching_node_reports_prerequisites(self):
        result = self.run_probe(responses())
        self.assertTrue(result['basic_wallet_checks_passed'])
        self.assertEqual(result['height'], 291)
        self.assertEqual(result['missing_wallet_methods'], [])

    def test_safe_rpc_and_old_node_are_not_reported_ready(self):
        values = responses()
        values['rpc_methods']['methods'].remove('hegemon_submitAction')
        values['rpc_methods']['methods'].remove('chain_getBlockActionsChunk')
        result = self.run_probe(values)
        self.assertFalse(result['basic_wallet_checks_passed'])
        self.assertEqual(set(result['missing_wallet_methods']),
                         {'hegemon_submitAction', 'chain_getBlockActionsChunk'})

    def test_incompatible_relation_or_stale_node_fails_basic_checks(self):
        values = responses()
        values['hegemon_privateSpendParameters']['relation_digest'] = '00' * 64
        self.assertFalse(self.run_probe(values)['basic_wallet_checks_passed'])
        for health in ({'isSyncing': True, 'peers': 1}, {'isSyncing': False, 'peers': 0}):
            values = responses()
            values['system_health'] = health
            self.assertFalse(self.run_probe(values)['basic_wallet_checks_passed'])

    def test_wrong_genesis_chain_manifest_and_digest_are_rejected(self):
        for target in ('genesis', 'chain', 'manifest', 'digest'):
            values = responses()
            if target == 'genesis':
                values['chain_getBlockHash'] = '0x' + '00' * 32
            elif target == 'chain':
                values['hegemon_nodeConfig']['chainId'] = '0x' + '00' * 32
            elif target == 'manifest':
                values['hegemon_nodeConfig']['networkManifest']['pow_bits'] = 1
            else:
                values['hegemon_nodeConfig']['networkManifestDigest'] = '0x' + '00' * 64
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'identity'):
                self.run_probe(values)

    def test_endpoint_requires_loopback_ip_and_no_userinfo(self):
        for url in ('http://example.com:9944', 'http://localhost:9944',
                    'https://127.0.0.1:9944', 'http://user@127.0.0.1:9944',
                    'http://127.0.0.1:9944/?token=x', 'http://127.0.0.1',
                    'http://127.0.0.1:99999'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                probe.endpoint(url)
        self.assertEqual(probe.endpoint('http://[::1]:19944'), 'http://[::1]:19944')

    def test_real_http_transport_uses_read_only_methods(self):
        values, calls = responses(), []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['content-length'])))
                calls.append(data['method'])
                body = json.dumps({'jsonrpc': '2.0', 'id': data['id'],
                                   'result': values[data['method']]}).encode()
                self.send_response(200)
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = probe.probe('http://127.0.0.1:' + str(server.server_port))
            self.assertTrue(result['basic_wallet_checks_passed'])
            self.assertEqual(set(calls), set(values))
            self.assertNotIn('hegemon_submitAction', calls)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
