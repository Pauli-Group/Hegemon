import contextlib
import datetime
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
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


class PublicReferenceTest(unittest.TestCase):
    def setUp(self):
        self.node = {'height': 100, 'genesis': json.loads(probe.RELEASE.read_text())['genesis_hash'],
                     'chain_id': json.loads(probe.RELEASE.read_text())['chain_id']}
        self.when = datetime.datetime(2026, 11, 4, 17, 45, tzinfo=datetime.timezone.utc)
        self.hash = '0x' + '12' * 32
        self.status = {'network': 'pre-mainnet-v0.11', 'genesis_hash': self.node['genesis'],
                       'chain_id': self.node['chain_id'], 'available': True, 'syncing': False,
                       'error': None, 'peers': 3, 'height': 100, 'hash': self.hash,
                       'block_timestamp_ms': int(self.when.timestamp() * 1000),
                       'updated_at': self.when.isoformat()}
        self.block = {'block': {'height': 100, 'hash': self.hash,
                                'timestamp_ms': int(self.when.timestamp() * 1000)}}
        self.calls = []

    def read(self, url, method, params):
        self.calls.append((method, params))
        return self.hash

    def fetch(self, path):
        if path == '/testnet/status.json':
            return self.status
        self.assertEqual(path, f'/testnet-api/v1/block/{self.block["block"]["height"]}?limit=1')
        return self.block

    def compare(self, read=None):
        return probe.compare_public_tip('http://127.0.0.1:9944', self.node,
                                        read=read or self.read, fetch=self.fetch,
                                        now=self.when.timestamp())

    def test_matching_tip_and_bounded_height_difference(self):
        result = self.compare()
        self.assertTrue(result['matches'])
        self.assertEqual(result['common_height'], 100)
        self.assertEqual(result['reference_block_age_seconds'], 0)
        self.assertEqual(result['common_block_age_seconds'], 0)
        self.assertEqual(self.calls, [('chain_getBlockHash', [100])] * 2)
        self.node['height'] = 103
        self.assertEqual(self.compare()['height_difference'], 3)
        self.node['height'] = 88
        self.block['block']['height'] = 88
        self.assertEqual(self.compare()['height_difference'], -12)

    def test_stale_or_wrong_network_reference_is_rejected(self):
        changes = [('network', 'wrong'), ('genesis_hash', '0x' + '00' * 32),
                   ('chain_id', '0x' + '00' * 32), ('available', False),
                   ('syncing', True), ('peers', 0), ('peers', True),
                   ('updated_at', 'not-a-time'), ('updated_at', '2026-11-04T17:42:00+00:00'),
                   ('updated_at', '2026-11-04T17:46:00+00:00')]
        original = self.status.copy()
        for name, value in changes:
            with self.subTest(name=name, value=value):
                self.status = dict(original, **{name: value})
                with self.assertRaises(ValueError):
                    self.compare()

    def test_fresh_status_does_not_hide_a_stalled_chain(self):
        self.status['block_timestamp_ms'] -= (probe.MAX_TIP_IDLE + 1) * 1000
        with self.assertRaisesRegex(ValueError, 'latest block is .* seconds old'):
            self.compare()
        self.status['syncing'] = True
        with self.assertRaisesRegex(ValueError, 'reports syncing; latest block is'):
            self.compare()

    def test_syncing_and_network_identity_have_distinct_diagnostics(self):
        self.status['syncing'] = True
        with self.assertRaisesRegex(ValueError, 'Public explorer reports syncing'):
            self.compare()
        self.status['network'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'wrong network'):
            self.compare()

    def test_block_timestamps_must_be_valid_fresh_and_consistent(self):
        original = self.status['block_timestamp_ms']
        for value in (None, True, -1, str(original), original + 121_000):
            with self.subTest(value=value):
                self.status['block_timestamp_ms'] = value
                with self.assertRaises(ValueError):
                    self.compare()
        self.status['block_timestamp_ms'] = original
        self.block['block']['timestamp_ms'] = original - 1
        with self.assertRaisesRegex(ValueError, 'timestamp changed'):
            self.compare()
        self.node['height'] = 99
        self.block['block']['height'] = 99
        self.block['block']['timestamp_ms'] = original - (probe.MAX_TIP_IDLE + 1) * 1000
        with self.assertRaisesRegex(ValueError, 'Common block timestamp'):
            self.compare()

    def test_large_gap_fork_and_inconsistent_explorer_are_rejected(self):
        self.node['height'] = 87
        with self.assertRaisesRegex(ValueError, 'differ by 13 blocks'):
            self.compare()
        self.node['height'] = 100
        self.block['block']['hash'] = '0x' + '34' * 32
        with self.assertRaisesRegex(ValueError, 'disagree'):
            self.compare()
        self.block['block']['hash'] = self.hash
        self.status['hash'] = '0x' + '56' * 32
        with self.assertRaisesRegex(ValueError, 'explorer tip changed'):
            self.compare()

    def test_observed_healthy_but_stale_node_is_rejected(self):
        self.node['height'] = 8659
        self.status['height'] = 9471
        with self.assertRaisesRegex(ValueError, 'differ by 812 blocks'):
            self.compare()

    def test_node_identity_cannot_be_replaced_by_a_matching_reference(self):
        wrong = '0x' + 'aa' * 32
        self.node['genesis'] = wrong
        self.status['genesis_hash'] = wrong
        with self.assertRaisesRegex(ValueError, 'network identity'):
            self.compare()

    def test_local_reorganization_is_rejected(self):
        hashes = iter((self.hash, '0x' + 'ab' * 32))
        with self.assertRaisesRegex(ValueError, 'reorganized'):
            self.compare(read=lambda *_: next(hashes))

    def test_public_fetcher_rejects_arbitrary_urls_without_a_request(self):
        for path in ('https://example.com', '/testnet/status.json?x=1',
                     '/testnet-api/v1/block/../../secret?limit=1'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                probe.public_json(path)

    def test_cli_fails_closed_when_requested_reference_is_unavailable(self):
        base = dict(self.node, basic_wallet_checks_passed=True, limitation='Trust the node.')
        output = io.StringIO()
        argv = ['probe', '--rpc', 'http://127.0.0.1:9944', '--check-public-tip']
        with patch.object(sys, 'argv', argv), patch.object(probe, 'probe', return_value=base), \
             patch.object(probe, 'compare_public_tip', side_effect=OSError('offline')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report['public_reference']['matches'])
        self.assertFalse(report['public_testnet_ready'])

    def test_default_cli_does_not_call_public_reference(self):
        output = io.StringIO()
        argv = ['probe', '--rpc', 'http://127.0.0.1:9944']
        with patch.object(sys, 'argv', argv), \
             patch.object(probe, 'probe', return_value={'basic_wallet_checks_passed': True}), \
             patch.object(probe, 'compare_public_tip', side_effect=AssertionError('network call')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 0)

    def test_cli_requires_both_basic_and_reference_checks(self):
        argv = ['probe', '--rpc', 'http://127.0.0.1:9944', '--check-public-tip']
        for basic in (False, True):
            with self.subTest(basic=basic), patch.object(sys, 'argv', argv), \
                 patch.object(probe, 'probe', return_value={'basic_wallet_checks_passed': basic,
                                                          'limitation': 'Trust the node.'}), \
                 patch.object(probe, 'compare_public_tip', return_value={'matches': True}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(), 0 if basic else 1)


class PublicProfileGuardTest(unittest.TestCase):
    def test_public_profile_requires_ntp_peers_and_a_close_tip(self):
        release = json.loads(probe.RELEASE.read_text())
        node = {'height': 200, 'genesis': release['genesis_hash'], 'chain_id': release['chain_id'],
                'peers': 8, 'syncing': False}
        compare = {'matches': True, 'node_height': 200, 'reference_height': 200, 'height_difference': 0}
        found, _ = probe.assert_public_profile(
            'http://127.0.0.1:9944', genesis=release['genesis_hash'], manifest=probe.MANIFEST,
            ntp=lambda: True, probe_node=lambda url: node, compare=lambda url, observed: compare)
        self.assertEqual(found['height'], 200)
        with self.assertRaisesRegex(ValueError, 'NTP'):
            probe.assert_public_profile(
                'http://127.0.0.1:9944', genesis=release['genesis_hash'], manifest=probe.MANIFEST,
                ntp=lambda: False, probe_node=lambda url: node, compare=lambda url, observed: compare)
        with self.assertRaisesRegex(ValueError, 'peers'):
            probe.assert_public_profile(
                'http://127.0.0.1:9944', genesis=release['genesis_hash'], manifest=probe.MANIFEST,
                ntp=lambda: True, probe_node=lambda url: {**node, 'peers': 1},
                compare=lambda url, observed: compare)
        with self.assertRaisesRegex(ValueError, 'limit 2'):
            probe.assert_public_profile(
                'http://127.0.0.1:9944', genesis=release['genesis_hash'], manifest=probe.MANIFEST,
                ntp=lambda: True, probe_node=lambda url: node,
                compare=lambda url, observed: {'matches': True, 'node_height': 200, 'reference_height': 203})
        self.assertEqual(probe.hegemon_policy_confirmations(),
                         json.loads((probe.ROOT / 'config/swap/chain-timing.json').read_text())['chains']['hegemon']['confirmations'])


if __name__ == '__main__':
    unittest.main()
