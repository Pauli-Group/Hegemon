import contextlib
import io
import json
import unittest
import check_hegemon_gateway as gateway
import probe_hegemon_testnet as probe
from test_probe_hegemon_testnet import responses


def served(methods=None, answer_unknown=False):
    values = responses()
    values['rpc_methods'] = {'methods': list(methods if methods is not None else sorted(gateway.ALLOWED))}
    calls = []

    def read(url, method, params):
        calls.append(method)
        if method in values:
            return values[method]
        if answer_unknown:
            return {'ok': True}
        raise ValueError('RPC method failed: ' + method)
    return read, calls


class GatewayInterfaceTest(unittest.TestCase):
    def check(self, **kwargs):
        read, calls = served(**kwargs)
        return gateway.check_gateway('http://127.0.0.1:19944', read=read), calls

    def test_exact_allow_list_passes_and_never_calls_an_unsafe_method(self):
        report, calls = self.check()
        self.assertTrue(report['interface_ok'], report['problems'])
        self.assertEqual(report['extra_methods'], [])
        self.assertEqual(set(calls) - gateway.ALLOWED - {gateway.UNKNOWN_SENTINEL}, set())
        self.assertNotIn('hegemon_submitAction', calls)

    def test_extra_methods_fail_each_unsafe_group(self):
        for extra in ('hegemon_startMining', 'hegemon_stopMining', 'hegemon_generateProof', 'hegemon_walletNotes',
                      'hegemon_walletCiphertexts', 'da_submitWitnesses', 'state_getStorage', 'hegemon_peerList',
                      'hegemon_submitTransaction'):
            with self.subTest(extra):
                report, calls = self.check(methods=[*sorted(gateway.ALLOWED), extra])
                self.assertFalse(report['interface_ok'])
                self.assertEqual(report['extra_methods'], [extra])
                self.assertNotIn(extra, calls)

    def test_missing_required_method_fails(self):
        for missing in sorted(gateway.ALLOWED - gateway.OPTIONAL):
            with self.subTest(missing):
                methods = sorted(gateway.ALLOWED - {missing})
                read, _ = served(methods=methods)
                report = gateway.check_gateway('http://127.0.0.1:19944', read=read)
                self.assertFalse(report['interface_ok'])
                self.assertIn(missing, report['missing_methods'])

    def test_unknown_method_must_be_an_error(self):
        report, _ = self.check(answer_unknown=True)
        self.assertFalse(report['interface_ok'])
        self.assertFalse(report['unknown_method_rejected'])

    def test_wrong_network_or_parameters_fail(self):
        read, _ = served()
        values = responses()
        values['hegemon_privateSpendParameters']['relation_digest'] = '00' * 64
        values['rpc_methods'] = {'methods': sorted(gateway.ALLOWED)}
        report = gateway.check_gateway('http://127.0.0.1:19944', read=lambda u, m, p: values[m] if m in values else (_ for _ in ()).throw(ValueError('RPC method failed: ' + m)))
        self.assertFalse(report['interface_ok'])
        values = responses()
        values['chain_getBlockHash'] = '0x' + '11' * 32
        values['rpc_methods'] = {'methods': sorted(gateway.ALLOWED)}
        with self.assertRaises(ValueError):
            gateway.check_gateway('http://127.0.0.1:19944', read=lambda u, m, p: values[m])

    def test_remote_url_is_refused_like_the_probe(self):
        read, _ = served()
        with self.assertRaises(ValueError):
            gateway.check_gateway('https://gateway.example', read=probe.rpc)

    def test_cli_exit_code_and_json(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gateway.main(['--rpc', 'https://gateway.example'])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out.getvalue())['interface_ok'])

    def test_allow_list_contains_only_what_the_wallet_sync_and_submit_path_needs(self):
        self.assertEqual(set(probe.REQUIRED) - gateway.ALLOWED, set())
        for forbidden in ('hegemon_startMining', 'hegemon_generateProof', 'hegemon_walletNotes', 'state_getStorage'):
            self.assertNotIn(forbidden, gateway.ALLOWED)


if __name__ == '__main__':
    unittest.main()
