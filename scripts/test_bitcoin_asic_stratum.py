#!/usr/bin/env python3
"""Socket-level contract tests for the Bitcoin80 Stratum adapter."""

import hashlib
import json
import time
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bitcoin_asic_stratum as bridge


def hash2(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def work(job_id="job-1", ntime="69000000", nbits="207fffff",
         parent_start=0, prehash_start=32, version_mask="00000000"):
    parent = bytes(range(parent_start, parent_start + 32))
    prefix = b"hegemon-btc80" + bytes(range(prehash_start, prehash_start + 32))
    reference = (
        (0x20000000).to_bytes(4, "little") + parent[::-1]
        + hash2(prefix + bytes(28)) + int(ntime, 16).to_bytes(4, "little")
        + int(nbits, 16).to_bytes(4, "little") + bytes(4)
    )
    return {
        "available": True, "algorithm": "sha256d-bitcoin80", "job_id": job_id,
        "height": 1, "parent_hash": "0x" + parent.hex(), "version": "20000000",
        "version_rolling_mask": version_mask,
        "ntime": ntime, "nbits": nbits,
        "target": "0x" + f"{(int(nbits, 16) & 0xffffff) << (8 * ((int(nbits, 16) >> 24) - 3)):064x}",
        "coinbase_prefix": prefix.hex(), "coinbase_suffix": "",
        "extranonce_bytes": 28, "header80": reference.hex(), "expires_in": 60,
    }


class MockRPC:
    def __init__(self):
        self.work = work()
        self.submissions = []
        self.solution_outcomes = []

    def call(self, method, params=None):
        if method == "hegemon_poolWork":
            return self.work
        if method == "hegemon_submitPoolShare":
            self.submissions.append(params)
            if self.solution_outcomes:
                outcome = self.solution_outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            return {"accepted": True, "block_candidate": True,
                    "hash": "0x" + "00" * 32, "error": None}
        raise AssertionError(method)


class NodeRPCAuthenticationTest(unittest.TestCase):
    def test_nonempty_rpc_token_is_rejected_instead_of_ignored(self):
        with self.assertRaisesRegex(ValueError, "does not authenticate tokens"):
            bridge.NodeRPC("http://127.0.0.1:9944", "secret")

    def test_no_fake_authentication_field_is_sent(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, size):
                return b'{"jsonrpc":"2.0","id":1,"result":{"available":false}}'

        with patch.object(bridge, "urlopen", return_value=Response()) as opened:
            result = bridge.NodeRPC("http://127.0.0.1:9944").call("hegemon_poolWork")
        request = opened.call_args.args[0]
        self.assertEqual(json.loads(request.data)["params"], [{}])
        self.assertNotIn("auth_token", request.data.decode())
        self.assertEqual(result, {"available": False})


class StratumTCPTest(unittest.TestCase):
    def setUp(self):
        self.rpc = MockRPC()
        self.pool = bridge.Pool(self.rpc, "miner.1", "secret", "0.000000000001", extranonce2_bytes=4)
        self.pool.poll_once()
        self.server = bridge._Server(("127.0.0.1", 0), self.pool)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.sock = socket.create_connection(self.server.server_address, timeout=2)
        self.sock.settimeout(2)
        self.reader = self.sock.makefile("rb")

    def tearDown(self):
        self.reader.close()
        self.sock.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def send(self, rid, method, params):
        self.sock.sendall((json.dumps({"id": rid, "method": method, "params": params}) + "\n").encode())

    def read(self):
        return json.loads(self.reader.readline())

    def subscribe(self):
        self.send(1, "mining.configure", [["unsupported-extension"], {}])
        config = self.read()
        self.assertFalse(config["result"]["unsupported-extension"])
        self.send(2, "mining.subscribe", [])
        sub = self.read()
        self.assertEqual(sub["id"], 2)
        self.assertEqual(sub["result"][2], 4)
        return sub["result"][1]

    def authorize(self, password="secret"):
        self.send(3, "mining.authorize", ["miner.1", password])
        auth = self.read()
        if password == "secret":
            self.assertTrue(auth["result"])
            difficulty = self.read()
            self.assertEqual(difficulty["method"], "mining.set_difficulty")
            notify = self.read()
            self.assertEqual(notify["method"], "mining.notify")
            return notify["params"]
        self.assertFalse(auth["result"])
        return None

    def solution_params(self, ex1, notify):
        ex2 = "01020304"
        job = self.pool.jobs[notify[0]]
        for candidate in range(100):
            nonce = f"{candidate:08x}"
            header = job.header(bytes.fromhex(ex1 + ex2), nonce)
            if int.from_bytes(hash2(header), "little") <= job.network_target:
                return ["miner.1", notify[0], ex2, notify[7], nonce]
        self.fail("expected easy compact-target solution")

    def test_real_tcp_share_and_independent_header(self):
        ex1 = self.subscribe()
        notify = self.authorize()
        self.assertEqual(notify[0], "job-1")
        self.assertEqual(notify[1], bridge.stratum_prevhash(self.pool.current.parent_hash))
        self.assertEqual(notify[4], [])
        self.assertTrue(notify[8])
        # Rebuild the bytes as a miner would: Bitaxe reverses each 4-byte word
        # of notify.prevhash to form header.prevhash.
        prev = bytes.fromhex(notify[1])
        header_prev = b"".join(prev[i:i + 4][::-1] for i in range(0, 32, 4))
        self.assertEqual(header_prev, bytes.fromhex(self.rpc.work["parent_hash"][2:])[::-1])
        ex2 = "01020304"
        merkle = hash2(bytes.fromhex(notify[2] + ex1 + ex2 + notify[3]))
        base = (int(notify[5], 16).to_bytes(4, "little") + header_prev
                + merkle + int(notify[7], 16).to_bytes(4, "little")
                + int(notify[6], 16).to_bytes(4, "little"))
        for candidate in range(100):
            nonce = f"{candidate:08x}"
            expected = base + candidate.to_bytes(4, "little")
            if int.from_bytes(hash2(expected), "little") <= self.pool.current.network_target:
                break
        else:
            self.fail("expected easy compact-target solution")
        self.assertEqual(len(expected), 80)
        self.assertEqual(expected, self.pool.current.header(bytes.fromhex(ex1 + ex2), nonce))
        self.assertLessEqual(int.from_bytes(hash2(expected), "little"), self.pool.current.network_target)
        self.send(4, "mining.submit", ["miner.1", "job-1", ex2, notify[7], nonce])
        self.assertTrue(self.read()["result"])
        self.assertEqual(self.rpc.submissions, [{
            "job_id": "job-1", "nonce": nonce, "extranonce": ex1 + ex2,
            "ntime": notify[7], "mining_version": notify[5],
        }])
        self.send(5, "mining.submit", ["miner.1", "job-1", ex2, notify[7], nonce])
        self.assertEqual(self.read()["error"][1], "duplicate share")

    def test_wrong_password_and_malformed_submission(self):
        self.subscribe()
        self.authorize("wrong")
        self.send(4, "mining.submit", ["miner.1", "job-1", "00000000", "69000000", "00000000"])
        self.assertEqual(self.read()["error"][1], "unauthorized")
        self.authorize()
        self.send(5, "mining.submit", ["miner.1", "job-1", "not hex!", "69000000", "00000000"])
        self.assertIsNotNone(self.read()["error"])
        self.send(51, "mining.submit", ["miner.1", "job-1", "00 00 00", "69000000", "00000000"])
        self.assertEqual(self.read()["error"][1], "extranonce2 must be hex")
        self.send(6, "mining.submit", ["miner.1", "job-1", "00000000", "69000001", "00000000"])
        self.assertEqual(self.read()["error"][1], "ntime rolling is disabled")
        self.send(7, "mining.submit", ["miner.1", "job-1", "00000000", "69000000", "00000000", "20000001"])
        self.assertEqual(self.read()["error"][1], "invalid submit parameters")
        self.assertEqual(self.rpc.submissions, [])

    def test_invalid_requests_and_line_limit(self):
        self.sock.sendall(b"[]\n")
        self.assertEqual(self.read()["error"][1], "invalid request")
        self.sock.sendall(b"{" + b"x" * bridge.MAX_LINE + b"}\n")
        self.assertEqual(self.reader.readline(), b"")

    def test_stale_job_and_malformed_json(self):
        self.subscribe()
        self.authorize()
        self.sock.sendall(b"{bad json\n")
        self.assertEqual(self.read()["error"][1], "invalid JSON")
        self.rpc.work = work("job-2", parent_start=1)
        self.pool.poll_once()
        self.assertEqual(self.read()["method"], "mining.set_difficulty")
        self.assertEqual(self.read()["method"], "mining.notify")
        self.send(4, "mining.submit", ["miner.1", "job-1", "00000000", "69000000", "00000000"])
        self.assertEqual(self.read()["error"][1], "stale job")

    def test_invalid_header_work_is_rejected(self):
        self.rpc.work = work("job-bad")
        self.rpc.work["header80"] = "00" * 80
        with self.assertRaisesRegex(ValueError, "header80 does not match"):
            self.pool.poll_once()
        self.assertEqual(self.pool.current.job_id, "job-1")

    def test_signed_noncanonical_and_above_limit_nbits_reject(self):
        self.assertEqual(bridge.compact_target("207fffff"), 0x7fffff << 232)
        self.assertEqual(bridge.compact_target("1f0fffff"), 0x0fffff << 224)
        self.assertEqual(bridge.compact_target("017f0000"), 127)
        for bits in ("20800000", "1f8fffff", "20000001", "2100ffff", "00000000"):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                bridge.compact_target(bits)
        self.rpc.work = work("signed-job", nbits="20800000")
        with self.assertRaisesRegex(ValueError, "compact target"):
            self.pool.poll_once()
        self.assertEqual(self.pool.current.job_id, "job-1")

    def test_local_share_does_not_forward_below_network_target(self):
        self.rpc.work = work("hard-network", nbits="1f0fffff")
        self.pool.poll_once()
        ex1 = self.subscribe()
        notify = self.authorize()
        ex2 = "00000000"
        for candidate in range(100):
            nonce = f"{candidate:08x}"
            header = self.pool.current.header(bytes.fromhex(ex1 + ex2), nonce)
            if int.from_bytes(hash2(header), "little") > self.pool.current.network_target:
                break
        else:
            self.fail("expected non-network local share")
        self.send(8, "mining.submit", ["miner.1", "hard-network", ex2, notify[7], nonce])
        self.assertTrue(self.read()["result"])
        self.assertEqual(self.rpc.submissions, [])

    def test_transient_rpc_failure_allows_exact_solution_retry(self):
        ex1 = self.subscribe()
        notify = self.authorize()
        params = self.solution_params(ex1, notify)
        self.rpc.solution_outcomes = [TimeoutError("temporary RPC timeout")]
        self.send(10, "mining.submit", params)
        self.assertEqual(self.read()["error"][1], "node RPC unavailable")
        self.send(11, "mining.submit", params)
        self.assertTrue(self.read()["result"])
        self.assertEqual(len(self.rpc.submissions), 2)
        self.send(12, "mining.submit", params)
        self.assertEqual(self.read()["error"][1], "duplicate share")
        self.assertEqual(len(self.rpc.submissions), 2)

    def test_busy_native_rpc_is_retried_without_miner_resubmission(self):
        class BusyResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, size):
                return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {
                    "code": -32602,
                    "message": "ASIC block import busy; retry solution",
                }}).encode()

        with patch.object(bridge, "urlopen", return_value=BusyResponse()):
            try:
                bridge.NodeRPC("http://127.0.0.1:9944").call("hegemon_submitPoolShare")
            except ValueError as busy:
                self.rpc.solution_outcomes = [busy]
            else:
                self.fail("expected the native busy RPC error")
        ex1 = self.subscribe()
        notify = self.authorize()
        params = self.solution_params(ex1, notify)
        self.send(19, "mining.submit", params)
        self.assertTrue(self.read()["result"], "one-shot full-target solution was lost on native import busy")
        self.assertEqual(len(self.rpc.submissions), 2)
        self.assertEqual(self.rpc.submissions[0], self.rpc.submissions[1])

    def test_import_busy_rejection_allows_exact_solution_retry(self):
        ex1 = self.subscribe()
        notify = self.authorize()
        params = self.solution_params(ex1, notify)
        self.rpc.solution_outcomes = [{"accepted": False, "error": "import busy"}]
        self.send(20, "mining.submit", params)
        self.assertEqual(self.read()["error"][1], "import busy")
        self.send(21, "mining.submit", params)
        self.assertTrue(self.read()["result"])
        self.assertEqual(len(self.rpc.submissions), 2)
        self.send(22, "mining.submit", params)
        self.assertEqual(self.read()["error"][1], "duplicate share")
        self.assertEqual(len(self.rpc.submissions), 2)

    def test_same_parent_retains_old_job_and_parent_change_cleans(self):
        ex1 = self.subscribe()
        old_notify = self.authorize()
        self.rpc.work = work("job-2", prehash_start=64)
        self.pool.poll_once()
        self.assertEqual(self.read()["method"], "mining.set_difficulty")
        new_notify = self.read()
        self.assertEqual(new_notify["method"], "mining.notify")
        self.assertFalse(new_notify["params"][8])
        self.send(30, "mining.submit", self.solution_params(ex1, old_notify))
        self.assertTrue(self.read()["result"])
        self.assertEqual(self.rpc.submissions[-1]["job_id"], "job-1")
        self.rpc.work = work("job-3", parent_start=1, prehash_start=96)
        self.pool.poll_once()
        self.assertEqual(self.read()["method"], "mining.set_difficulty")
        self.assertTrue(self.read()["params"][8])
        self.send(31, "mining.submit", ["miner.1", "job-2", "00000000", "69000000", "00000000"])
        self.assertEqual(self.read()["error"][1], "stale job")

    def test_unavailable_work_clears_all_jobs(self):
        self.subscribe()
        self.authorize()
        self.rpc.work = {"available": False, "reason": "syncing"}
        self.pool.poll_once()
        self.assertEqual(self.pool.jobs, {})
        self.send(32, "mining.submit", ["miner.1", "job-1", "00000000", "69000000", "00000000"])
        self.assertEqual(self.read()["error"][1], "stale job")

    def test_same_parent_job_cache_is_bounded(self):
        for index in range(2, 68):
            self.rpc.work = work(f"job-{index}", prehash_start=32 + index)
            self.pool.poll_once()
        self.assertEqual(len(self.pool.jobs), bridge.MAX_JOBS)
        self.assertNotIn("job-1", self.pool.jobs)
        self.assertIn("job-67", self.pool.jobs)

    def test_ordinary_share_cache_full_does_not_block_network_solution(self):
        ex1 = self.subscribe()
        notify = self.authorize()
        job = self.pool.current
        ordinary = []
        network = None
        for candidate in range(100):
            nonce = f"{candidate:08x}"
            value = int.from_bytes(hash2(job.header(bytes.fromhex(ex1 + "01020304"), nonce)), "little")
            if value <= job.network_target and network is None:
                network = nonce
            elif value > job.network_target and len(ordinary) < 2:
                ordinary.append(nonce)
            if network is not None and len(ordinary) == 2:
                break
        self.assertIsNotNone(network)
        self.assertEqual(len(ordinary), 2)
        with patch.object(bridge, "MAX_SEEN_SHARES", 1):
            for rid, nonce in enumerate(ordinary, 40):
                self.send(rid, "mining.submit", ["miner.1", notify[0], "01020304", notify[7], nonce])
                self.assertTrue(self.read()["result"])
            self.assertEqual(len(self.pool.seen), 1)
            self.send(42, "mining.submit", ["miner.1", notify[0], "01020304", notify[7], network])
            self.assertTrue(self.read()["result"])
        self.assertEqual(len(self.rpc.submissions), 1)

    def test_stalled_client_cannot_block_healthy_notification(self):
        self.subscribe()
        self.authorize()
        stalled_sock, unread = socket.socketpair()
        stalled_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        stalled = bridge.Client(stalled_sock, authorized=True)
        self.pool.start_client(stalled)
        # Occupy the OS send buffer without reading the other side.
        stalled_sock.setblocking(False)
        while True:
            try:
                stalled_sock.send(b"x" * 4096, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
        stalled_sock.setblocking(True)
        try:
            self.rpc.work = work("job-2", prehash_start=64)
            start = time.monotonic()
            self.pool.poll_once()
            self.assertLess(time.monotonic() - start, 1.0)
            self.assertEqual(self.read()["method"], "mining.set_difficulty")
            self.assertEqual(self.read()["method"], "mining.notify")
            for index in range(3, 10):
                self.rpc.work = work(f"job-{index}", prehash_start=64 + index)
                self.pool.poll_once()
                self.read()
                self.read()
            self.assertNotIn(stalled, self.pool.clients)
        finally:
            stalled_sock.close()
            unread.close()


class PollSerializationTest(unittest.TestCase):
    def test_overlapping_polls_publish_parent_or_unavailable_in_request_order(self):
        for newer in (work("job-2", parent_start=1), {"available": False}):
            with self.subTest(available=newer["available"]):
                rpc = MockRPC()
                pool = bridge.Pool(rpc, "miner.1", "secret", "0.000000000001")
                pool.poll_once()
                first_entered, second_entered = threading.Event(), threading.Event()
                release_first = threading.Event()
                calls_lock, errors = threading.Lock(), []
                calls = 0

                def call(method, params=None):
                    nonlocal calls
                    self.assertEqual(method, "hegemon_poolWork")
                    with calls_lock:
                        calls += 1
                        number = calls
                    if number == 1:
                        first_entered.set()
                        if not release_first.wait(2):
                            raise TimeoutError("test did not release first work snapshot")
                        return work()
                    second_entered.set()
                    return newer

                def poll():
                    try:
                        pool.poll_once()
                    except Exception as exc:
                        errors.append(exc)

                with patch.object(rpc, "call", side_effect=call):
                    first = threading.Thread(target=poll)
                    second = threading.Thread(target=poll)
                    first.start()
                    try:
                        self.assertTrue(first_entered.wait(1))
                        second.start()
                        self.assertFalse(second_entered.wait(0.1),
                                         "a second RPC overtook an unpublished work snapshot")
                    finally:
                        release_first.set()
                        first.join(2)
                        if second.ident is not None:
                            second.join(2)
                self.assertFalse(first.is_alive())
                self.assertFalse(second.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(second_entered.is_set())
                if newer["available"]:
                    self.assertEqual(pool.current.job_id, "job-2")
                    self.assertEqual(set(pool.jobs), {"job-2"})
                else:
                    self.assertIsNone(pool.current)
                    self.assertFalse(pool.jobs)

    def test_expired_poll_deadline_does_not_fetch_work(self):
        rpc = MockRPC()
        pool = bridge.Pool(rpc, "miner.1", "secret", "0.000000000001")
        with patch.object(rpc, "call") as call:
            self.assertFalse(pool.poll_once(time.monotonic() - 1))
        call.assert_not_called()


class BusyRetentionTest(unittest.TestCase):
    def setUp(self):
        self.rpc = MockRPC()
        self.pool = bridge.Pool(self.rpc, "miner.1", "secret", "0.000000000001", max_clients=1, extranonce2_bytes=4)
        self.pool.poll_once()
        self.client = bridge.Client(None, authorized=True, extranonce1=bytes(24), job_ids={"job-1"})
        job = self.pool.current
        self.requests = []
        for number in range(100):
            nonce = f"{number:08x}"
            if int.from_bytes(hash2(job.header(bytes(28), nonce)), "little") <= job.network_target:
                self.requests.append({"id": number, "method": "mining.submit", "params": [
                    "miner.1", "job-1", "00000000", job.ntime, nonce]})
                if len(self.requests) == 2:
                    break
        self.assertEqual(len(self.requests), 2)

    def busy(self):
        return bridge.NodeRPCError(-32602, bridge.BUSY_SUBMISSION_MESSAGE)

    def submit(self, during_wait=lambda: None):
        self.rpc.solution_outcomes = [self.busy()]
        with patch.object(bridge.time, "sleep", side_effect=lambda delay: during_wait()):
            return self.pool.handle(self.client, self.requests[0])

    def test_busy_reservation_blocks_duplicate_and_capacity_then_accepts_same_bytes(self):
        replies = []
        def check():
            replies.extend(self.pool.handle(self.client, request) for request in self.requests)
        result = self.submit(check)
        self.assertTrue(result["result"])
        self.assertEqual([reply["error"][1] for reply in replies],
                         ["duplicate share", "network submission capacity reached"])
        self.assertEqual(self.rpc.submissions[0], self.rpc.submissions[1])
        self.assertEqual(self.pool.network_pending, set())
        self.assertEqual(self.pool.handle(self.client, self.requests[0])["error"][1], "duplicate share")

    def test_parent_change_cancels_without_retry_or_resurrecting_old_reservation(self):
        result = self.submit(lambda: setattr(self.rpc, "work", work("job-2", parent_start=1)))
        self.assertEqual(result["error"][1], "stale job")
        self.assertEqual(len(self.rpc.submissions), 1)
        self.assertFalse(self.pool.network_pending)
        self.assertFalse(self.pool.network_pending_tokens)
        self.assertFalse(self.pool.network_success)

    def test_unavailable_work_cancels_without_retry(self):
        result = self.submit(lambda: setattr(self.rpc, "work", {"available": False}))
        self.assertEqual(result["error"][1], "stale job")
        self.assertEqual(len(self.rpc.submissions), 1)

    def test_original_expiry_cannot_be_extended_by_work_refresh(self):
        original_expiry = self.pool.current.expires_monotonic
        expired_clock = patch.object(bridge.time, "monotonic", return_value=original_expiry + 1)
        try:
            result = self.submit(expired_clock.start)
        finally:
            expired_clock.stop()
        self.assertEqual(result["error"][1], "stale job")
        self.assertEqual(len(self.rpc.submissions), 1)

    def test_cache_eviction_cancels_before_second_rpc(self):
        def evict():
            self.pool.jobs.clear()
            self.rpc.work = work("job-2", prehash_start=64)
        result = self.submit(evict)
        self.assertEqual(result["error"][1], "stale job")
        self.assertEqual(len(self.rpc.submissions), 1)

    def test_newer_same_parent_job_does_not_discard_original_solution(self):
        result = self.submit(lambda: setattr(self.rpc, "work", work("job-2", prehash_start=64)))
        self.assertTrue(result["result"])
        self.assertEqual(self.rpc.submissions[0], self.rpc.submissions[1])
        self.assertEqual(self.rpc.submissions[1]["job_id"], "job-1")

    def test_terminal_or_ambiguous_errors_are_not_automatically_retried(self):
        for error, reason in [(bridge.NodeRPCError(-32602, "stale ASIC job"), "stale ASIC job"),
                              (bridge.NodeRPCError(-32000, bridge.BUSY_SUBMISSION_MESSAGE), bridge.BUSY_SUBMISSION_MESSAGE),
                              (TimeoutError("unknown outcome"), "node RPC unavailable")]:
            with self.subTest(error=str(error)):
                self.rpc.solution_outcomes = [error]
                before = len(self.rpc.submissions)
                result = self.pool.handle(self.client, self.requests[0])
                self.assertFalse(result["result"])
                self.assertEqual(result["error"][1], reason)
                self.assertEqual(len(self.rpc.submissions), before + 1)

    def test_busy_then_terminal_error_preserves_reason(self):
        self.rpc.solution_outcomes = [self.busy(), bridge.NodeRPCError(-32602, "unknown or expired ASIC job")]
        with patch.object(bridge.time, "sleep"):
            result = self.pool.handle(self.client, self.requests[0])
        self.assertEqual(result["error"][1], "unknown or expired ASIC job")
        self.assertEqual(len(self.rpc.submissions), 2)


    def test_late_authoritative_success_does_not_repopulate_new_epoch(self):
        original_call = self.rpc.call
        def call(method, params=None):
            if method == "hegemon_submitPoolShare":
                self.rpc.work = {"available": False}
                self.pool.poll_once()
                return {"accepted": True}
            return original_call(method, params)
        with patch.object(self.rpc, "call", side_effect=call):
            result = self.pool.handle(self.client, self.requests[0])
        self.assertTrue(result["result"])
        self.assertFalse(self.pool.network_pending)
        self.assertFalse(self.pool.network_pending_tokens)
        self.assertFalse(self.pool.network_success)

    def test_expiry_during_busy_delay_does_not_start_work_refresh(self):
        expired_clock = patch.object(bridge.time, "monotonic", return_value=float("inf"))
        try:
            with patch.object(self.rpc, "call", wraps=self.rpc.call) as call:
                result = self.submit(expired_clock.start)
        finally:
            expired_clock.stop()
        self.assertEqual(result["error"][1], "stale job")
        self.assertEqual([entry.args[0] for entry in call.call_args_list],
                         ["hegemon_submitPoolShare"])

    def test_fixed_attempt_budget_does_not_claim_acceptance(self):
        self.rpc.solution_outcomes = [self.busy(), self.busy()]
        with patch.object(bridge, "MAX_BUSY_SUBMISSION_ATTEMPTS", 2), patch.object(bridge.time, "sleep"):
            result = self.pool.handle(self.client, self.requests[0])
        self.assertFalse(result["result"])
        self.assertIn("retry budget exhausted", result["error"][1])
        self.assertEqual(len(self.rpc.submissions), 2)


class FutureRetentionTest(unittest.TestCase):
    setUp = BusyRetentionTest.setUp

    def paused_work(self, retained=None, parent=None):
        original = self.pool.jobs["job-1"]
        return {"available": False, "reason": bridge.TEMPORARY_FUTURE_WORK_REASON,
                "reason_code": "future_timestamp",
                "parent_hash": "0x" + (parent or original.parent_hash),
                "retained_job_ids": ["job-1"] if retained is None else retained}

    def future(self):
        return bridge.NodeRPCError(-32602, bridge.FUTURE_SUBMISSION_MESSAGE)

    def test_future_busy_success_keeps_exact_payload_and_bounded_owner(self):
        self.rpc.solution_outcomes = [self.future(),
                                      bridge.NodeRPCError(-32602, bridge.BUSY_SUBMISSION_MESSAGE)]
        paused = self.paused_work()
        during = []
        def wait(_delay):
            self.rpc.work = paused
            during.append([self.pool.handle(self.client, request) for request in self.requests])
        with patch.object(bridge.time, "sleep", side_effect=wait):
            result = self.pool.handle(self.client, self.requests[0])
        self.assertTrue(result["result"])
        self.assertEqual(len(self.rpc.submissions), 3)
        self.assertTrue(all(payload == self.rpc.submissions[0] for payload in self.rpc.submissions))
        self.assertIsNone(self.pool.current)
        self.assertEqual(self.pool.paused_parent, paused["parent_hash"][2:])
        for replies in during:
            self.assertEqual([reply["error"][1] for reply in replies],
                             ["duplicate share", "network submission capacity reached"])
        self.assertFalse(self.pool.network_pending)

    def test_pause_unknown_job_or_new_parent_cancels_before_retry(self):
        for paused in [self.paused_work(retained=[]),
                       self.paused_work(retained=["unknown"]),
                       self.paused_work(parent="ff" * 32)]:
            with self.subTest(paused=paused):
                self.setUp()
                self.rpc.solution_outcomes = [self.future()]
                with patch.object(bridge.time, "sleep", side_effect=lambda delay: setattr(self.rpc, "work", paused)):
                    result = self.pool.handle(self.client, self.requests[0])
                self.assertEqual(result["error"][1], "stale job")
                self.assertEqual(len(self.rpc.submissions), 1)

    def test_same_id_refresh_and_pause_preserve_original_monotonic_expiry(self):
        original = self.pool.current
        with patch.object(bridge.time, "time", return_value=time.time() - 3_600):
            self.rpc.work = work()
            self.rpc.work["expires_in"] = 120
            self.pool.poll_once()
        self.assertLessEqual(self.pool.current.expires_monotonic, original.expires_monotonic)
        self.rpc.work = self.paused_work()
        self.pool.poll_once()
        self.pool.poll_once()
        self.assertEqual(self.pool.jobs["job-1"].expires_monotonic, original.expires_monotonic)
        with patch.object(bridge.time, "time", return_value=original.expires_at - 10_000), \
                patch.object(bridge.time, "monotonic", return_value=original.expires_monotonic + 1):
            self.pool.poll_once()
        self.assertFalse(self.pool.jobs)
        self.assertIsNone(self.pool.paused_parent)

    def test_clock_rollback_before_submission_cannot_extend_original_expiry(self):
        original = self.pool.current
        with patch.object(bridge.time, "time", return_value=original.expires_at - 10_000), \
                patch.object(bridge.time, "monotonic", return_value=original.expires_monotonic + 1):
            result = self.pool.handle(self.client, self.requests[0])
        self.assertEqual(result["error"][1], "stale job")
        self.assertFalse(self.rpc.submissions)

    def test_resume_same_parent_preserves_epoch_and_cancels_on_real_withdrawal(self):
        epoch = self.pool.work_epoch
        original = self.pool.current
        self.rpc.work = self.paused_work()
        self.pool.poll_once()
        self.assertIsNone(self.pool.current)
        self.assertEqual(self.pool.work_epoch, epoch)
        self.rpc.work = work()
        self.pool.poll_once()
        self.assertEqual(self.pool.current.job_id, original.job_id)
        self.assertEqual(self.pool.work_epoch, epoch)
        self.assertLessEqual(self.pool.current.expires_monotonic, original.expires_monotonic)
        self.rpc.work = {"available": False}
        self.pool.poll_once()
        self.assertFalse(self.pool.jobs)
        self.assertGreater(self.pool.work_epoch, epoch)



class VersionRollingTCPTest(unittest.TestCase):
    """A real miner socket exercises negotiated versions and the default split."""

    send = StratumTCPTest.send
    read = StratumTCPTest.read
    authorize = StratumTCPTest.authorize
    tearDown = StratumTCPTest.tearDown

    def setUp(self):
        self.rpc = MockRPC()
        self.rpc.work = work(version_mask="1fffffe0")
        self.pool = bridge.Pool(self.rpc, "miner.1", "secret", "0.000000000001")
        self.pool.poll_once()
        self.server = bridge._Server(("127.0.0.1", 0), self.pool)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.sock = socket.create_connection(self.server.server_address, timeout=2)
        self.sock.settimeout(2)
        self.reader = self.sock.makefile("rb")

    def configure(self, mask="ffffffff", minimum=0):
        self.send(1, "mining.configure", [["version-rolling"], {
            "version-rolling.mask": mask, "version-rolling.min-bit-count": minimum}])
        return self.read()

    def subscribe(self):
        self.send(2, "mining.subscribe", [])
        response = self.read()
        self.assertEqual(response["result"][2], 8)
        self.assertEqual(len(bytes.fromhex(response["result"][1])), 20)
        return response["result"][1]

    def solved_params(self, ex1, notify, bits=None):
        ex2 = "0102030405060708"
        version = int(notify[5], 16) if bits is None else 0x20000000 | int(bits, 16)
        parent = bytes.fromhex(self.rpc.work["parent_hash"][2:])[::-1]
        root = hash2(bytes.fromhex(notify[2] + ex1 + ex2 + notify[3]))
        for candidate in range(100):
            header = (version.to_bytes(4, "little") + parent + root
                      + int(notify[7], 16).to_bytes(4, "little")
                      + int(notify[6], 16).to_bytes(4, "little")
                      + candidate.to_bytes(4, "little"))
            if int.from_bytes(hash2(header), "little") <= self.pool.current.network_target:
                params = ["miner.1", notify[0], ex2, notify[7], f"{candidate:08x}"]
                return params + ([bits] if bits is not None else []), header
        self.fail("expected easy compact-target solution")

    def test_intersection_below_minimum_keeps_connection_and_largest_mask(self):
        response = self.configure("e0002020", minimum=64)
        self.assertEqual(response["result"], {
            "version-rolling": True, "version-rolling.mask": "00002020"})
        self.subscribe()
        self.authorize()

    def test_default_mask_and_rolled_solution_forward_exact_header_version(self):
        self.send(1, "mining.configure", [["version-rolling"], {
            "version-rolling.min-bit-count": 2}])
        self.assertEqual(self.read()["result"]["version-rolling.mask"], "1fffffe0")
        ex1 = self.subscribe()
        notify = self.authorize()
        params, expected_header = self.solved_params(ex1, notify, "01000020")
        self.assertEqual(expected_header[:4], bytes.fromhex("20000021"))
        self.assertEqual(expected_header,
                         self.pool.current.header(bytes.fromhex(ex1 + params[2]), params[4], "21000020"))
        self.send(4, "mining.submit", params)
        self.assertTrue(self.read()["result"])
        self.assertEqual(self.rpc.submissions[0]["mining_version"], "21000020")
        self.assertEqual(len(bytes.fromhex(self.rpc.submissions[0]["extranonce"])), 28)
        self.send(5, "mining.submit", params)
        self.assertEqual(self.read()["error"][1], "duplicate share")

    def test_fixed_version_client_retains_five_field_submit_on_active_profile(self):
        ex1 = self.subscribe()
        notify = self.authorize()
        params, expected_header = self.solved_params(ex1, notify)
        self.assertEqual(expected_header[:4], bytes.fromhex("00000020"))
        self.send(4, "mining.submit", params)
        self.assertTrue(self.read()["result"])
        self.assertEqual(self.rpc.submissions[0]["mining_version"], "20000000")
        self.send(5, "mining.submit", params + ["00000020"])
        self.assertEqual(self.read()["error"][1], "invalid submit parameters")

    def test_negotiated_client_rejects_missing_bits_outside_mask_and_wrong_time(self):
        self.configure("00002020", 2)
        ex1 = self.subscribe()
        notify = self.authorize()
        params, _ = self.solved_params(ex1, notify, "00000020")
        for rid, submitted, reason in (
                (4, params[:-1], "invalid submit parameters"),
                (5, params[:-1] + ["20000000"], "version bits exceed negotiated mask"),
                (6, params[:-1] + ["00000001"], "version bits exceed negotiated mask"),
                (7, params[:3] + ["69000001"] + params[4:], "ntime rolling is disabled")):
            self.send(rid, "mining.submit", submitted)
            self.assertEqual(self.read()["error"][1], reason)
        self.assertEqual(self.rpc.submissions, [])

    def test_activation_and_reorg_notify_new_mask_before_new_job(self):
        self.rpc.work = work("pre-activation", version_mask="00000000")
        self.pool.poll_once()
        self.assertEqual(self.configure("00002020", 2)["result"]["version-rolling.mask"], "00000000")
        self.subscribe()
        self.authorize()
        for jid, parent, mask in (("activation", 1, "1fffffe0"), ("reorg-before", 2, "00000000")):
            self.rpc.work = work(jid, parent_start=parent, version_mask=mask)
            self.pool.poll_once()
            event = self.read()
            self.assertEqual(event["method"], "mining.set_version_mask")
            self.assertEqual(event["params"], ["00002020" if mask != "00000000" else mask])
            self.assertEqual(self.read()["method"], "mining.set_difficulty")
            notify = self.read()
            self.assertEqual(notify["method"], "mining.notify")
            self.assertEqual(notify["params"][0], jid)
        self.send(8, "mining.submit", ["miner.1", "reorg-before", "00" * 8,
                                       "69000000", "00000000", "00000020"])
        self.assertEqual(self.read()["error"][1], "version bits exceed negotiated mask")

    def test_duplicate_identity_distinguishes_version(self):
        self.configure("00000060", 2)
        ex1 = self.subscribe()
        notify = self.authorize()
        # A fixed digest makes two different valid versions share all other
        # coordinates; each has a separate bounded reservation and replay key.
        with patch.object(bridge, "sha256d", return_value=bytes(32)):
            for rid, bits in ((4, "00000020"), (5, "00000040")):
                self.send(rid, "mining.submit", ["miner.1", notify[0], "00" * 8,
                                                notify[7], "00000000", bits])
                self.assertTrue(self.read()["result"])
        self.assertEqual([row["mining_version"] for row in self.rpc.submissions],
                         ["20000020", "20000040"])

    def test_malformed_configuration_does_not_negotiate(self):
        for options in ({"version-rolling.mask": "bad", "version-rolling.min-bit-count": 0},
                        {"version-rolling.min-bit-count": True}, {},
                        {"version-rolling.min-bit-count": -1}):
            self.send(1, "mining.configure", [["version-rolling"], options])
            self.assertIsInstance(self.read()["result"]["version-rolling"], str)
        ex1 = self.subscribe()
        notify = self.authorize()
        params, _ = self.solved_params(ex1, notify)
        self.send(2, "mining.submit", params)
        self.assertTrue(self.read()["result"])

    def test_reconfiguration_response_stays_ordered_with_activation_notification(self):
        self.rpc.work = work("pre-activation", version_mask="00000000")
        self.pool.poll_once()
        self.configure()
        self.subscribe()
        self.authorize()
        client = next(iter(self.pool.clients))
        original_event = client.event
        notification_ready = threading.Event()
        continue_notification = threading.Event()

        def paused_event(method, params):
            if method == "mining.set_version_mask":
                notification_ready.set()
                self.assertTrue(continue_notification.wait(2))
            original_event(method, params)

        self.rpc.work = work("activation", parent_start=1, version_mask="1fffffe0")
        with patch.object(client, "event", side_effect=paused_event):
            poller = threading.Thread(target=self.pool.poll_once)
            poller.start()
            try:
                self.assertTrue(notification_ready.wait(2))
                self.send(10, "mining.configure", [["version-rolling"], {
                    "version-rolling.mask": "00000020", "version-rolling.min-bit-count": 1}])
                self.sock.settimeout(0.05)
                with self.assertRaises(TimeoutError):
                    self.sock.recv(1, socket.MSG_PEEK)
            finally:
                self.sock.settimeout(2)
                continue_notification.set()
                poller.join(timeout=2)
            self.assertFalse(poller.is_alive())
        self.assertEqual(self.read()["params"], ["1fffffe0"])
        self.assertEqual(self.read()["method"], "mining.set_difficulty")
        self.assertEqual(self.read()["method"], "mining.notify")
        response = self.read()
        self.assertEqual(response["id"], 10)
        self.assertEqual(response["result"]["version-rolling.mask"], "00000020")
        self.assertEqual(client.version_rolling_mask, 0x20)


class MiningProfileValidationTest(unittest.TestCase):
    def test_untrusted_rpc_mask_outside_reserved_bits_rejects(self):
        for mask in ("ffffffff", "20000000", "00000001", "ffff", None):
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                bridge.Job.from_rpc(work(version_mask=mask), time.time())

    def test_missing_rpc_mask_is_fixed_version_compatibility(self):
        value = work()
        del value["version_rolling_mask"]
        self.assertEqual(bridge.Job.from_rpc(value, time.time()).version_rolling_mask, 0)

    def test_extranonce_split_validation_and_total_width(self):
        for ex2, ex1 in ((8, 20), (4, 24), (12, 16)):
            pool = bridge.Pool(MockRPC(), "miner", "secret", "1", extranonce2_bytes=ex2)
            self.assertEqual((pool.extranonce1_bytes, pool.extranonce2_bytes), (ex1, ex2))
        for ex2 in (0, 28, -1, True, 3.5):
            with self.subTest(ex2=ex2), self.assertRaises(ValueError):
                bridge.Pool(MockRPC(), "miner", "secret", "1", extranonce2_bytes=ex2)
        with self.assertRaisesRegex(ValueError, "namespace"):
            bridge.Pool(MockRPC(), "miner", "secret", "1", max_clients=257, extranonce2_bytes=27)


if __name__ == "__main__":
    unittest.main()
