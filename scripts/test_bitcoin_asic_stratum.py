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
         parent_start=0, prehash_start=32):
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


class StratumTCPTest(unittest.TestCase):
    def setUp(self):
        self.rpc = MockRPC()
        self.pool = bridge.Pool(self.rpc, "miner.1", "secret", "0.000000000001")
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
        self.send(1, "mining.configure", [["version-rolling"], {"version-rolling.mask": "1fffe000"}])
        config = self.read()
        self.assertFalse(config["result"]["version-rolling"])
        self.assertEqual(config["result"]["version-rolling.mask"], "00000000")
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
            "ntime": notify[7],
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


if __name__ == "__main__":
    unittest.main()
