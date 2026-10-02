#!/usr/bin/env python3
"""Disposable live acceptance for native Bitcoin80 pool work and sync."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.request import Request, urlopen


SCRIPT_DIR = Path(__file__).resolve().parent
ADAPTER = SCRIPT_DIR / "bitcoin_asic_stratum.py"


def isolated_node_env(seeds: str) -> dict[str, str]:
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("HEGEMON_") or key in {"PQ_IDENTITY_SEED", "PQ_IDENTITY_SEED_PATH"}:
            env.pop(key, None)
    env.update({"HEGEMON_MINE": "0", "HEGEMON_SEEDS": seeds,
                "HEGEMON_BOOTSTRAP_AUTHORING": "1", "HEGEMON_MAX_PEERS": "8"})
    return env


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def reserve_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def rpc(url: str, method: str, params: list[Any] | None = None, timeout: float = 5) -> Any:
    payload = {"jsonrpc": "2.0", "id": secrets.randbelow(1 << 30),
               "method": method, "params": [] if params is None else params}
    request = Request(url, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read())
    if not isinstance(result, dict) or result.get("error") is not None:
        raise RuntimeError(f"RPC {method} failed: {result!r}")
    return result.get("result")


def status(url: str) -> tuple[int, str]:
    value = rpc(url, "hegemon_consensusStatus")
    if not isinstance(value, dict):
        raise RuntimeError("hegemon_consensusStatus did not return an object")
    height, block_hash = value.get("height"), value.get("best_hash")
    if not isinstance(height, int) or not isinstance(block_hash, str):
        raise RuntimeError(f"invalid consensus status: {value!r}")
    return height, block_hash.removeprefix("0x").lower()


def wait_rpc(url: str, deadline: float) -> None:
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rpc(url, "system_health", timeout=1)
            return
        except Exception as exc:  # node startup errors are retained in its log
            last_error = exc
            time.sleep(0.25)
    raise TimeoutError(f"node RPC did not become ready: {last_error}")


def wait_status(url: str, expected_height: int, expected_hash: str,
                deadline: float) -> tuple[int, str]:
    last = (-1, "")
    while time.monotonic() < deadline:
        try:
            last = status(url)
            if last == (expected_height, expected_hash):
                return last
        except Exception:
            pass
        time.sleep(0.25)
    raise TimeoutError(f"expected node tip {(expected_height, expected_hash)}, got {last}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def launch_node(binary: Path, base: Path, rpc_port: int, p2p_port: int,
                name: str, seeds: str, log_path: Path) -> subprocess.Popen[bytes]:
    env = isolated_node_env(seeds)
    command = [str(binary), "--dev", "--base-path", str(base),
               "--rpc-methods", "unsafe", "--rpc-port", str(rpc_port),
               "--listen-addr", f"127.0.0.1:{p2p_port}", "--name", name]
    with log_path.open("ab", buffering=0) as log:
        return subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)


def stop_process_group(child: subprocess.Popen[bytes], timeout: float = 15) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)


class JsonLineClient:
    def __init__(self, host: str, port: int, deadline: float):
        self.sock = socket.create_connection((host, port), timeout=max(0.1, deadline - time.monotonic()))
        self.sock.settimeout(max(0.1, deadline - time.monotonic()))
        self.file = self.sock.makefile("rwb", buffering=0)
        self.next_id = 1

    def send(self, method: str, params: list[Any]) -> int:
        request_id = self.next_id
        self.next_id += 1
        line = json.dumps({"id": request_id, "method": method, "params": params},
                          separators=(",", ":")).encode() + b"\n"
        self.file.write(line)
        return request_id

    def read(self, deadline: float) -> dict[str, Any]:
        self.sock.settimeout(max(0.1, deadline - time.monotonic()))
        raw = self.file.readline(8193)
        if not raw or len(raw) > 8192 or not raw.endswith(b"\n"):
            raise RuntimeError("Stratum connection closed or sent an oversized line")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError(f"malformed Stratum message: {value!r}")
        return value

    def response(self, request_id: int, deadline: float) -> dict[str, Any]:
        while time.monotonic() < deadline:
            value = self.read(deadline)
            if value.get("id") == request_id:
                return value
        raise TimeoutError(f"Stratum response {request_id} not received")

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()


def reconstruct_header(notify: list[Any], extranonce1: bytes,
                       extranonce2: bytes, nonce_hex: str) -> bytes:
    if len(notify) != 9 or notify[4] != []:
        raise RuntimeError("expected Bitcoin80 mining.notify with an empty Merkle branch")
    _, prevhash, coinbase_prefix_hex, coinbase_suffix_hex, _, version, nbits, ntime, _ = notify
    prevhash_bytes = bytes.fromhex(prevhash)
    if len(prevhash_bytes) != 32:
        raise RuntimeError("mining.notify prevhash must be 32 bytes")
    # Independent inverse of Stratum's four-byte word reversal.
    parent_wire = b"".join(prevhash_bytes[i:i + 4] for i in range(28, -1, -4))
    coinbase = (bytes.fromhex(coinbase_prefix_hex) + extranonce1 + extranonce2
                + bytes.fromhex(coinbase_suffix_hex))
    merkle_root = sha256d(coinbase)
    header = (int(version, 16).to_bytes(4, "little") + parent_wire[::-1]
              + merkle_root + int(ntime, 16).to_bytes(4, "little")
              + int(nbits, 16).to_bytes(4, "little")
              + int(nonce_hex, 16).to_bytes(4, "little"))
    if len(header) != 80:
        raise RuntimeError(f"constructed header length is {len(header)}, expected 80")
    return header


def target_from_compact(nbits_hex: str) -> int:
    compact = int(nbits_hex, 16)
    exponent, mantissa = compact >> 24, compact & 0x00FFFFFF
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    if target <= 0 or target >= 1 << 256:
        raise RuntimeError("compact nbits yielded an invalid target")
    return target


def solve_header(notify: list[Any], extranonce1: bytes, extranonce2: bytes,
                 target: int, deadline: float) -> tuple[str, bytes, bytes]:
    # Search the full nonce range in bounded chunks so the deadline remains live.
    for nonce in range(1 << 32):
        if nonce % 2048 == 0 and time.monotonic() >= deadline:
            raise TimeoutError("timed out searching the Bitcoin80 network target")
        nonce_hex = f"{nonce:08x}"
        header = reconstruct_header(notify, extranonce1, extranonce2, nonce_hex)
        digest = sha256d(header)
        if int.from_bytes(digest, "little") <= target:
            return nonce_hex, header, digest
    raise RuntimeError("exhausted all 32-bit nonces without a network solution")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(node_bin: Path, timeout: int) -> dict[str, Any]:
    if not node_bin.is_file() or not os.access(node_bin, os.X_OK):
        raise ValueError(f"--node-bin must be an executable absolute path: {node_bin}")
    if not ADAPTER.is_file():
        raise FileNotFoundError(f"Stratum adapter must be alongside the harness: {ADAPTER}")
    if not node_bin.is_absolute():
        raise ValueError("--node-bin must be an absolute path")

    run_dir = Path(tempfile.mkdtemp(prefix="hegemon-bitcoin80-live-",
                                    dir=str(SCRIPT_DIR.parent)))
    base_a = Path(tempfile.mkdtemp(prefix="source-a-", dir=run_dir))
    base_b = Path(tempfile.mkdtemp(prefix="source-b-", dir=run_dir))
    rpc_a, rpc_b, p2p_a, p2p_b, stratum_port = reserve_ports(5)
    # Prove the two requested base directories are newly created and empty.
    if any(any(base.iterdir()) for base in (base_a, base_b)):
        raise RuntimeError("new node base path was unexpectedly nonempty")
    node_a: subprocess.Popen[bytes] | None = None
    node_b: subprocess.Popen[bytes] | None = None
    adapter: subprocess.Popen[bytes] | None = None
    client: JsonLineClient | None = None
    receipt: dict[str, Any] = {
        "status": "running", "run_dir": str(run_dir), "base_paths": [str(base_a), str(base_b)],
        "node_binary": str(node_bin), "node_binary_sha256": file_sha256(node_bin),
        "adapter_script": str(ADAPTER), "adapter_script_sha256": file_sha256(ADAPTER),
        "harness_script": str(Path(__file__).resolve()),
        "harness_script_sha256": file_sha256(Path(__file__).resolve()),
        "logs": {"source_a": str(run_dir / "source-a.log"),
                 "source_b": str(run_dir / "source-b.log"),
                 "adapter": str(run_dir / "adapter.log")},
        "rpc_ports": [rpc_a, rpc_b], "p2p_ports": [p2p_a, p2p_b],
        "stratum_port": stratum_port,
    }
    receipt_path = run_dir / "receipt.json"
    timeout_at = time.monotonic() + timeout
    try:
        node_a = launch_node(node_bin, base_a, rpc_a, p2p_a, "asic-live-a", "",
                             Path(receipt["logs"]["source_a"]))
        url_a, url_b = f"http://127.0.0.1:{rpc_a}", f"http://127.0.0.1:{rpc_b}"
        wait_rpc(url_a, min(timeout_at, time.monotonic() + 40))
        genesis = status(url_a)
        receipt["genesis_height"], receipt["genesis_hash"] = genesis

        node_b = launch_node(node_bin, base_b, rpc_b, p2p_b, "asic-live-b",
                             f"127.0.0.1:{p2p_a}", Path(receipt["logs"]["source_b"]))
        wait_rpc(url_b, min(timeout_at, time.monotonic() + 40))
        adapter_env = isolated_node_env("")
        adapter_env["HEGEMON_STRATUM_PASSWORD"] = secrets.token_urlsafe(24)
        adapter_log = Path(receipt["logs"]["adapter"]).open("ab", buffering=0)
        adapter = subprocess.Popen(
            [sys.executable, "-B", str(ADAPTER), "--rpc-url", url_a,
             "--bind", "127.0.0.1", "--port", str(stratum_port),
             "--worker", "miner.1", "--share-difficulty", "0.000000000001",
             "--poll-seconds", "0.2"], env=adapter_env, stdin=subprocess.DEVNULL,
            stdout=adapter_log, stderr=subprocess.STDOUT, start_new_session=True)
        # The log descriptor is owned by the child after spawn.
        adapter_log.close()

        connect_deadline = min(timeout_at, time.monotonic() + 20)
        while True:
            if adapter.poll() is not None:
                raise RuntimeError(f"Stratum adapter exited with {adapter.returncode}")
            try:
                client = JsonLineClient("127.0.0.1", stratum_port, connect_deadline)
                break
            except OSError:
                if time.monotonic() >= connect_deadline:
                    raise TimeoutError("Stratum adapter did not accept a TCP connection")
                time.sleep(0.1)

        sub_id = client.send("mining.subscribe", [])
        sub = client.response(sub_id, min(timeout_at, time.monotonic() + 10))
        if sub.get("result") is None or sub.get("error") is not None:
            raise RuntimeError(f"Stratum subscribe failed: {sub!r}")
        subscription = sub["result"]
        if not isinstance(subscription, list) or len(subscription) != 3:
            raise RuntimeError(f"invalid mining.subscribe result: {subscription!r}")
        extranonce1 = bytes.fromhex(subscription[1])
        extranonce2_size = subscription[2]
        if len(extranonce1) != 24 or extranonce2_size != 4:
            raise RuntimeError("adapter did not provide 24-byte extranonce1 and 4-byte extranonce2")
        ex2 = secrets.token_bytes(extranonce2_size)

        auth_id = client.send("mining.authorize", ["miner.1", adapter_env["HEGEMON_STRATUM_PASSWORD"]])
        auth = client.response(auth_id, min(timeout_at, time.monotonic() + 10))
        if auth.get("result") is not True or auth.get("error") is not None:
            raise RuntimeError(f"Stratum authorize failed: {auth!r}")

        notify: list[Any] | None = None
        notify_job: str | None = None
        share_difficulty = None
        while time.monotonic() < timeout_at:
            event = client.read(timeout_at)
            method, params = event.get("method"), event.get("params")
            if method == "mining.set_difficulty" and isinstance(params, list):
                share_difficulty = params[0]
            if method == "mining.notify" and isinstance(params, list):
                notify = params
                notify_job = params[0]
                break
        if notify is None or not isinstance(notify_job, str):
            raise TimeoutError("did not receive mining.notify")

        work = rpc(url_a, "hegemon_poolWork")
        if not isinstance(work, dict) or work.get("available") is not True:
            raise RuntimeError(f"native node has no available pool work: {work!r}")
        if work.get("job_id") != notify_job:
            raise RuntimeError("Stratum job id differs from native poolWork")
        target_hex = work.get("target")
        nbits = notify[6]
        target = target_from_compact(nbits)
        if not isinstance(target_hex, str) or int(target_hex.removeprefix("0x"), 16) != target:
            raise RuntimeError("native target does not match compact nbits from mining.notify")
        if work.get("ntime") != notify[7] or work.get("version") != notify[5] or work.get("nbits") != nbits:
            raise RuntimeError("Stratum notify fields differ from native poolWork")
        reference_header = work.get("header80")
        ref_header_bytes = bytes.fromhex(reference_header.removeprefix("0x"))
        zero_extranonce_header = reconstruct_header(notify, bytes(24), bytes(4), "00000000")
        if zero_extranonce_header != ref_header_bytes:
            raise RuntimeError("independent Stratum header reconstruction mismatches native header80")

        nonce, header, digest = solve_header(notify, extranonce1, ex2, target, timeout_at)
        parent_display = work["parent_hash"].removeprefix("0x").lower()
        # Independently invert Stratum's word ordering and compare with the node RPC parent.
        wire_prevhash = bytes.fromhex(notify[1])
        parent_from_stratum = b"".join(wire_prevhash[i:i + 4] for i in range(28, -1, -4)).hex()
        if parent_from_stratum != parent_display:
            raise RuntimeError("independent Stratum prevhash inverse mismatches poolWork parent_hash")
        if int.from_bytes(sha256d(header), "little") > target:
            raise AssertionError("independent header hash does not meet network target")

        mutated_ntime = f"{(int(notify[7], 16) + 1) & 0xffffffff:08x}"
        bad_time_id = client.send("mining.submit", ["miner.1", notify_job, ex2.hex(), mutated_ntime, nonce])
        bad_time = client.response(bad_time_id, min(timeout_at, time.monotonic() + 10))
        if bad_time.get("result") is not False:
            raise RuntimeError(f"adapter accepted mutated ntime: {bad_time!r}")
        submit_id = client.send("mining.submit", ["miner.1", notify_job, ex2.hex(), notify[7], nonce])
        submitted = client.response(submit_id, min(timeout_at, time.monotonic() + 20))
        if submitted.get("result") is not True or submitted.get("error") is not None:
            raise RuntimeError(f"adapter rejected independently solved network share: {submitted!r}")
        replay_id = client.send("mining.submit", ["miner.1", notify_job, ex2.hex(), notify[7], nonce])
        replay = client.response(replay_id, min(timeout_at, time.monotonic() + 10))
        if replay.get("result") is not False:
            raise RuntimeError(f"adapter accepted replayed share: {replay!r}")

        mined_deadline = min(timeout_at, time.monotonic() + 20)
        height_a, hash_a = genesis
        while time.monotonic() < mined_deadline:
            tip = status(url_a)
            if tip[0] > genesis[0]:
                height_a, hash_a = tip
                break
            time.sleep(0.1)
        if height_a <= genesis[0]:
            raise TimeoutError("source A did not advance after accepting the pool solution")
        if hash_a != digest[::-1].hex():
            raise RuntimeError(
                f"accepted block hash {hash_a} does not match solved Bitcoin80 hash {digest[::-1].hex()}"
            )

        sync_deadline = min(timeout_at, time.monotonic() + 40)
        height_b, hash_b = wait_status(url_b, height_a, hash_a, sync_deadline)
        peer_health = rpc(url_b, "system_health")
        receipt.update({
            "job_id": notify_job, "version": notify[5], "ntime": notify[7], "nbits": nbits,
            "target": f"{target:064x}", "extranonce1": extranonce1.hex(),
            "extranonce2": ex2.hex(), "nonce": nonce,
            "header80": header.hex(), "workhash": digest.hex(),
            "workhash_display": digest[::-1].hex(),
            "height_after_mine": height_a, "block_hash": hash_a,
            "block_hash_matches_workhash": True,
            "source_b_synced": {"height": height_b, "block_hash": hash_b},
            "source_b_peer_check": peer_health,
            "share_difficulty": share_difficulty,
            "mutated_ntime_rejected": True, "replay_rejected": True,
            "adapter_submission": submitted, "adapter_mutated_ntime_response": bad_time,
            "adapter_replay_response": replay,
        })

        client.close()
        client = None
        stop_process_group(adapter)
        adapter = None
        stop_process_group(node_a)
        node_a = None
        node_a = launch_node(node_bin, base_a, rpc_a, p2p_a, "asic-live-a-reopened", "",
                             Path(receipt["logs"]["source_a"]))
        wait_rpc(url_a, min(timeout_at, time.monotonic() + 40))
        reopened = wait_status(url_a, height_a, hash_a, min(timeout_at, time.monotonic() + 20))
        receipt["source_a_restart"] = {"height": reopened[0], "block_hash": reopened[1], "same_tip": True}
        receipt["status"] = "passed"
        return receipt
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if client is not None:
            client.close()
        for child in (adapter, node_b, node_a):
            if child is not None:
                stop_process_group(child)
        # The run directory, two disposable databases, logs, and receipt are retained.
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(f"receipt: {receipt_path}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-bin", required=True, type=Path,
                        help="absolute path to the native hegemon-node executable")
    parser.add_argument("--timeout", type=int, default=120,
                        help="whole-run deadline in seconds (default: 120)")
    args = parser.parse_args()
    if args.timeout < 10 or args.timeout > 1800:
        parser.error("--timeout must be between 10 and 1800 seconds")
    try:
        receipt = run(args.node_bin, args.timeout)
    except Exception as exc:
        print(f"bitcoin80 live acceptance failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
