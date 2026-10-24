#!/usr/bin/env python3
"""Replay a pinned public donor ledger through a fresh production node.

The importer never receives donor files. This checks existing public proofs in
actual new binaries; it does not generate proofs, exercise custody or authorize
public deployment. State directories contain fresh ephemeral peer seeds: upload
only receipt.json and *.log, never the state directories.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = {"claim", "claim_lock", "fee_fund_1", "fee_fund_2", "refund", "refund_lock"}
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_BODY = 16 * 1024 * 1024
MAX_RPC = 3 * 1024 * 1024
RPC_DEADLINE = None


class ReplayError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ReplayError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path, cap=1024 * 1024):
    require(Path(path).stat().st_size <= cap, "JSON input exceeds bound")
    raw = Path(path).read_bytes()
    require(len(raw) <= cap, "JSON input exceeds bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_fixture(manifest):
    require(manifest.get("schema") == "hegemon.public-qualification-chain-fixture.v1", "fixture schema mismatch")
    require(manifest.get("contains_wallets_or_peer_seeds") is False, "fixture must contain public ledger only")
    require(digest(manifest.get("chain_id")) and re.fullmatch(r"0x[0-9a-f]{64}", manifest.get("genesis_hash", "")), "fixture network identity malformed")
    require(digest(manifest.get("network_manifest_sha256")), "fixture network digest malformed")
    archive = manifest.get("archive", {})
    require(archive.get("path") == "native-chain.sled.tar.gz" and digest(archive.get("sha256")), "fixture archive identity malformed")
    require(type(archive.get("bytes")) is int and 0 < archive["bytes"] <= MAX_ARCHIVE, "fixture archive size invalid")
    files = manifest.get("files")
    require(isinstance(files, list) and 1 <= len(files) <= 128, "fixture file count invalid")
    names = []
    for row in files:
        require(isinstance(row, dict) and isinstance(row.get("path"), str), "fixture file row malformed")
        name = row["path"]
        require(re.fullmatch(r"native-chain\.sled/(?:db|conf|blobs/[0-9]+)", name), "fixture path is not public native ledger data")
        require(type(row.get("bytes")) is int and 0 <= row["bytes"] <= MAX_EXPANDED and digest(row.get("sha256")), "fixture file metadata invalid")
        names.append(name)
    require(len(set(names)) == len(names) and sum(row["bytes"] for row in files) <= MAX_EXPANDED, "duplicate or oversized fixture inventory")
    require({"native-chain.sled/db", "native-chain.sled/conf"} <= set(names), "fixture ledger metadata absent")
    bodies = manifest.get("canonical_bodies")
    require(isinstance(bodies, list) and len(bodies) == 163, "fixture must cover all 163 canonical blocks")
    for height, row in enumerate(bodies, 1):
        require(row.get("height") == height and type(row.get("height")) is int and digest(row.get("body_sha256")) and re.fullmatch(r"0x[0-9a-f]{64}", row.get("block_hash", "")), "canonical fixture range malformed")
    proofs = manifest.get("proof_cases")
    require(isinstance(proofs, dict) and set(proofs) == CASES and manifest.get("proof_count") == 6, "fixture must cover exactly six proof cases")
    for row in proofs.values():
        require(type(row.get("height")) is int and 1 <= row["height"] <= 163, "proof height invalid")
        body = bodies[row["height"] - 1]
        require(row.get("block_hash") == body["block_hash"] and row.get("canonical_body_sha256") == body["body_sha256"], "proof fixture canonical binding mismatch")
        require(digest(row.get("action_sha256")) and type(row.get("bytes")) is int and 0 < row["bytes"] <= MAX_BODY, "proof action metadata invalid")
        require(re.fullmatch(r"0x[0-9a-f]{96}", row.get("action_body_hash", "")), "proof body hash malformed")
    return {row["path"]: row for row in files}


def extract_fixture(manifest, archive, destination):
    """Extract only inventoried regular files into a newly created donor path."""
    expected = validate_fixture(manifest)
    require(archive.stat().st_size == manifest["archive"]["bytes"] and sha(archive) == manifest["archive"]["sha256"], "fixture archive digest/size mismatch")
    destination.mkdir(mode=0o700)  # refuses an existing directory, including symlinks
    seen = set()
    with tarfile.open(archive, mode="r:gz") as bundle:
        for index, member in enumerate(bundle):
            require(index < 256, "too many archive entries")
            name = member.name
            require("\\" not in name and not name.startswith("/") and all(part not in ("", ".", "..") for part in name.rstrip("/").split("/")), "unsafe archive path")
            if member.isdir():
                require(name.rstrip("/") in ("native-chain.sled", "native-chain.sled/blobs") and member.size == 0, "unexpected archive directory")
                continue
            require(member.isfile() and name in expected and name not in seen, "unlisted, duplicate or nonregular archive entry")
            row = expected[name]
            require(member.size == row["bytes"], "archive entry length mismatch")
            stream = bundle.extractfile(member)
            require(stream is not None, "archive file data unavailable")
            with stream:
                data = stream.read(row["bytes"] + 1)
            require(len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"], "archive entry digest mismatch")
            target = destination / name
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)
            seen.add(name)
    require(seen == set(expected), "fixture archive inventory incomplete")


class WindowsJob:
    """Account for all owned Windows descendants without external packages."""
    def __init__(self, process):
        from ctypes import wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        require(self.handle, "cannot create owned Windows job")
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close()
            raise ReplayError("cannot assign node to owned Windows job")

    def active(self):
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_longlong) for name in ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [(name, ctypes.c_uint32) for name in ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses")]
        value = Accounting()
        require(self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(value), ctypes.sizeof(value), None), "cannot inspect owned Windows job")
        return value.ActiveProcesses != 0

    def kill(self):
        require(self.kernel.TerminateJobObject(self.handle, 1), "cannot terminate owned Windows job")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class OwnedNode:
    def __init__(self, binary, manifest, state, log, p2p, rpc_port, seeds, name):
        self.log = log
        self.url = f"http://127.0.0.1:{rpc_port}"
        self.state = state
        self.name = name
        self.seeds = seeds
        self.job = None
        self.stopped = False
        env = {key: value for key, value in os.environ.items() if not key.startswith("HEGEMON_") and key not in ("PQ_IDENTITY_SEED", "PQ_IDENTITY_SEED_PATH")}
        env.update(HEGEMON_MINE="0", HEGEMON_MINER_ADDRESS="", HEGEMON_SEEDS=seeds, HEGEMON_BOOTSTRAP_AUTHORING="0", RAYON_NUM_THREADS="2")
        argv = [str(binary), "--network", "pre-mainnet", "--network-manifest", str(manifest), "--base-path", str(state), "--listen-addr", f"127.0.0.1:{p2p}", "--port", str(p2p), "--rpc-port", str(rpc_port), "--rpc-methods", "unsafe", "--name", name]
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        with log.open("xb") as output:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, env=env, **kwargs)
        if os.name == "nt":
            try:
                self.job = WindowsJob(self.process)
            except BaseException:
                self.process.kill()
                self.process.wait(timeout=10)
                raise

    def group_active(self):
        if self.job:
            return self.job.active()
        try:
            os.killpg(self.process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def stop(self):
        if self.stopped:
            return
        forced = False
        try:
            if self.process.poll() is None:
                self.process.send_signal(signal.CTRL_BREAK_EVENT) if os.name == "nt" else os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    forced = True
            if forced or self.group_active():
                forced = True
                self.job.kill() if self.job else os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=10)
            until = time.monotonic() + 5
            while self.group_active() and time.monotonic() < until:
                time.sleep(0.05)
            require(not self.group_active(), "owned node descendants survived cleanup")
            require(not forced and self.process.returncode == 0, "node did not shut down cleanly; forced cleanup is a failed check")
        finally:
            if self.job:
                self.job.close()
            self.stopped = self.process.poll() is not None


def rpc(url, method, params=()):
    # URL is built by OwnedNode from an integer, never supplied by a fixture.
    port = int(url.rsplit(":", 1)[1])
    remaining = 10 if RPC_DEADLINE is None else RPC_DEADLINE - time.monotonic()
    require(remaining > 0, "public replay exceeded total timeout")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=min(10, remaining))
    try:
        connection.request("POST", "/", json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}), {"Content-Type": "application/json"})
        response = connection.getresponse()
        require(response.status == 200, "RPC HTTP status failure")
        raw = response.read(MAX_RPC + 1)
        require(len(raw) <= MAX_RPC, "RPC response exceeds bound")
        result = json.loads(raw)
        require(not result.get("error") and "result" in result, "RPC method failed: " + method)
        return result["result"]
    finally:
        connection.close()


def compact(raw, position):
    require(position < len(raw), "truncated SCALE length")
    mode = raw[position] & 3
    width = (1, 2, 4)[mode] if mode < 3 else (raw[position] >> 2) + 5
    require(width <= 9 and position + width <= len(raw), "invalid SCALE length width")
    value = int.from_bytes(raw[position:position + width], "little") >> 2 if mode < 3 else int.from_bytes(raw[position + 1:position + width], "little")
    require(mode == 0 or value >= (64, 16384, 1 << 30)[mode - 1], "noncanonical SCALE length")
    return value, position + width


def actions(raw):
    count, position = compact(raw, 0)
    require(count <= 1024, "too many canonical actions")
    result = []
    for _ in range(count):
        size, position = compact(raw, position)
        require(size <= MAX_BODY and position + size <= len(raw), "truncated canonical action")
        result.append(raw[position:position + size])
        position += size
    require(position == len(raw), "canonical action body has trailing bytes")
    return result


def body(node, block_hash):
    first = rpc(node.url, "chain_getBlockActionsChunk", [block_hash, 0])
    require(isinstance(first, dict), "canonical body missing")
    meta = {key: first.get(key) for key in ("height", "parent_hash", "tx_count", "extrinsics_root", "action_body_hash", "action_body_len", "chunk_count")}
    require(type(meta["action_body_len"]) is int and 0 < meta["action_body_len"] <= MAX_BODY and type(meta["chunk_count"]) is int and 1 <= meta["chunk_count"] <= 256, "canonical body resource bounds invalid")
    data = bytearray()
    for index in range(meta["chunk_count"]):
        row = first if index == 0 else rpc(node.url, "chain_getBlockActionsChunk", [block_hash, index])
        require(row.get("schema") == "hegemon.native.action-body-chunk-v1" and row.get("block_hash") == block_hash and row.get("chunk_index") == index and all(row.get(key) == value for key, value in meta.items()), "canonical chunk binding mismatch")
        encoded = row.get("chunk")
        require(isinstance(encoded, str) and encoded.startswith("0x"), "malformed canonical chunk")
        chunk = bytes.fromhex(encoded[2:])
        require(len(chunk) == row.get("chunk_len") and len(data) + len(chunk) <= meta["action_body_len"], "canonical chunk length mismatch")
        data.extend(chunk)
    require(len(data) == meta["action_body_len"], "canonical body incomplete")
    return actions(data), meta, bytes(data)


def free_ports():
    sockets = [socket.socket() for _ in range(4)]
    try:
        for stream in sockets:
            stream.bind(("127.0.0.1", 0))
        return [stream.getsockname()[1] for stream in sockets]
    finally:
        for stream in sockets:
            stream.close()


def bind_artifact(path, node):
    manifest = read_json(path)
    require(manifest.get("schema_version") == 1, "artifact manifest schema mismatch")
    entries = [row for row in manifest.get("artifacts", []) if row.get("package") == "hegemon-node" and row.get("binary") == "hegemon-node"]
    require(len(entries) == 1, "artifact manifest must bind one node binary")
    row = entries[0]
    relative = Path(row.get("path", ""))
    require(not relative.is_absolute() and (ROOT / relative).resolve() == node, "node path differs from artifact manifest")
    require(row.get("sha256") == sha(node) and row.get("size") == node.stat().st_size, "node does not match artifact manifest")
    return manifest


def run(args, receipt, owned):
    global RPC_DEADLINE
    fixture = read_json(args.fixture_manifest)
    validate_fixture(fixture)
    require(sha(args.network_manifest) == fixture["network_manifest_sha256"], "network manifest does not match public fixture")
    artifact = bind_artifact(args.artifact_manifest, args.node_bin)
    receipt.update(node_sha256=sha(args.node_bin), artifact_manifest_sha256=sha(args.artifact_manifest), fixture_manifest_sha256=sha(args.fixture_manifest), network_manifest_sha256=sha(args.network_manifest), source_head=artifact.get("source_head"), fixture_archive_sha256=fixture["archive"]["sha256"], importer_fixture_copied=False)
    deadline = time.monotonic() + args.timeout_seconds
    RPC_DEADLINE = deadline
    def budget():
        require(time.monotonic() < deadline, "public replay exceeded total timeout")
        require(shutil.disk_usage(args.output).free >= args.min_free_gib * 1024 ** 3, "public replay disk reserve exhausted")
        for node in owned:
            require(node.log.stat().st_size <= 64 * 1024 * 1024, "node diagnostics exceed bound")
            if not node.stopped:
                require(node.process.poll() is None, "owned node exited during replay")
    def wait(fn, label, seconds=180):
        end = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            budget()
            try:
                value = fn()
                if value:
                    return value
            except (OSError, ValueError, http.client.HTTPException, ReplayError):
                pass
            time.sleep(0.2)
        raise ReplayError("no progress at " + label)
    donor_state = args.output / "donor-state"
    importer_state = args.output / "importer-state"
    budget()
    extract_fixture(fixture, args.fixture_manifest.parent / fixture["archive"]["path"], donor_state)
    require(not importer_state.exists(), "importer state must not exist before genesis start")
    importer_state.mkdir(mode=0o700)
    require(not list(importer_state.iterdir()), "importer state must begin empty")
    p2p_a, rpc_a, p2p_b, rpc_b = free_ports()
    def start(label, state, p2p, rpc_port, seeds):
        budget()
        node = OwnedNode(args.node_bin, args.network_manifest, state, args.output / (label + ".log"), p2p, rpc_port, seeds, "v011-replay-" + label)
        owned.append(node)
        cfg = wait(lambda: rpc(node.url, "hegemon_nodeConfig"), label + " startup")
        require(cfg.get("nodeName") == node.name and Path(cfg.get("basePath", "")).resolve() == state.resolve() and cfg.get("chainId") == "0x" + fixture["chain_id"] and cfg.get("networkProfile") == "pre-mainnet" and cfg.get("bootstrapNodes") == ([seeds] if seeds else []), "started node identity/config differs")
        require(rpc(node.url, "chain_getBlockHash", [0]) == fixture["genesis_hash"], "started node genesis differs")
        return node
    def height(node):
        return int(rpc(node.url, "chain_getHeader")["number"], 16)
    donor = start("donor", donor_state, p2p_a, rpc_a, "")
    require(height(donor) == 163, "donor fixture tip differs")
    importer = start("importer-genesis", importer_state, p2p_b, rpc_b, "")
    require(height(importer) == 0, "fresh isolated importer did not start at genesis")
    receipt["importer_started_at_genesis"] = True
    importer.stop()
    importer = start("importer-sync", importer_state, p2p_b, rpc_b, f"127.0.0.1:{p2p_a}")
    wait(lambda: height(importer) == 163, "actual fresh-node public proof import", args.timeout_seconds)
    require(rpc(importer.url, "system_health").get("peers", 0) >= 1, "importer did not connect to donor")
    def check(node):
        previous = fixture["genesis_hash"]
        found = {}
        for row in fixture["canonical_bodies"]:
            budget()
            require(rpc(node.url, "chain_getBlockHash", [row["height"]]) == row["block_hash"], "canonical block hash differs")
            header = rpc(node.url, "chain_getHeader", [row["block_hash"]])
            require(isinstance(header, dict) and int(header["number"], 16) == row["height"] and header.get("parentHash") == previous and header.get("chainId") == "0x" + fixture["chain_id"], "canonical header continuity differs")
            exact, meta, raw = body(node, row["block_hash"])
            require(meta["height"] == row["height"] and meta["parent_hash"] == previous and hashlib.sha256(raw).hexdigest() == row["body_sha256"], "canonical body differs")
            for case, proof in fixture["proof_cases"].items():
                if proof["height"] != row["height"]:
                    continue
                matches = [action for action in exact if hashlib.sha256(action).hexdigest() == proof["action_sha256"]]
                require(len(matches) == 1 and len(matches[0]) == proof["bytes"] and meta["action_body_hash"] == proof["action_body_hash"], "proof-bearing action differs")
                found[case] = {"height": row["height"], "action_sha256": proof["action_sha256"], "bytes": proof["bytes"]}
            previous = row["block_hash"]
        require(set(found) == CASES and height(node) == 163, "canonical proof-case coverage incomplete")
        return found
    check(donor)
    first = check(importer)
    importer.stop()
    importer = start("importer-restart", importer_state, p2p_b, rpc_b, "")
    require(height(importer) == 163 and check(importer) == first, "isolated importer restart lost canonical evidence")
    require(sha(args.node_bin) == receipt["node_sha256"] and sha(args.artifact_manifest) == receipt["artifact_manifest_sha256"] and sha(args.fixture_manifest) == receipt["fixture_manifest_sha256"] and sha(args.network_manifest) == receipt["network_manifest_sha256"], "replay inputs changed during validation")
    receipt.update(actual_proof_verification=True, canonical_blocks_verified=163, proof_cases_verified=6, proof_cases=first, restart_verified=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-bin", type=Path, required=True)
    parser.add_argument("--artifact-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence/state directory; must not already exist")
    parser.add_argument("--fixture-manifest", type=Path, default=ROOT / "release-evidence/v0.11-public-chain-fixture/manifest.json")
    parser.add_argument("--network-manifest", type=Path, default=ROOT / "config/testnet/0.11/network-manifest.json")
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--min-free-gib", type=int, default=4 if os.environ.get("GITHUB_ACTIONS") == "true" else 15)
    args = parser.parse_args(argv)
    require(1 <= args.timeout_seconds <= 1200 and args.min_free_gib >= 4, "invalid timeout/disk reserve")
    for name in ("node_bin", "artifact_manifest", "output", "fixture_manifest", "network_manifest"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(mode=0o700)
    receipt = {"schema": "hegemon.v011.public-chain-replay.v1", "status": "RUNNING", "actual_proof_verification": False, "processes_reaped": False, "scope": "Existing six public proofs independently imported by a fresh production node; no new proving, custody exercise or deployment authority."}
    owned = []
    old_handlers = {}
    def interrupt(number, _frame):
        raise ReplayError("public replay interrupted by signal " + str(number))
    for number in (signal.SIGINT, signal.SIGTERM):
        old_handlers[number] = signal.signal(number, interrupt)
    try:
        run(args, receipt, owned)
        receipt["status"] = "PASS"
    except (Exception, KeyboardInterrupt) as error:
        receipt.update(status="FAIL", error=str(error))
    finally:
        cleanup = []
        for node in reversed(owned):
            try:
                node.stop()
            except Exception as error:
                cleanup.append(str(error))
        receipt["processes_reaped"] = all(node.stopped for node in owned) and not cleanup
        if cleanup:
            receipt.update(status="FAIL", cleanup_errors=cleanup)
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
        receipt["owned_node_runs"] = len(owned)
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ReplayError, OSError, ValueError) as error:
        print("Public replay rejected: " + str(error), file=sys.stderr)
        sys.exit(1)
