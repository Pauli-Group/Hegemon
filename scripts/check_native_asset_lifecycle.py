#!/usr/bin/env python3
"""Prepare and, once integrated, run actual Development asset-node acceptance.

Preparation is read-only on runtime source and never starts a node or a prover.
Run artifacts may only be created below the dedicated native-lifecycle directory.
The pending native RPC/wallet contract is deliberately not simulated.
"""

import argparse
import fcntl
import hashlib
import http.client
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import subprocess
import sys
import termios
import time
import traceback
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = ROOT / ".agent/stablecoin-v1-20261016/native-lifecycle"
MAX_RPC_BYTES = 12 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 1024 * 1024
MAX_WALLETD_REQUEST_BYTES = 8 * 1024 * 1024
MAX_WALLETD_RESPONSE_BYTES = 8 * 1024 * 1024
GOLDILOCKS = 0xFFFFFFFF00000001
RELATION_ID = b"Hegemon.AssetSpend.BoundedPolicy.Credentials.CompFF01.v2"


class AcceptanceError(RuntimeError):
    pass


class RpcRejected(AcceptanceError):
    def __init__(self, method, error):
        super().__init__(f"{method} rejected: {error.get('code')}")
        self.method, self.error = method, error


class WalletRejected(AcceptanceError):
    def __init__(self, method, code):
        super().__init__(f"{method} rejected: {code}")
        self.method, self.code = method, code


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def failure_evidence(error, stage):
    """Public source locations only: no frame locals, source text or inputs."""
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename).resolve()
        frames.append({"file": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else path.name,
                       "line": frame.lineno, "function": frame.name})
    result = {"status": "failed", "failed_step": stage, "public_stage": stage,
            "error_type": type(error).__name__,
            "error": str(error) if isinstance(error, AcceptanceError) else "unexpected exception; see public source frames",
            "traceback_frames": frames}
    if hasattr(error, "public_error_sources"):
        result["public_error_sources"] = error.public_error_sources
    return result


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def file_record(path):
    path = Path(path).resolve()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}


def write_json(path, data):
    path = Path(path).resolve()
    require(path.is_relative_to(ARTIFACT_ROOT), "artifact path outside dedicated directory")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as target:
        json.dump(data, target, indent=2, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, path)


def rpc(url, method, params=None, timeout=15):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"),
            "only loopback HTTP RPC is allowed")
    require(not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "RPC URL must have no credentials, query or fragment")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
        connection.request("POST", parsed.path or "/", body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        require(response.status == 200, "RPC HTTP status was not200")
        raw = response.read(MAX_RPC_BYTES + 1)
    finally:
        connection.close()
    require(len(raw) <= MAX_RPC_BYTES, "RPC response exceeds bound")
    result = json.loads(raw)
    require(isinstance(result, dict) and result.get("jsonrpc") == "2.0" and result.get("id") == 1,
            "RPC response identity mismatch")
    if result.get("error") is not None:
        raise RpcRejected(method, result["error"])
    require("result" in result, "RPC result missing")
    return result["result"]


def canonical_compact(data, offset):
    require(offset < len(data), "truncated SCALE compact")
    first, mode = data[offset], data[offset] & 3
    if mode < 3:
        count = (1, 2, 4)[mode]
        require(offset + count <= len(data), "truncated SCALE compact")
        value = int.from_bytes(data[offset:offset + count], "little") >> 2
        require(mode == 0 or value >= (64, 16384)[mode - 1], "noncanonical SCALE compact")
    else:
        count = (first >> 2) + 5
        require(count <= 9 and offset + count <= len(data), "oversized SCALE compact")
        require(data[offset + count - 1] != 0, "noncanonical SCALE compact leading zero")
        value = int.from_bytes(data[offset + 1:offset + count], "little")
        require(value >= 1 << 30, "noncanonical SCALE compact large mode")
    return value, offset + count


def canonical_actions(body):
    count, offset = canonical_compact(body, 0)
    require(count <= 10000, "canonical action count exceeds bound")
    actions = []
    for _ in range(count):
        size, offset = canonical_compact(body, offset)
        require(size <= MAX_RPC_BYTES and offset + size <= len(body), "canonical action truncated/oversized")
        actions.append(body[offset:offset + size])
        offset += size
    require(offset == len(body), "canonical action body has trailing bytes")
    return actions


def canonical_body(url, block_hash):
    first = rpc(url, "chain_getBlockActionsChunk", [block_hash, 0])
    require(isinstance(first, dict) and first.get("schema") == "hegemon.native.action-body-chunk-v1",
            "canonical action chunk schema changed")
    keys = ("height", "parent_hash", "tx_count", "extrinsics_root", "action_body_hash",
            "action_body_len", "chunk_count")
    metadata = {key: first[key] for key in keys}
    require(0 < first["chunk_count"] <= 512 and first["action_body_len"] <= MAX_RPC_BYTES,
            "canonical action body bound exceeded")
    body = bytearray()
    for index in range(first["chunk_count"]):
        row = first if index == 0 else rpc(url, "chain_getBlockActionsChunk", [block_hash, index])
        require(row.get("schema") == first["schema"] and row.get("chunk_index") == index
                and row.get("block_hash", "").lower() == block_hash.lower(), "canonical chunk identity mismatch")
        require(all(row.get(key) == value for key, value in metadata.items()), "canonical chunk metadata changed")
        chunk = bytes.fromhex(row["chunk"].removeprefix("0x"))
        require(len(chunk) == row["chunk_len"] and len(body) + len(chunk) <= MAX_RPC_BYTES,
                "canonical chunk length mismatch")
        body += chunk
    require(len(body) == first["action_body_len"], "canonical action body incomplete")
    actions = canonical_actions(body)
    require(len(actions) == first["tx_count"], "canonical action count mismatch")
    return actions, metadata, bytes(body)


def pending_action_public_args(raw):
    """Exact current PendingActionWire public-args projection, not admission."""
    require(len(raw) >= 113 and len(raw) <= MAX_RPC_BYTES, "pending action length mismatch")
    offset = 104
    counts, vectors = [], []
    for width in (48, 48, 48, 4):
        count, offset = canonical_compact(raw, offset)
        require(count <= (len(raw) - offset) // width, "pending action vector truncated")
        counts.append(count)
        vectors.append([raw[index:index + width].hex() for index in range(offset, offset + count * width, width)])
        offset += count * width
    size, offset = canonical_compact(raw, offset)
    end = offset + size
    require(end + 9 == len(raw) and raw[end + 8] == 0, "pending action args/fee/None framing mismatch")
    return raw[offset:end], {"binding_circuit": int.from_bytes(raw[48:50], "little"),
                            "binding_crypto": int.from_bytes(raw[50:52], "little"),
                            "family_id": int.from_bytes(raw[52:54], "little"),
                            "action_id": int.from_bytes(raw[54:56], "little"),
                            "anchor": raw[56:104].hex(),
                            "outer_fee": int.from_bytes(raw[end:end + 8], "little"),
                            "vector_counts": counts, "vectors": vectors, "public_args_offset": offset}


def inspect_asset_carrier(raw, expected_source48=None):
    """Independent public-only candidate/native spend framing, not a verifier."""
    native = raw[:8] == b"HGANSP01"
    require(raw[:8] in (b"HGASLC02", b"HGANSP01") and len(raw) >= 74, "asset carrier magic/length mismatch")
    identity_length = int.from_bytes(raw[8:10], "little")
    require(identity_length == len(RELATION_ID) and raw[10:10 + identity_length] == RELATION_ID,
            "asset carrier relation mismatch")
    require(len(raw) >= 74 + identity_length, "asset carrier header truncated")
    cursor = 10 + identity_length
    source = raw[cursor:cursor + 48]
    require(len(source) == 48 and (expected_source48 is None or source == expected_source48),
            "asset carrier source mismatch")
    cursor += 48
    words = int.from_bytes(raw[cursor:cursor + 2], "little")
    outputs, reserved = raw[cursor + 2:cursor + 4]
    ciphertext_size = int.from_bytes(raw[cursor + 4:cursor + 8], "little")
    proof_size = int.from_bytes(raw[cursor + 8:cursor + 12], "little")
    total = int.from_bytes(raw[cursor + 12:cursor + 16], "little")
    cursor += 16
    require((words, outputs, reserved, ciphertext_size) == (134, 3, 0, 2608), "asset carrier schema mismatch")
    require(total == len(raw) and cursor + words * 8 + outputs * ciphertext_size + proof_size == total,
            "asset carrier declared length mismatch")
    public = [int.from_bytes(raw[index:index + 8], "little") for index in range(cursor, cursor + words * 8, 8)]
    require(all(word < GOLDILOCKS for word in public), "noncanonical asset public field")
    require(public[124] in (0, 1) and public[125] in (0, 1), "noncanonical policy/release mode")
    require(all(word < 1 << 32 for word in public[126:134]), "noncanonical release limb")
    require(public[125] == 1 or public[126:134] == [0] * 8, "inactive release is not zero")
    require(public[124] == 1 or public[125:134] == [0] * 9, "ordinary mode carries policy release")
    if native:
        upper = {(0, 4): 819493, (0, 8): 888445, (0, 16): 1026437,
                 (1, 4): 1981701, (1, 8): 2050701}.get((public[124], public[40]))
        require(upper is not None,
                "unsupported native asset policy/depth profile")
        require(proof_size <= min(upper, 2 * 1024**2), "native asset proof exceeds qualified source bound")
    proof_offset = cursor + words * 8 + outputs * ciphertext_size
    require(raw[proof_offset:proof_offset + 4] == b"SMZE" and proof_size >= 4, "asset proof framing mismatch")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "magic": raw[:8].decode(),
            "source48": source.hex(), "public_words": public, "public_offset": cursor,
            "proof_offset": proof_offset, "proof_bytes": proof_size,
            "proof_sha256": hashlib.sha256(raw[proof_offset:]).hexdigest(),
            "policy_mode": public[124], "secret_release": public[125],
            "released_secret_hex": b"".join(word.to_bytes(4, "little") for word in public[126:134]).hex(),
            "proof_verified_by_this_parser": False}


def inspect_admin_carrier(raw, expected_source48=None):
    """Check native administrator public framing; authorization stays with nodes."""
    relation = b"Hegemon.AssetPolicyAdmin.Controls.CompFF01.v2"
    require(raw[:8] == b"HGANAD01" and len(raw) >= 70 + len(relation), "native admin header mismatch")
    require(int.from_bytes(raw[8:10], "little") == len(relation) and raw[10:10 + len(relation)] == relation,
            "native admin relation mismatch")
    cursor = 10 + len(relation)
    source = raw[cursor:cursor + 48]
    require(expected_source48 is None or source == expected_source48, "native admin source mismatch")
    cursor += 48
    require(raw[cursor:cursor + 4] == (134).to_bytes(2, "little") + bytes(2), "native admin schema mismatch")
    proof_size = int.from_bytes(raw[cursor + 4:cursor + 8], "little")
    total = int.from_bytes(raw[cursor + 8:cursor + 12], "little")
    cursor += 12
    require(4 <= proof_size <= 158533 and total == len(raw) == cursor + 134 * 8 + proof_size,
            "native admin proof/action length mismatch")
    public = [int.from_bytes(raw[index:index + 8], "little") for index in range(cursor, cursor + 134 * 8, 8)]
    require(all(word < GOLDILOCKS for word in public), "noncanonical native admin public field")
    require(public[90:] == [0] * 44, "native admin reserved public fields are not zero")
    proof_offset = cursor + 134 * 8
    require(raw[proof_offset:proof_offset + 4] == b"SMZE", "native admin proof magic mismatch")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "magic": "HGANAD01",
            "source48": source.hex(), "public_words": public, "proof_bytes": proof_size,
            "proof_offset": proof_offset, "proof_sha256": hashlib.sha256(raw[proof_offset:]).hexdigest(),
            "proof_verified_by_this_parser": False}


def inspect_native_pending_action(raw, expected_source48=None):
    """Bind retained native action metadata to exact asset/admin carrier bytes.

    This is an independent public framing check. Nodes still authenticate the
    source, verify the proof and apply canonical note/registry/nullifier state.
    """
    body, outer = pending_action_public_args(raw)
    require((outer["binding_circuit"], outer["binding_crypto"], outer["family_id"]) == (13, 7, 1)
            and outer["anchor"] == "00" * 48 and outer["vector_counts"][:2] == [0, 0],
            "asset native outer binding or legacy fields mismatch")
    if outer["action_id"] == 16:
        inner = inspect_asset_carrier(body, expected_source48)
        require(inner["magic"] == "HGANSP01", "candidate asset carrier used on native route")
        public = inner["public_words"]
        hashes = [b"".join(word.to_bytes(4, "little") for word in public[start:start + 12]).hex()
                  for start in (88, 100, 112)]
        require(outer["outer_fee"] == public[52] and outer["vector_counts"] == [0, 0, 3, 3]
                and outer["vectors"][2] == hashes
                and outer["vectors"][3] == [(2608).to_bytes(4, "little").hex()] * 3,
                "asset native outer fee/ciphertexts mismatch")
    elif outer["action_id"] == 17:
        inner = inspect_admin_carrier(body, expected_source48)
        require(outer["outer_fee"] == 0 and outer["vector_counts"] == [0, 0, 0, 0],
                "asset admin native outer value/ciphertexts mismatch")
    else:
        raise AcceptanceError("unknown native asset action id")
    return {"pending_action_bytes": len(raw), "pending_action_sha256": hashlib.sha256(raw).hexdigest(),
            "action_id": raw[:48].hex(), "outer": outer, "carrier": inner,
            "proof_verified_by_this_parser": False}


def private_wallet(argv, prompts, environment, timeout, guard):
    """Run the actual existing wallet with hidden TTY prompts and bounded output."""
    master, slave = os.openpty()
    def child_session():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    process = subprocess.Popen(list(map(str, argv)), stdin=slave, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, preexec_fn=child_session,
                               env=environment, close_fds=True)
    streams = [process.stdout, process.stderr, master]
    output, diagnostic = bytearray(), bytearray()
    deadline, sent, cursor = time.monotonic() + timeout, 0, 0
    try:
        while streams:
            guard()
            require(time.monotonic() < deadline, "wallet command exceeded deadline")
            if sent < len(prompts):
                needle, secret = prompts[sent]
                found = diagnostic.lower().find(needle.lower(), cursor)
                if found >= 0 and not termios.tcgetattr(slave)[3] & termios.ECHO:
                    os.write(master, secret + b"\n")
                    cursor, sent = found + len(needle), sent + 1
            ready, _, _ = select.select(streams, [], [], 0.05)
            for stream in ready:
                try:
                    data = os.read(stream if isinstance(stream, int) else stream.fileno(), 65536)
                except OSError:
                    data = b""
                if not data:
                    streams.remove(stream)
                elif stream is process.stdout:
                    output += data
                else:
                    diagnostic += data
                require(len(output) + len(diagnostic) <= MAX_DIAGNOSTIC_BYTES, "wallet output exceeds bound")
            if process.poll() is not None and master in streams:
                streams.remove(master)
        code = process.wait(timeout=5)
        require(sent == len(prompts), "wallet hidden prompt contract changed")
        require(not any(secret in output or secret in diagnostic for _, secret in prompts if secret),
                "wallet echoed private prompt input")
        return code, bytes(output), bytes(diagnostic)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        process.stdout.close()
        process.stderr.close()
        os.close(master)
        os.close(slave)


def walletd_request(binary, store, passphrase, method, params, environment, timeout, guard, create=False):
    """Actual encrypted walletd stdio protocol; no secret-bearing request file.

    Parameters, passphrases, stderr and request bodies are never added to an
    acceptance receipt. The caller retains only explicitly public results.
    This helper neither starts nodes nor invents wallet keys/owned notes.
    """
    require(isinstance(passphrase, bytes) and passphrase and b"\n" not in passphrase
            and b"\r" not in passphrase, "wallet passphrase framing mismatch")
    require(isinstance(method, str) and method.startswith("asset."), "not an asset wallet method")
    request = json.dumps({"id": 101, "method": method, "params": params}, separators=(",", ":")).encode()
    require(len(request) <= MAX_WALLETD_REQUEST_BYTES, "asset wallet request exceeds harness bound")
    payload = passphrase + b"\n" + request + b"\n"
    process = subprocess.Popen([str(binary), "--store", str(store), "--mode", "create" if create else "open"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=environment, close_fds=True)
    output, diagnostic, sent = bytearray(), bytearray(), 0
    readers = [process.stdout, process.stderr]
    writer = process.stdin
    os.set_blocking(writer.fileno(), False)
    deadline = time.monotonic() + timeout
    try:
        while readers or writer is not None:
            guard()
            require(time.monotonic() < deadline, "asset wallet exceeded deadline")
            readable, writable, _ = select.select(readers, [writer] if writer is not None else [], [], 0.1)
            if writable:
                try:
                    count = os.write(writer.fileno(), payload[sent:sent + 65536])
                    sent += count
                except BrokenPipeError:
                    count = 0
                if sent == len(payload) or count == 0:
                    writer.close()
                    writer = None
            for stream in readable:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    readers.remove(stream)
                elif stream is process.stdout:
                    output += chunk
                else:
                    diagnostic += chunk
                require(len(output) <= MAX_WALLETD_RESPONSE_BYTES
                        and len(diagnostic) <= MAX_DIAGNOSTIC_BYTES, "asset wallet output exceeds bound")
        code = process.wait(timeout=5)
        require(sent == len(payload), "asset wallet closed its request input early")
        require(passphrase not in output and passphrase not in diagnostic, "asset wallet echoed passphrase")
        lines = output.splitlines()
        require(len(lines) == 1, "asset wallet response must contain exactly one JSON line")
        response = json.loads(lines[0])
        require(isinstance(response, dict) and response.get("id") == 101
                and isinstance(response.get("ok"), bool), "asset wallet response identity changed")
        if not response["ok"]:
            raise WalletRejected(method, response.get("error_code"))
        require(code == 0 and response.get("error") is None and response.get("error_code") is None
                and "result" in response, "asset wallet response/process outcome disagrees")
        return response["result"]
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if writer is not None:
            writer.close()
        process.stdout.close()
        process.stderr.close()


def asset_snapshot(url, expected_genesis, expected_chain, expected_manifest, asset_id=None):
    """Read the exact current public RPC contract, without granting authority.

    Nodes are deliberately stopped between acceptance steps, so context must
    remain identical across both read-only calls. Nodes perform policy-path,
    source/proof and canonical-state checks during actual action admission.
    """
    parameters = rpc(url, "hegemon_assetParameters")
    registry = rpc(url, "hegemon_assetRegistry", [] if asset_id is None else [asset_id])
    require(parameters.get("schema") == "hegemon.native.asset-parameters.v1"
            and parameters.get("development_only") is True
            and parameters.get("production_authorized") is False, "asset source RPC contract mismatch")
    require(registry.get("schema") == "hegemon.native.asset-registry.v1"
            and registry.get("context") == parameters.get("context"), "asset snapshot context changed")
    context, source = parameters["context"], parameters["source"]
    require(context.get("genesis_hash") == expected_genesis and context.get("chain_id") == expected_chain
            and context.get("manifest_digest") == expected_manifest, "asset snapshot network identity mismatch")
    for key in ("note_root", "registry_root"):
        require(isinstance(context.get(key), list) and len(context[key]) == 7
                and all(type(word) is int and 0 <= word < GOLDILOCKS for word in context[key]),
                "asset snapshot noncanonical digest")
    require(type(context.get("parent_height")) is int and context["parent_height"] >= 0,
            "asset snapshot parent height invalid")
    parent = context.get("reference_parent_hash")
    require(isinstance(parent, str) and re.fullmatch(r"[0-9a-f]{64}", parent) and int(parent, 16) != 0,
            "asset snapshot reference parent invalid")
    require(source.get("public_words") == 134 and source.get("admin_public_words") == 134
            and source.get("ciphertext_bytes") == 2608 and source.get("max_proof_bytes") == 2 * 1024**2
            and source.get("max_actions_per_block") == 1
            and source.get("allowed_profiles") == [[0, 4], [0, 8], [0, 16], [1, 4], [1, 8]]
            and source.get("spend_action_id") == 16 and source.get("admin_action_id") == 17,
            "asset source profile mismatch")
    rows = registry.get("rows")
    require(isinstance(rows, list) and len(rows) <= 16, "asset snapshot registry count invalid")
    ids = []
    for row in rows:
        identity, encoded = row.get("asset_id"), row.get("row")
        require(type(identity) is int and 0 < identity < 1 << 32
                and (asset_id is None or identity == asset_id), "asset snapshot row identity invalid")
        require(isinstance(encoded, str) and re.fullmatch(r"[0-9a-f]{1104}", encoded)
                and row.get("row_codec") == "hegemon.asset-policy-row.v1.u64le552"
                and int.from_bytes(bytes.fromhex(encoded[:16]), "little") == identity,
                "asset snapshot row codec mismatch")
        ids.append(identity)
    require(ids == sorted(set(ids)) and (asset_id is None or ids == [asset_id]),
            "asset snapshot rows unordered, duplicated or absent")
    return {"parameters": parameters, "registry": registry,
            "cryptographic_authority_checked_by_this_reader": False}


CHECKLIST = [
    ("source-network-identity", "Two independent Development nodes use one exact manifest/genesis/source identity, reciprocal loopback seeds, source-disabled production authority and easy real PoW. Retain binary hashes, launch arguments, manifest and node readbacks."),
    ("mined-native-fee-ingress", "Existing private-spend bootstrap creates disposable encrypted wallets. Mine to actual coinbase maturity; recover actual positive HGN note and its full seven-limb owner. Never insert a synthetic fee note or import an in-memory candidate snapshot."),
    ("authenticated-genesis-registry", "Asset configuration is bound to the exact Development genesis/rules identity. Both nodes expose the same authenticated row/root; no unsigned RPC setter creates or replaces registry authority."),
    ("authenticated-controls-admin", "A real current policy-admin-secret proof changes credentials/freeze/mint controls and consumes semantic admin identity. Issuer-only and old-admin proofs reject. Full config/version/counters remain equal."),
    ("mint-transfer-burn", "Real proofs consume actual canonical notes, relay unchanged on both nodes, mine unchanged, decrypt all three outputs and update exact supply/debt/cap/collateral/epoch counters. Transfer and holder burn remain available with mint disabled."),
    ("native-fee-global-conflict", "Before reservations, cold-copy a disposable wallet. Prepare a native ordinary spend and an asset action consuming the same mature HGN note. Include one and reject the other on both nodes, after restart, and after fresh sync. Reverse route ordering on a fresh note."),
    ("all-three-output-positions", "Bind three exact asset action ciphertexts/commitments to canonical V8 tree positions, including zero change. Spend recovered asset-route HGN change through the existing native ordinary wallet and native-created HGN change through the asset route."),
    ("freeze-wraps-every-route", "Authenticated freeze rejects mint/ordinary transfer/burn/bounded creation/both bounded spend branches, including zero asset change, without publishing any state. Prove an action before freeze and reject its unchanged bytes afterward."),
    ("bounded-height-release", "Create a holder-chosen bounded owner through shared evaluator. Reject disabled/early branches. Accept at exact current parent height; required release contains all32 preimage bytes in exported/pending/canonical action. An alternative branch shares the same consumed nullifier."),
    ("current-credentials", "All asset input/recipient/change credentials, even zero change, bind complete owner, asset/version/current root and expiry. Authenticated revocation causes old prepared bytes to reject, while a new valid credential permits a fresh proof."),
    ("registry-root-consensus", "Mutating public registry/root/credential/issuer/version fields, detached-parent state or wrong chain rejects before commit. Canonical state/header or exact consensus-bound checkpoint must bind the registry root; an RPC-only root comparison is insufficient."),
    ("atomic-failure-replay", "Malformed proof/ciphertext/type/noncanonical/trailing/repeated-nullifier/wrong fee inputs reject. Compare exact before/after roots, counts, counters, nullifier membership and admin history. Randomized admin proof copies cannot replay a semantic action; root cycles do not erase history."),
    ("two-node-exact-bytes", "For every accepted native/admin/asset action, compare canonical chunk metadata and full bodies on both nodes and require exactly one unchanged retained action. Preserve proof/public/ciphertext hashes and exact output indexes."),
    ("restart-and-fresh-sync", "Cleanly restart existing nodes, then stop B and start a fresh replacement with an empty owned DB, keeping at most two nodes live. Require exact common tip, canonical bodies, all roots/rows/counters/spent memberships/admin history, wallet recovery and replay rejection. Rebuild from actual blocks, never a copied in-memory snapshot."),
    ("real-higher-work-reorg", "From a closed-node cold prefix DB, mine a genuine isolated competing branch to greater cumulative work. Reconnect peers and require canonical rollback of registry/counters/notes/nullifiers/admin history followed by exact winning-branch replay. Resubmit only actions whose original context remains valid; otherwise require stale rejection and reprove."),
]


SOURCE_PATHS = [
    "scripts/check_native_asset_lifecycle.py", "scripts/release_private_spend_lifecycle.py",
    "scripts/release_private_spend_lifecycle_io.py", "scripts/test_bitcoin_asic_live.py",
    "node/src/native/network_profile.rs", "node/src/native/launch_v8_verifier.rs",
    "node/src/native/poseidon2_v8_state.rs", "node/src/native/node_impl.rs",
    "node/src/native/block_flow.rs", "node/src/native/mod.rs",
    "node/src/native/asset_state.rs",
    "node/src/native/asset_native.rs", "node/src/native/asset_rpc.rs",
    "walletd/src/main.rs", "walletd/src/asset.rs", "wallet/src/node_rpc.rs",
    "wallet/src/asset_spend_rpc.rs", "wallet/src/asset_spend_store.rs",
    "wallet/src/store.rs", "wallet/src/poseidon2_v8_sync.rs", "walletd/Cargo.toml", "wallet/Cargo.toml",
    "node/Cargo.toml", "node/src/native/native_proof_binding.rs", "node/src/native/admission.rs",
    "node/src/native/poseidon2_v8_pending.rs", "node/src/native/util.rs", "node/src/native/service.rs",
    "node/src/native/rpc.rs",
    "wallet/src/bin/private_spend.rs", "wallet/src/private_spend_rpc.rs",
    "wallet/src/private_spend_build.rs", "wallet/src/asset_spend_v1.rs",
    "circuits/transaction/src/asset_spend_v1/circuit.rs",
    "circuits/transaction/src/asset_spend_v1_state.rs",
    "circuits/transaction/src/asset_spend_v1_wire.rs",
    "circuits/transaction/src/asset_spend_v1_admission.rs",
    "circuits/transaction/src/asset_policy_admin_v1.rs", "circuits/transaction/src/asset_spend_v1.rs",
    "circuits/transaction/src/asset_spend_v1/types.rs", "circuits/transaction/src/asset_spend_v1/helpers.rs",
    "circuits/transaction/src/asset_spend_v1/proof.rs", "circuits/transaction/src/private_spend/circuit.rs",
    "circuits/transaction/src/smallwood_engine.rs", "circuits/transaction-core/src/asset_registry_v1.rs",
    "protocol/shielded-pool/src/private_spend_transport.rs",
    # Complete immutable-candidate relation include_bytes! closure: 84 entries,
    # 45 unique source paths across asset, administrator and native relations.
    "Cargo.lock",
    "circuits/hegemon-field/src/lib.rs",
    "circuits/transaction-core/src/bounded_policy.rs",
    "circuits/transaction-core/src/constants.rs",
    "circuits/transaction-core/src/hashing_pq.rs",
    "circuits/transaction-core/src/poseidon2.rs",
    "circuits/transaction-core/src/poseidon2_constants.rs",
    "circuits/transaction-core/src/poseidon2_width16.rs",
    "circuits/transaction-core/src/stablecoin_poseidon2_v8.rs",
    "circuits/transaction-core/src/types.rs",
    "circuits/transaction/src/error.rs",
    "circuits/transaction/src/full_shake448_statement.rs",
    "circuits/transaction/src/private_spend.rs",
    "circuits/transaction/src/private_spend/helpers.rs",
    "circuits/transaction/src/private_spend/proof.rs",
    "circuits/transaction/src/private_spend/types.rs",
    "circuits/transaction/src/smallwood_htlc.rs",
    "circuits/transaction/src/smallwood_htlc/circuit.rs",
    "circuits/transaction/src/smallwood_htlc/sha256.rs",
    "circuits/transaction/src/smallwood_hx512_transcript.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_hash_schedule.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_rng_refinement.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_types.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_zk_refinement.rs",
    "circuits/transaction/src/smallwood_semantics.rs",
    "circuits/transaction/src/smallwood_v6_envelope.rs",
    "circuits/transaction/src/smallwood_v6_transcript.rs",
    "crypto/hash384/src/lib.rs",
    "crypto/src/asset_note_encryption_v1.rs",
    "crypto/src/deterministic.rs",
    "crypto/src/ml_kem.rs",
    "crypto/src/private_note_encryption.rs",
    "crypto/src/private_note_payload.rs",
    "crypto/src/traits.rs",
    "protocol/versioning/src/launch_candidate_identity.rs",
]


def prepare():
    plan = {"schema": "hegemon.native-asset.actual-lifecycle-preparation.v1",
            "status": "PREPARED_NOT_EXECUTED", "production_authorized": False,
            "release_gate_closed": False, "node_processes_started": 0, "proofs_generated": 0,
            "source_root": str(ROOT), "sources": [file_record(ROOT / path) for path in SOURCE_PATHS],
            "resource_policy": {"minimum_remaining_usage_percent": 40, "minimum_free_disk_bytes": 10 * 1024**3,
                                "cargo_builders": 1, "maximum_live_owned_nodes": 2,
                                "worker_builds_or_proofs_permitted": False},
            "checks": [{"id": identity, "status": "not_run", "required_evidence": text} for identity, text in CHECKLIST],
            "existing_wallet_interface": {"binary": "private-spend", "development_flag": "--development-local-candidate",
                                          "commands": ["bootstrap-new", "bootstrap-address", "notes", "ordinary", "export", "submit", "attempts"]},
            "asset_wallet_interface": {"binary": "walletd", "passphrase_transport": "first stdin line",
                                       "request_transport": "one JSON stdin line, never a secret-bearing request file",
                                       "methods": ["asset.row", "asset.setup", "asset.address", "asset.credentials", "asset.policyOwner",
                                                   "asset.sync", "asset.prepare", "asset.submit", "asset.admin", "asset.adminPrepare",
                                                   "asset.adminSubmit", "asset.export", "asset.balances", "asset.notes", "asset.journal", "asset.abandon"],
                                       "sync_params": ["ws_url", "manifest", "expected_genesis"],
                                       "prepare_params": ["ws_url", "asset_id", "operation", "amount", "fee", "recipient",
                                                          "asset_change_index", "native_change_index", "credentials",
                                                          "issuer_secret", "policy", "input_position"],
                                       "admin_prepare_method": "asset.adminPrepare"},
            "existing_node_interface": {"development_flags": ["--dev", "--network", "development", "--development-candidate"],
                                        "rpc": ["hegemon_nodeConfig", "hegemon_privateSpendParameters", "hegemon_poolWork",
                                                "hegemon_submitPoolShare", "chain_getBlockHash", "chain_getHeader",
                                                "chain_getBlockActionsChunk", "hegemon_developmentPendingActionChunk",
                                                "hegemon_assetParameters", "hegemon_assetRegistry", "hegemon_submitAction"]},
            "native_asset_source_profiles": {"allowed_policy_mode_and_credential_depth": [[0, 4], [0, 8], [0, 16], [1, 4], [1, 8]],
                                              "inner_proof_cap_bytes": 2 * 1024**2,
                                              "bounded_depth16": "Excluded by native source profile; retained candidate proof 2187325 bytes exceeds the 2 MiB native cap."},
            "pending_native_contract": ["Coordinator confirmation that final runtime binaries are ready before actual execution"],
            "limitations": ["This plan and framing parser are not live acceptance or cryptographic proof verification.",
                            "Inherited backend query-bound/security, source-lowering/refinement, adaptive privacy/QROM, release capability and deployment obligations remain open.",
                            "Only actual independently started nodes, mined canonical actions and retained exact artifacts can satisfy these checks."]}
    destination = ARTIFACT_ROOT / "prepared-plan.json"
    write_json(destination, plan)
    return destination


def load_pool_helpers():
    path = ROOT / "scripts/test_bitcoin_asic_live.py"
    spec = importlib.util.spec_from_file_location("native_asset_pool_helpers", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class NativeLifecycle:
    def __init__(self, args):
        self.args, self.pool = args, load_pool_helpers()
        self.base = ARTIFACT_ROOT / args.run_name
        require(not self.base.exists(), "run directory already exists; use a fresh --run-name")
        self.base.mkdir(mode=0o700, parents=True)
        self.deadline = time.monotonic() + args.timeout
        self.children, self.nodes, self.proofs = [], {}, []
        self.phrases = [secrets.token_urlsafe(48).encode() for _ in range(2)]
        self.stores = [self.base / f"actor-{i}.wallet" for i in range(2)]
        self.issuer = [secrets.randbelow(GOLDILOCKS - 1) + 1 for _ in range(7)]
        self.admin_secret = [secrets.randbelow(GOLDILOCKS - 1) + 1 for _ in range(7)]
        self.env = self.pool.isolated_node_env("")
        self.env.update(RAYON_NUM_THREADS="2", RUST_LOG="warn", RUST_BACKTRACE="0")
        self.ports = self.pool.reserve_ports(4)
        self.urls = [f"http://127.0.0.1:{p}" for p in self.ports[:2]]
        self.current = "initialization"
        self.receipt = {"schema": "hegemon.native-asset.actual-lifecycle.v1", "status": "running",
                        "production_authorized": False, "release_gate_closed": False,
                        "deployment_verified": False, "state_directory": str(self.base),
                        "sources": [file_record(ROOT / p) for p in SOURCE_PATHS],
                        "binaries": {k: file_record(getattr(args, k)) for k in ("node", "walletd", "private_spend")},
                        "checks": [], "proofs": self.proofs,
                        "requested_gates": [identity for identity, _ in CHECKLIST],
                        "resource_policy": {"maximum_owned_nodes": 2, "minimum_disk_bytes": 10 * 1024**3,
                                            "minimum_remaining_usage_percent": 40,
                                            "usage_confirmed_by_coordinator": args.coordinator_usage_remaining},
                        "limitations": ["Finite actual-node acceptance, not a cryptographic security or production-release theorem.",
                                        "Registry snapshots are canonical transactionally retained rows; no claim they are header/V8-checkpoint roots.",
                                        "Inherited q58/backend, lowering/refinement and adaptive privacy/QROM obligations remain open."]}
        self.save()

    def guard(self):
        require(time.monotonic() < self.deadline, "whole-run deadline exceeded")
        require(shutil.disk_usage(self.base).free > 10 * 1024**3, "10 GiB disk reserve reached")
        require(sum(child.poll() is None for child in self.nodes.values()) <= 2, "owned node concurrency exceeded")
        require(all(path.stat().st_size < 32 * 1024**2 for path in self.base.glob("*.log")), "node log bound exceeded")

    def save(self):
        write_json(self.base / "receipt.json", self.receipt)

    def mark(self, identity, **evidence):
        self.receipt["checks"].append({"id": identity, "status": "passed", **evidence})
        self.save()
        print(json.dumps({"check": identity, "status": "passed"}), flush=True)

    def wait(self, condition, label, timeout=180):
        end = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < end:
            self.guard()
            try:
                value = condition()
                if value:
                    return value
            except (OSError, ValueError, AcceptanceError):
                pass
            time.sleep(0.2)
        raise AcceptanceError("no progress: " + label)

    def w(self, actor, method, params=None, create=False, store=None):
        self.current = method
        return walletd_request(self.args.walletd, store or self.stores[actor], self.phrases[actor], method,
                               params or {}, self.env, self.args.proof_timeout, self.guard, create)

    def sync(self, actor=0, url=None, store=None):
        return self.w(actor, "asset.sync", {"ws_url": url or self.urls[0],
                      "manifest": str(self.base / "manifest.json"), "expected_genesis": self.genesis}, store=store)

    def snap(self, url=None):
        result = asset_snapshot(url or self.urls[0], self.genesis, self.chain, self.manifest_digest)
        registry = result["registry"]
        require(isinstance(registry.get("state_digest"), str)
                and re.fullmatch(r"[0-9a-f]{96}", registry["state_digest"])
                and type(registry.get("consumed_admin_actions")) is int,
                "durable asset digest/admin count readback absent")
        return {"asset": result, "notes": rpc(url or self.urls[0], "hegemon_walletNotes")}

    def row(self):
        return self.snap()["asset"]["registry"]["rows"][0]

    def node(self, label, directory, index, seeds=""):
        self.guard()
        require(sum(child.poll() is None for child in self.nodes.values()) < 2, "starting a third owned node")
        directory.mkdir(mode=0o700, exist_ok=True)
        env = dict(self.env, HEGEMON_SEEDS=seeds, HEGEMON_MINER_ADDRESS=self.addresses[0]["address"])
        command = [str(self.args.node), "--dev", "--network", "development", "--network-manifest",
                   str(self.base / "manifest.json"), "--development-candidate", "--base-path", str(directory),
                   "--rpc-port", str(self.ports[index]), "--rpc-methods", "unsafe", "--listen-addr",
                   f"127.0.0.1:{self.ports[index + 2]}", "--name", label]
        with (self.base / f"{label}.log").open("xb", buffering=0) as log:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                     env=env, start_new_session=True)
        self.children.append(child)
        self.nodes[label] = child
        self.wait(lambda: rpc(self.urls[index], "system_health"), "node startup " + label)
        config = rpc(self.urls[index], "hegemon_nodeConfig")
        require(config["networkProfile"] == "development" and config["networkManifest"] == self.manifest,
                "node exact Development manifest mismatch")
        genesis = rpc(self.urls[index], "chain_getBlockHash", [0]).removeprefix("0x")
        if hasattr(self, "genesis"):
            require(genesis == self.genesis, "node genesis changed")
        else:
            self.genesis, self.chain = genesis, config["chainId"].removeprefix("0x")
            self.manifest_digest = config["networkManifestDigest"].removeprefix("0x")
            self.receipt.update(genesis=self.genesis, chain_id=self.chain, manifest_digest=self.manifest_digest)
        require(rpc(self.urls[index], "hegemon_privateSpendParameters")["production_authorized"] is False,
                "Development private route advertised production authority")
        self.receipt.setdefault("node_launches", []).append({"label": label, "argv": command, "seeds": seeds})
        self.save()
        return child

    def stop(self, child):
        self.pool.stop_process_group(child)
        require(child.returncode == 0, "owned node exited nonzero")

    def status(self, url=None):
        result = rpc(url or self.urls[0], "hegemon_consensusStatus")
        return result["height"], result["best_hash"].removeprefix("0x")

    def tip_work(self, url=None, expected_tip=None):
        tip = self.status(url)
        if expected_tip is not None:
            require(tip == expected_tip, "canonical tip changed before cumulative-work readback")
        header = rpc(url or self.urls[0], "chain_getHeader", ["0x" + tip[1]])
        require(isinstance(header, dict), "canonical cumulative-work header is not an object")
        value = header.get("cumulativeWork")
        require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{96}", value),
                "canonical header cumulative Work48 is not exact big-endian hex")
        require(header.get("number") == hex(tip[0]), "cumulative-work header height mismatch")
        # RPC emits raw Work48 bytes; consensus_light_client::compare_work
        # compares these 48-byte big-endian arrays lexicographically.
        return bytes.fromhex(value[2:])

    def converge(self):
        expected = self.status()
        started = last_progress = time.monotonic()
        end = min(self.deadline, started + 2400)
        highest = -1
        progress = []
        observation = {"expected_tip": expected, "maximum_seconds": 2400,
                       "maximum_seconds_without_forward_height": 180,
                       "forward_heights": progress, "status": "running"}
        self.receipt.setdefault("canonical_convergence", []).append(observation)
        while time.monotonic() < end:
            self.guard()
            try:
                current = self.status(self.urls[1])
            except (OSError, ValueError, AcceptanceError):
                current = None
            now = time.monotonic()
            self.guard()
            require(now < end, "two-node canonical convergence exceeded bounded2400-second stage")
            require(now - last_progress < 180, "canonical sync made no forward height progress for180 seconds")
            if current == expected:
                require(self.status() == expected, "source canonical tip changed during convergence")
                require(self.snap() == self.snap(self.urls[1]), "two-node roots/rows/notes/admin state differ")
                self.guard()
                finished = time.monotonic()
                require(finished < end, "two-node canonical convergence exceeded bounded2400-second stage")
                observation.update(status="passed", elapsed_seconds=round(finished - started, 3))
                self.save()
                return expected
            if current is not None and current[0] > highest:
                highest, last_progress = current[0], now
                progress.append({"height": current[0], "hash": current[1],
                                 "elapsed_seconds": round(now - started, 3)})
                self.save()
            time.sleep(0.5)
        raise AcceptanceError("two-node canonical convergence exceeded bounded2400-second stage")

    def mine(self, height, url=None):
        self.current = "mine-to-" + str(height)
        url = url or self.urls[0]
        while self.status(url)[0] < height:
            self.guard()
            job = rpc(url, "hegemon_poolWork")
            require(job.get("available") is True, "real Development PoW unavailable")
            header = bytes.fromhex(job["header80"].removeprefix("0x"))
            target = int(job["target"].removeprefix("0x"), 16)
            for nonce in range(1 << 32):
                if nonce % 4096 == 0:
                    self.guard()
                if int.from_bytes(self.pool.sha256d(header[:76] + nonce.to_bytes(4, "little")), "little") <= target:
                    response = rpc(url, "hegemon_submitPoolShare", [{"job_id": job["job_id"], "nonce": f"{nonce:08x}",
                                   "extranonce": "00" * 28, "ntime": job["ntime"]}], timeout=180)
                    require(response.get("accepted") is True, "independently solved block rejected")
                    break
            else:
                raise AcceptanceError("nonce range exhausted")
        require(self.status(url)[0] == height, "mining overshot exact height")

    def pending(self, url, tx):
        data, total = bytearray(), None
        while total is None or len(data) < total:
            row = rpc(url, "hegemon_developmentPendingActionChunk", ["0x" + tx, len(data), 262144])
            if row is None:
                # A relayed action may not have arrived yet, or may disappear
                # between chunk reads. The next poll restarts from offset0.
                return None
            require(isinstance(row, dict) and row.get("schema") == "hegemon.development-pending-action-chunk-v1"
                    and row["offset"] == len(data) and row["tx_hash"].removeprefix("0x") == tx,
                    "pending chunk identity mismatch")
            chunk = bytes.fromhex(row["chunk"].removeprefix("0x"))
            require(chunk and len(chunk) == row["chunk_len"] and row["total_len"] <= MAX_RPC_BYTES
                    and (total is None or total == row["total_len"]), "pending chunk bound changed")
            total = row["total_len"]
            data += chunk
        require(len(data) == total and data[:48].hex() == tx, "pending action identity/length mismatch")
        return bytes(data)

    def retain_body(self, name, body, admin=False):
        parsed = inspect_admin_carrier(body) if admin else inspect_asset_carrier(body)
        path = self.base / (name + ".carrier")
        require(not path.exists(), "proof artifact name reused")
        path.write_bytes(body)
        public = parsed["public_words"]
        row = {"name": name, "carrier": file_record(path), "proof_bytes": parsed["proof_bytes"],
               "proof_sha256": parsed["proof_sha256"], "admin": admin, "public_statement": public,
               "proof_generated_by_actual_walletd": True}
        self.proofs.append(row)
        self.save()
        return row

    def req(self, body, admin=False):
        return {"binding_circuit": 13, "binding_crypto": 7, "family_id": 1, "action_id": 17 if admin else 16,
                "object_refs": [], "new_nullifiers": [], "public_args": base64.b64encode(body).decode(),
                "authorization_proof": None, "authorization_signatures": [], "aux_data": None}

    def reject(self, name, request, urls=None):
        for url in urls or self.urls:
            before = self.snap(url)
            try:
                result = rpc(url, "hegemon_submitAction", [request], timeout=180)
                require(isinstance(result, dict) and result.get("success") is False, "negative action unexpectedly admitted: " + name)
                reason = result.get("error")
            except RpcRejected as error:
                reason = error.error.get("message", "RPC rejection")
            require(self.snap(url) == before, "rejected action changed canonical state: " + name)
            self.receipt.setdefault("rejections", []).append({"name": name, "url": url, "reason": reason,
                                                               "canonical_state_unchanged": True})
        self.save()

    def include(self, row, body, submit, expected_fee=1000):
        self.current = "include-" + row["name"]
        response = submit()
        tx = response["action_id"].removeprefix("0x")
        self.current = "observe-local-pending-" + row["name"]
        first = self.wait(lambda: self.pending(self.urls[0], tx), "local exact pending action")
        self.current = "observe-relayed-pending-" + row["name"]
        self.wait(lambda: self.pending(self.urls[1], tx) == first, "exact pending relay")
        self.current = "inspect-exact-pending-" + row["name"]
        args, outer = pending_action_public_args(first)
        require(args == body and outer["outer_fee"] == expected_fee, "pending action changed proof/body/fee")
        if row.get("admin") is not None:
            inspect_native_pending_action(first)
        path = self.base / (row["name"] + ".action")
        if path.exists():
            require(path.read_bytes() == first, "exported native action changed before pending relay")
        path.write_bytes(first)
        height = self.status()[0] + 1
        self.mine(height)
        self.converge()
        block_hash = rpc(self.urls[0], "chain_getBlockHash", [height])
        aa, ma, ba = canonical_body(self.urls[0], block_hash)
        bb, mb, body_b = canonical_body(self.urls[1], block_hash)
        require((aa, ma, ba) == (bb, mb, body_b) and aa.count(first) == 1,
                "canonical bytes changed, missing or duplicated across nodes")
        reward = rpc(self.urls[0], "hegemon_blockReward", [block_hash])
        require(int(reward["fees_atoms"]) == expected_fee, "proof fee not accounted exactly once in real reward")
        row.update(action=file_record(path), action_id=tx, inclusion={"height": height, "hash": block_hash,
                   "canonical_body_sha256": hashlib.sha256(ba).hexdigest()}, fees_atoms=expected_fee)
        for actor in range(2):
            self.sync(actor)
        if not row.get("admin", True):
            matches = [dict(n, actor=actor) for actor in range(2) for n in self.w(actor, "asset.notes")
                       if n["created_height"] == height
                       and n["commitment"] in [row["public_statement"][start:start + 7] for start in (67, 74, 81)]]
            require(len(matches) == 3 and sorted(n["position"] for n in matches)
                    == list(range(min(n["position"] for n in matches), min(n["position"] for n in matches) + 3)),
                    "all three exact outputs/positions were not recovered")
            row["outputs"] = matches
        self.save()
        return first

    def credentials(self, entries, expiry=10000):
        return self.w(0, "asset.credentials", {"asset_id": 17, "policy_version": 1, "depth": 4,
                       "entries": [dict(entry, expires_at=expiry) for entry in entries]})

    def build(self, name, operation="transfer", amount=1, credentials=None, policy=None, position=None, store=None, recipient=None):
        self.sync(store=store)
        params = {"ws_url": self.urls[0], "asset_id": 17, "operation": operation, "amount": amount, "fee": 1000,
                  "recipient": recipient or self.addresses[0]["address"], "credentials": credentials or [self.cred[0]] * 3}
        if operation == "mint":
            params["issuer_secret"] = self.issuer
            params["credentials"][0] = {"index": 0, "expires_at": 0, "siblings": []}
        if policy is not None:
            params["policy"] = policy
        if position is not None:
            params["input_position"] = position
        result = self.w(0, "asset.prepare", params, store=store)
        exported = self.w(0, "asset.export", {"reservation_id": result["reservation_id"]}, store=store)
        body = bytes.fromhex(exported["action"])
        row = self.retain_body(name, body)
        row["reservation_id"] = result["reservation_id"]
        return row, body, lambda: self.w(0, "asset.submit", {"ws_url": self.urls[0],
                                            "reservation_id": result["reservation_id"]}, store=store)

    def admin(self, name, controls, submit=True, secret=None):
        self.sync()
        params = dict(ws_url=self.urls[0], asset_id=17, admin_secret=secret or self.admin_secret,
                      expires_at=10000, action_intent=[secrets.randbelow(GOLDILOCKS - 1) + 1 for _ in range(7)], **controls)
        result = self.w(0, "asset.adminPrepare", params)
        body = bytes.fromhex(result["action"])
        row = self.retain_body(name, body, True)
        if submit:
            self.include(row, body, lambda: self.w(0, "asset.adminSubmit", {"ws_url": self.urls[0],
                                                                       "action": body.hex()}), 0)
        return row, body, params

    def native(self, name, position, amount=1, store=None):
        wallet = store or self.stores[0]
        def cli(command, proof=False):
            argv = [str(self.args.private_spend), "--wallet", str(wallet), "--manifest", str(self.base / "manifest.json"),
                    "--genesis", "0x" + self.genesis, "--rpc", self.urls[0], "--development-local-candidate", *map(str, command)]
            code, out, _ = private_wallet(argv, [(b"passphrase:", self.phrases[0])], self.env,
                                          self.args.proof_timeout if proof else 180, self.guard)
            require(code == 0, "native private-spend wallet command failed: " + str(command[0]))
            return out.decode()
        output = cli(["ordinary", "--inputs", position, "--recipient", self.addresses[0]["address"],
                      "--amount", amount, "--fee", 1000], True)
        found = re.search(r"candidate ([0-9a-f]{64})", output)
        require(found is not None, "native ordinary candidate id absent")
        path = self.base / (name + ".action")
        cli(["export", found[1], path])
        action = path.read_bytes()
        body, outer = pending_action_public_args(action)
        require(body[:8] == b"HGPSLC02" and outer["action_id"] == 15, "ordinary native route framing mismatch")
        row = {"name": name, "action": file_record(path), "native_ordinary": True,
               "proof_bytes": len(body) - 5784, "carrier_sha256": hashlib.sha256(body).hexdigest()}
        self.proofs.append(row)
        def submit():
            cli(["submit", found[1]])
            return {"action_id": action[:48].hex()}
        return row, body, submit, action

    def native_notes(self, store=None):
        argv = [str(self.args.private_spend), "--wallet", str(store or self.stores[0]), "--manifest", str(self.base / "manifest.json"),
                "--genesis", "0x" + self.genesis, "--rpc", self.urls[0], "--development-local-candidate", "notes"]
        code, output, _ = private_wallet(argv, [(b"passphrase:", self.phrases[0])], self.env, 180, self.guard)
        require(code == 0, "actual native note inventory failed")
        return [(int(p), int(v)) for p, v in re.findall(rb"ordinary position=(\d+) value=(\d+)", output)]

    def gates(self):
        completed = {row["id"] for row in self.receipt["checks"]}
        missing = set(self.receipt["requested_gates"]) - completed
        require(not missing, "mandatory live gates missing: " + ", ".join(sorted(missing)))

    def wallet_reject(self, name, params):
        before = self.snap()
        try:
            self.w(0, "asset.prepare", params)
        except WalletRejected as error:
            require(self.snap() == before, "negative wallet operation changed canonical state")
            self.receipt.setdefault("wallet_rejections", []).append({"name": name, "code": error.code,
                                                                     "canonical_state_unchanged": True})
            self.save()
            return
        raise AcceptanceError("negative wallet operation unexpectedly proved: " + name)

    def params(self, operation="transfer", amount=1, credentials=None, policy=None, position=None):
        result = {"ws_url": self.urls[0], "asset_id": 17, "operation": operation, "amount": amount, "fee": 1000,
                  "recipient": self.addresses[0]["address"], "credentials": credentials or [self.cred[0]] * 3}
        if operation == "mint":
            result["issuer_secret"] = self.issuer
            result["credentials"][0] = {"index": 0, "expires_at": 0, "siblings": []}
        if policy is not None: result["policy"] = policy
        if position is not None: result["input_position"] = position
        return result

    def policy_checks(self, entries):
        secret = secrets.token_bytes(32)
        boundary = self.status()[0] + 12
        policy = {"nullifier_key": [secrets.randbelow(GOLDILOCKS - 1) + 1 for _ in range(5)],
                  "branches": [{"enabled": 1, "authority": self.addresses[0]["authority"], "not_before": boundary,
                                "hash_required": 1, "hashlock": list(hashlib.sha256(secret).digest()), "release_secret": 1}, {}]}
        owner = self.w(0, "asset.policyOwner", {"chain_id": self.chain, "asset_id": 17, "policy": policy})["owner"]
        entries = entries + [{"index": 2, "recipient": self.addresses[0]["address"], "owner": owner}]
        tree = self.credentials(entries)
        self.admin("install-bounded-owner-credential", {"credential_root": tree["credential_root"]})
        self.cred = [entry["witness"] for entry in tree["entries"]]
        lock = self.build("bounded-lock-disabled-fallback", amount=200, credentials=[self.cred[0], self.cred[2], self.cred[0]],
                          policy={"create": 1, "output": policy})
        self.include(*lock)
        position = next(n["position"] for n in lock[0]["outputs"] if n["script_owned"])
        opening = {"spend": 1, "input": policy, "selected": [1, 0], "secret": list(secret)}
        spend = self.params(amount=200, credentials=[self.cred[2], self.cred[0], self.cred[0]], policy=opening, position=position)
        self.wallet_reject("bounded-before-height", spend)
        disabled = json.loads(json.dumps(spend))
        disabled["policy"]["selected"] = [0, 1]
        disabled["policy"]["secret"] = [0] * 32
        self.wallet_reject("bounded-disabled-branch", disabled)
        # A proof made before freeze must fail unchanged afterward on both nodes.
        stale = self.build("ordinary-pre-freeze")
        before = self.row()
        count = self.snap()["asset"]["registry"]["consumed_admin_actions"]
        freeze, freeze_body, _ = self.admin("freeze", {"frozen": True})
        require(bytes.fromhex(self.row()["row"])[:59 * 8] == bytes.fromhex(before["row"])[:59 * 8],
                "admin freeze changed config/version/counters")
        self.reject("ordinary-pre-freeze-unchanged", self.req(stale[1]))
        for operation in ("mint", "transfer", "burn"):
            self.wallet_reject("frozen-" + operation, self.params(operation))
        self.wallet_reject("frozen-bounded-create", self.params(amount=200,
                           credentials=[self.cred[0], self.cred[2], self.cred[0]], policy={"create": 1, "output": policy}))
        self.wallet_reject("frozen-bounded-primary", spend)
        self.wallet_reject("frozen-bounded-fallback", disabled)
        self.admin("unfreeze", {"frozen": False})
        require(self.row()["row"] == before["row"] and self.snap()["asset"]["registry"]["consumed_admin_actions"] == count + 2,
                "root cycle changed policy or lost consumed administrator history")
        self.reject("old-admin-proof-after-root-cycle", self.req(freeze_body, True))
        self.w(0, "asset.abandon", {"reservation_id": stale[0]["reservation_id"]})
        # The issuer role cannot use the separate asset-admin relation.
        self.sync()
        issuer_rejection_before = self.snap()
        try:
            self.admin("issuer-cannot-admin", {"frozen": True}, secret=self.issuer)
        except WalletRejected as error:
            require(error.code == "internal_error", "issuer administrator test failed through unrelated wallet route")
            require(self.snap() == issuer_rejection_before, "rejected issuer administrator request changed canonical state")
        else:
            raise AcceptanceError("issuer secret authorized controls")
        self.mark("authenticated-controls-admin", full_config_and_counters_preserved=True,
                  root_cycle_preserved_semantic_admin_history=True, issuer_only_rejected=True)
        self.mark("freeze-wraps-every-route", actual_wallet_routes=["mint", "transfer", "burn", "bounded-create", "bounded-primary", "bounded-fallback"],
                  unchanged_pre_freeze_proof_rejected_on_both_nodes=True)
        # Revoke the previous tree while retaining valid current owners.
        stale = self.build("ordinary-pre-revocation")
        old_creds = json.loads(json.dumps(self.cred))
        renewed = self.credentials(entries, expiry=9000)
        require(renewed["credential_root"] != tree["credential_root"], "credential revocation root did not change")
        self.admin("renew-credentials", {"credential_root": renewed["credential_root"]})
        self.reject("old-credential-proof-unchanged", self.req(stale[1]))
        # Release the exported stale candidate before testing the witness:
        # otherwise its reservation can mask credential rejection as no funds.
        self.w(0, "asset.abandon", {"reservation_id": stale[0]["reservation_id"]})
        self.wallet_reject("old-credential-witness", self.params(credentials=[old_creds[0]] * 3))
        self.cred = [entry["witness"] for entry in renewed["entries"]]
        self.mine(boundary)
        self.converge()
        self.sync()
        bad_zero_change = self.params(amount=200, credentials=[self.cred[2], self.cred[0],
                               {"index": 0, "expires_at": 0, "siblings": []}], policy=opening, position=position)
        self.wallet_reject("missing-current-zero-change-credential", bad_zero_change)
        released = self.build("bounded-exact-height-release", amount=200,
                              credentials=[self.cred[2], self.cred[0], self.cred[0]], policy=opening, position=position)
        require(released[0]["public_statement"][16] == boundary, "missed exact bounded parent-height boundary")
        require(inspect_asset_carrier(released[1])["released_secret_hex"] == secret.hex(), "not all 256 preimage bits were released")
        self.include(*released)
        self.mark("current-credentials", revoked_old_proof_and_witness_rejected=True,
                  fresh_credentials_accepted_at_current_root=True, zero_change_credential_checked=True)
        # A second real policy permits two branches; prove both from cold copies.
        second = json.loads(json.dumps(policy))
        second["nullifier_key"] = [secrets.randbelow(GOLDILOCKS - 1) + 1 for _ in range(5)]
        second_boundary = self.status()[0] + 4
        second["branches"][0]["not_before"] = second_boundary
        second["branches"][1] = {"enabled": 1, "authority": self.addresses[0]["authority"], "not_before": second_boundary}
        second_owner = self.w(0, "asset.policyOwner", {"chain_id": self.chain, "asset_id": 17, "policy": second})["owner"]
        entries.append({"index": 3, "recipient": self.addresses[0]["address"], "owner": second_owner})
        renewed = self.credentials(entries, expiry=9000)
        self.admin("install-two-branch-credential", {"credential_root": renewed["credential_root"]})
        self.cred = [entry["witness"] for entry in renewed["entries"]]
        lock2 = self.build("bounded-two-branch-lock", amount=50, credentials=[self.cred[0], self.cred[3], self.cred[0]],
                           policy={"create": 1, "output": second})
        self.include(*lock2)
        second_position = next(n["position"] for n in lock2[0]["outputs"] if n["script_owned"])
        self.mine(second_boundary)
        self.converge()
        self.sync()
        branch_copy = self.base / "branch-alternative.wallet"
        shutil.copy2(self.stores[0], branch_copy)
        first = self.build("bounded-primary-branch", amount=50, credentials=[self.cred[3], self.cred[0], self.cred[0]],
                           policy={"spend": 1, "input": second, "selected": [1, 0], "secret": list(secret)}, position=second_position)
        other = self.build("bounded-alternative-branch", amount=50, credentials=[self.cred[3], self.cred[0], self.cred[0]],
                           policy={"spend": 1, "input": second, "selected": [0, 1]}, position=second_position, store=branch_copy)
        require(first[0]["public_statement"][53:60] == other[0]["public_statement"][53:60], "policy branches have different spent nullifiers")
        self.include(*first)
        self.reject("alternative-branch-after-consumption", self.req(other[1]))
        self.mark("bounded-height-release", exact_parent_height=boundary, all_256_release_bits=True,
                  disabled_and_early_rejected=True, both_valid_branches_proved_same_nullifier=True)
        # Mutations use one actual current proof and unchanged authenticated state.
        valid = self.build("ordinary-negative-matrix")
        parsed = inspect_asset_carrier(valid[1])
        mutations = {"trailing": valid[1] + b"\0", "proof-bit": valid[1][:-1] + bytes([valid[1][-1] ^ 1])}
        ct_at = parsed["public_offset"] + 134 * 8
        damaged = bytearray(valid[1]); damaged[ct_at] ^= 1
        mutations["ciphertext-bit"] = bytes(damaged)
        for label, index in (("wrong-chain", 0), ("wrong-parent", 8), ("wrong-height", 16), ("registry-root", 24),
                             ("wrong-version", 32), ("credential-root", 33), ("frozen-row", 41), ("issuer-row", 43),
                             ("wrong-fee", 52), ("ordinary-policy-mode", 124)):
            damaged = bytearray(valid[1])
            start = parsed["public_offset"] + index * 8
            word = int.from_bytes(damaged[start:start + 8], "little")
            damaged[start:start + 8] = (word ^ 1).to_bytes(8, "little")
            mutations[label] = bytes(damaged)
        for label, index, value in (("field-modulus-alias", 24, GOLDILOCKS), ("noncanonical-mode", 124, 2),
                                    ("nonboolean-release", 125, 2), ("oversized-release-limb", 126, 1 << 32)):
            damaged = bytearray(valid[1])
            start = parsed["public_offset"] + index * 8
            damaged[start:start + 8] = value.to_bytes(8, "little")
            mutations[label] = bytes(damaged)
        for label, body in mutations.items(): self.reject("mutation-" + label, self.req(body))
        wrong_type = self.req(valid[1]); wrong_type["action_id"] = 15
        self.reject("asset-carrier-on-native-private-type", wrong_type)
        self.include(*valid)
        self.mark("registry-root-consensus", current_chain_parent_root_and_full_row_mutations_rejected=True,
                  consensus_action_bodies_bind_replay=True, registry_header_root_claim=False)
        self.mark("atomic-failure-replay", malformed_public_proof_ciphertext_and_context=len(mutations),
                  both_node_snapshots_unchanged=True, admin_history_survives_root_cycle=True)

    def verify_retained_actions(self, allow_orphaned=False):
        checked, orphaned = 0, 0
        for row in self.proofs:
            if "inclusion" not in row: continue
            height, expected_hash = row["inclusion"]["height"], row["inclusion"]["hash"]
            current = rpc(self.urls[0], "chain_getBlockHash", [height])
            if current != expected_hash:
                require(allow_orphaned, "retained action inclusion was unexpectedly orphaned")
                orphaned += 1
                continue
            expected = Path(row["action"]["path"]).read_bytes()
            aa, ma, ba = canonical_body(self.urls[0], current)
            bb, mb, body_b = canonical_body(self.urls[1], current)
            require((aa, ma, ba) == (bb, mb, body_b) and aa.count(expected) == 1, "retained canonical bytes changed")
            checked += 1
        self.mark("two-node-exact-bytes", currently_canonical_actions=checked, observed_orphaned_actions=orphaned,
                  all_inclusions_compared_before_reorg=True)

    def release_orphaned_mint(self, row, body):
        """Explicit wallet release preserves the stale exported-action tombstone."""
        self.current = "release-orphaned-mint-reservation"
        identity = row["reservation_id"]
        require(isinstance(identity, str) and re.fullmatch(r"[0-9a-f]{64}", identity),
                "original mint reservation identity invalid")
        identity_bytes = list(bytes.fromhex(identity))
        before = self.w(0, "asset.journal")
        matches = [entry for entry in before if entry["id"] == identity_bytes]
        require(len(matches) == 1, "original orphan mint reservation absent or duplicated")
        original = matches[0]
        require(original["status"] == "Submitted" and original["mined_in"] is None
                and original["inputs_reserved"] is True
                and original["parent_height"] == row["public_statement"][16]
                and self.status()[0] > original["parent_height"]
                and original["action_id"] == list(bytes.fromhex(row["action_id"])),
                "original mint is not an expired orphaned submitted reservation")
        exported = self.w(0, "asset.export", {"reservation_id": identity})
        require(exported.get("reservation_id") == identity and exported.get("encoding") == "hex"
                and exported.get("action_bytes") == len(body) and exported.get("action") == body.hex(),
                "orphan mint exported bytes differ before explicit release")
        canonical = self.snap()
        result = self.w(0, "asset.abandon", {"reservation_id": identity})
        require(result == {"reservation_id": identity}, "explicit orphan mint release identity differs")
        expected = [dict(entry, status="Abandoned", inputs_reserved=False)
                    if entry["id"] == identity_bytes else entry for entry in before]
        after = self.w(0, "asset.journal")
        require(after == expected, "explicit orphan mint release changed identity, parent, bytes metadata or another reservation")
        require(self.w(0, "asset.export", {"reservation_id": identity}) == exported,
                "explicit orphan mint release removed or changed retained action bytes")
        require(self.snap() == canonical, "explicit wallet release changed canonical node state")
        self.receipt["orphan_mint_explicit_release"] = {
            "reservation_id": identity, "before": original,
            "after": next(entry for entry in after if entry["id"] == identity_bytes),
            "retained_carrier_sha256": hashlib.sha256(body).hexdigest(),
            "exact_exported_bytes_preserved": True, "other_reservations_unchanged": True,
            "canonical_node_state_unchanged": True}
        self.save()

    def execute(self):
        # Bootstrap secrets enter only encrypted wallet stores, never receipts.
        self.addresses = [self.w(i, "asset.address", {"index": 0}, create=True) for i in range(2)]
        entries = [{"index": i, "recipient": address["address"]} for i, address in enumerate(self.addresses)]
        credentials = self.credentials(entries)
        self.cred = [entry["witness"] for entry in credentials["entries"]]
        row = self.w(0, "asset.row", {"disposable": True, "asset_id": 17, "policy_version": 1,
                     "issuer_secret": self.issuer, "admin_secret": self.admin_secret,
                     "credential_root": credentials["credential_root"], "credential_depth": 4})
        write_json(self.base / "asset-descriptor.json", row["descriptor"])
        command = [str(self.args.node), "--print-development-candidate-manifest", "--development-funding-address",
                   self.addresses[0]["address"], "--development-assets-json", str(self.base / "asset-descriptor.json")]
        result = subprocess.run(command, env=self.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
        require(result.returncode == 0 and len(result.stdout) < 65536, "fresh Development manifest generation failed")
        self.manifest = json.loads(result.stdout)
        self.manifest["pow_bits"] = 0x207fffff
        write_json(self.base / "manifest.json", self.manifest)
        a = self.node("asset-a", self.base / "node-a", 0)
        b = self.node("asset-b", self.base / "node-b", 1, f"127.0.0.1:{self.ports[2]}")
        self.converge()
        self.mark("source-network-identity", genesis=self.genesis, chain_id=self.chain,
                  manifest_digest=self.manifest_digest, two_independent_nodes=True)
        initial = self.snap()
        self.receipt["initial_snapshot"] = initial
        require(bytes.fromhex(self.row()["row"])[55 * 8:59 * 8] == bytes(32), "genesis supply/counters nonzero")
        self.mark("authenticated-genesis-registry", descriptor=file_record(self.base / "asset-descriptor.json"))
        self.mine(121)
        self.converge()
        for actor in range(2): self.sync(actor)
        reward = rpc(self.urls[0], "hegemon_blockReward", [rpc(self.urls[0], "chain_getBlockHash", [1])])
        require(reward["reward_present"] is True and reward["maturity_height"] == 121, "real positive mature reward absent")
        self.mark("mined-native-fee-ingress", reward=reward, fixture_note_ingress=False)
        # Retain a stopped-node prefix for a genuine later competing branch.
        self.stop(a); self.stop(b)
        shutil.copytree(self.base / "node-b", self.base / "fork-prefix")
        a = self.node("asset-a-prefix-restart", self.base / "node-a", 0, f"127.0.0.1:{self.ports[3]}")
        b = self.node("asset-b-prefix-restart", self.base / "node-b", 1, f"127.0.0.1:{self.ports[2]}")
        self.converge()
        mint = self.build("mint", "mint", 1000)
        self.include(*mint)
        require(int.from_bytes(bytes.fromhex(self.row()["row"])[57 * 8:58 * 8], "little") == 1000, "mint debt mismatch")
        # Asset HGN change must be usable by the existing ordinary route.
        native_position = next(n["position"] for n in mint[0]["outputs"] if n["asset_id"] == 0)
        ordinary = self.native("asset-change-to-native", native_position)
        self.include(*ordinary[:3])
        # Native-created HGN change is now the smallest eligible real fee note.
        self.sync()
        link_copy = self.base / "native-change-link.wallet"
        shutil.copy2(self.stores[0], link_copy)
        original_change = next(n["value"] for n in mint[0]["outputs"] if n["asset_id"] == 0)
        positions = [p for p, value in self.native_notes(link_copy) if value == original_change - 1001]
        require(len(positions) == 1, "exact native-created HGN change note not recovered")
        native_link = self.native("native-created-change-nullifier-link", positions[0], store=link_copy)
        transfer = self.build("native-change-to-asset", "transfer", 1)
        native_nf = [int.from_bytes(ordinary[1][index:index + 8], "little") for index in range(208, 264, 8)]
        require(mint[0]["public_statement"][60:67] != native_nf, "native spend reused original fee rather than its change")
        linked_nf = [int.from_bytes(native_link[1][index:index + 8], "little") for index in range(208, 264, 8)]
        require(linked_nf == transfer[0]["public_statement"][60:67], "asset fee did not consume exact native-created change")
        ordinary_change_cm = [int.from_bytes(ordinary[1][i:i + 8], "little") for i in range(376, 432, 8)]
        require(any(ordinary_change_cm), "ordinary native change commitment absent")
        transfer[0]["native_change_commitment"] = ordinary_change_cm
        self.include(*transfer)
        self.mark("all-three-output-positions", outputs_recovered_including_zero=True,
                  asset_change_spent_through_native=True, native_change_spent_through_asset=True)
        # Cross-route conflict: cold wallet copy before either reservation.
        self.sync()
        clone = self.base / "conflict.wallet"
        shutil.copy2(self.stores[0], clone)
        conflict = self.build("cross-route-asset", "transfer", 1)
        expected_nf = conflict[0]["public_statement"][60:67]
        fee_notes = [n for n in self.w(0, "asset.notes") if n["asset_id"] == 0 and n["nullifier"] == expected_nf]
        if fee_notes:
            fee_position = fee_notes[0]["position"]
        else:
            argv = [str(self.args.private_spend), "--wallet", str(clone), "--manifest", str(self.base / "manifest.json"),
                    "--genesis", "0x" + self.genesis, "--rpc", self.urls[0], "--development-local-candidate", "notes"]
            code, output, _ = private_wallet(argv, [(b"passphrase:", self.phrases[0])], self.env, 180, self.guard)
            require(code == 0, "native fee note inventory failed")
            choices = [(int(v), int(p)) for p, v in re.findall(rb"ordinary position=(\d+) value=(\d+)", output) if int(v) >= 1000]
            require(choices, "no real ordinary fee notes")
            fee_position = min(choices)[1]
        loser = self.native("same-fee-native-loser", fee_position, store=clone)
        require([int.from_bytes(loser[1][i:i + 8], "little") for i in range(208, 264, 8)] == expected_nf,
                "cross-route proofs did not consume the exact same fee nullifier")
        self.include(*conflict)
        native_request = {"binding_circuit": 12, "binding_crypto": 7, "family_id": 1, "action_id": 15,
                          "object_refs": [], "new_nullifiers": [], "public_args": base64.b64encode(loser[1]).decode(),
                          "authorization_proof": None, "authorization_signatures": [], "aux_data": None}
        self.reject("same-global-nullifier-native-after-asset", native_request)
        # Reverse route order from an independent pre-reservation wallet copy.
        self.sync()
        reverse_clone = self.base / "reverse-conflict.wallet"
        shutil.copy2(self.stores[0], reverse_clone)
        reverse = self.build("cross-route-asset-loser", "transfer", 1)
        reverse_nf = reverse[0]["public_statement"][60:67]
        reverse_notes = [n for n in self.w(0, "asset.notes") if n["asset_id"] == 0 and n["nullifier"] == reverse_nf]
        require(len(reverse_notes) == 1, "reverse route fee must be actual recovered asset HGN change")
        native_winner = self.native("same-fee-native-winner", reverse_notes[0]["position"], store=reverse_clone)
        require([int.from_bytes(native_winner[1][i:i + 8], "little") for i in range(208, 264, 8)] == reverse_nf,
                "reverse route candidates do not share the actual fee nullifier")
        self.include(*native_winner[:3])
        self.reject("same-global-nullifier-asset-after-native", self.req(reverse[1]))
        self.w(0, "asset.abandon", {"reservation_id": reverse[0]["reservation_id"]})
        self.mark("native-fee-global-conflict", exact_shared_nullifier=expected_nf,
                  historical_native_proof_rejected_after_asset=True, reverse_native_first_rejected_asset=True,
                  reverse_rejection_also_binds_exact_parent=True)
        # Disable issuance but preserve ordinary transfer/holder burn.
        self.admin("disable-mint", {"mint_enabled": False})
        transfer = self.build("transfer-mint-disabled", "transfer", 1)
        self.include(*transfer)
        burn = self.build("holder-burn-mint-disabled", "burn", 1)
        self.include(*burn)
        require(int.from_bytes(bytes.fromhex(self.row()["row"])[57 * 8:58 * 8], "little") == 999, "burn debt mismatch")
        payout = self.build("transfer-to-independent-recipient", amount=10,
                            credentials=[self.cred[0], self.cred[1], self.cred[0]], recipient=self.addresses[1]["address"])
        self.include(*payout)
        require(any(n["asset_id"] == 17 and n["value"] == 10 and not n["spent"] for n in self.w(1, "asset.notes")),
                "independent recipient did not recover controlled-asset payout")
        self.mark("mint-transfer-burn", actual_mint=1000, actual_burn=1, debt=999, mint_disabled_transfer_and_burn=True)
        self.policy_checks(entries)
        # Restart both, then replace B with a genuinely empty database.
        snapshot, tip = self.snap(), self.status()
        losing_work = self.tip_work(expected_tip=tip)
        self.stop(a); self.stop(b)
        a = self.node("asset-a-durable-restart", self.base / "node-a", 0, f"127.0.0.1:{self.ports[3]}")
        b = self.node("asset-b-durable-restart", self.base / "node-b", 1, f"127.0.0.1:{self.ports[2]}")
        self.converge()
        require(self.snap() == snapshot and self.status() == tip, "restart changed exact canonical state")
        self.stop(b)
        fresh = self.base / "node-b-empty"
        require(not fresh.exists(), "fresh sync database was not empty")
        b = self.node("asset-b-empty-sync", fresh, 1, f"127.0.0.1:{self.ports[2]}")
        self.converge()
        require(self.snap() == snapshot, "fresh sync changed roots/rows/admin history")
        self.reject("durable-cross-route-replay", native_request)
        self.mark("restart-and-fresh-sync", exact_snapshot=snapshot, truly_empty_database=True,
                  stopped_prefix_copy_only_for_fork=True)
        self.verify_retained_actions()
        # Adopt real independently mined greater-work blocks; no state injection.
        self.stop(a); self.stop(b)
        fork = self.node("asset-fork-isolated", self.base / "fork-prefix", 1)
        self.mine(tip[0] + 2, self.urls[1])
        extra_blocks = 0
        winning_work = self.tip_work(self.urls[1])
        while winning_work <= losing_work and extra_blocks < 64:
            self.guard()
            previous_work = winning_work
            self.mine(self.status(self.urls[1])[0] + 1, self.urls[1])
            extra_blocks += 1
            winning_work = self.tip_work(self.urls[1])
            require(winning_work > previous_work, "isolated fork cumulative work did not advance")
        require(winning_work > losing_work, "isolated fork did not exceed actual losing-tip cumulative work")
        winning = self.status(self.urls[1])
        require(self.tip_work(self.urls[1], expected_tip=winning) == winning_work,
                "isolated winning tip cumulative work changed before reconnect")
        a = self.node("asset-a-adopt-fork", self.base / "node-a", 0, f"127.0.0.1:{self.ports[3]}")
        self.wait(lambda: self.status() == winning, "actual greater-work adoption", 300)
        self.stop(fork)
        b = self.node("asset-b-adopt-fork", fresh, 1, f"127.0.0.1:{self.ports[2]}")
        self.converge()
        require(self.row()["row"] == initial["asset"]["registry"]["rows"][0]["row"]
                and self.snap()["asset"]["registry"]["consumed_admin_actions"] == 0, "reorg failed registry/admin rollback")
        for actor in range(2): self.sync(actor)
        require(not any(not n["spent"] and n["asset_id"] == 17 for n in self.w(0, "asset.notes")),
                "orphan asset notes remain canonical after real reorg")
        self.reject("orphan-context-mint-replay", self.req(mint[1]))
        self.release_orphaned_mint(mint[0], mint[1])
        self.cred = [entry["witness"] for entry in credentials["entries"]]
        reproved = self.build("mint-after-real-reorg", "mint", 1000)
        require(reproved[0]["public_statement"][60:67] == mint[0]["public_statement"][60:67],
                "reorg did not restore the original actual fee note")
        self.include(*reproved)
        self.mark("real-higher-work-reorg", losing_tip=tip, adopted_tip=winning,
                  losing_cumulative_work="0x" + losing_work.hex(),
                  winning_cumulative_work="0x" + winning_work.hex(),
                  additional_fork_blocks_for_strictly_greater_work=extra_blocks,
                  registry_supply_and_admin_rollback=True, original_fee_note_spendable_again=True,
                  original_submitted_reservation_explicitly_abandoned_with_exact_bytes_preserved=True,
                  stale_action_rejected_and_reproved=True)
        self.verify_retained_actions(allow_orphaned=True)
        self.gates()
        require(all(sha(record["path"]) == record["sha256"] for record in self.receipt["sources"])
                and all(sha(record["path"]) == record["sha256"] for record in self.receipt["binaries"].values()),
                "runtime source/binaries changed during acceptance")
        self.receipt["status"] = "passed"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="write checklist/source pins, without RPC or subprocesses")
    parser.add_argument("--run", action="store_true", help="run actual two-node Development acceptance; coordinator executes after build readiness")
    parser.add_argument("--node", type=Path, default=ROOT / "target-stablecoin/retained-proof/hegemon-node")
    parser.add_argument("--walletd", type=Path, default=ROOT / "target-stablecoin/retained-proof/walletd")
    parser.add_argument("--private-spend", type=Path, default=ROOT / "target-stablecoin/retained-proof/private-spend")
    parser.add_argument("--run-name", default="actual-" + time.strftime("%Y%m%dT%H%M%S"))
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--proof-timeout", type=int, default=600)
    parser.add_argument("--coordinator-usage-remaining", type=float,
                        help="coordinator's fresh account readback; must exceed the agreed 40 percent floor")
    args = parser.parse_args()
    os.umask(0o077)
    require(not (args.run and args.prepare_only), "choose preparation or actual execution")
    if args.run:
        require(args.coordinator_usage_remaining is not None and args.coordinator_usage_remaining > 40,
                "coordinator must supply a fresh remaining-account readback above40 percent")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_name), "unsafe run name")
        require(0 < args.proof_timeout <= 1800 and 0 < args.timeout <= 14400, "execution deadline out of bounds")
        for key in ("node", "walletd", "private_spend"):
            binary = getattr(args, key).resolve()
            require(binary.is_file() and os.access(binary, os.X_OK), "missing executable " + key)
            setattr(args, key, binary)
        run = NativeLifecycle(args)
        def interrupted(number, _frame):
            raise AcceptanceError("owned acceptance interrupted by signal " + str(number))
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            run.execute()
        except BaseException as error:
            run.receipt.update(failure_evidence(error, run.current))
        finally:
            for child in reversed(run.children):
                if child.poll() is None:
                    run.pool.stop_process_group(child)
            run.receipt.update(owned_processes=len(run.children), owned_processes_reaped=all(c.poll() is not None for c in run.children),
                               disk_free_bytes=shutil.disk_usage(run.base).free, harness_sha256=sha(__file__))
            run.save()
            print(json.dumps({"status": run.receipt["status"], "receipt": str(run.base / "receipt.json"),
                              "checks": len(run.receipt["checks"]), "failed_step": run.receipt.get("failed_step"),
                              "error": run.receipt.get("error")}), flush=True)
        return 0 if run.receipt["status"] == "passed" else 1
    destination = prepare()
    print(json.dumps({"status": "PREPARED_NOT_EXECUTED", "plan": str(destination), "sha256": sha(destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
