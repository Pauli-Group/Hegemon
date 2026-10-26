#!/usr/bin/env python3
"""Exercise the agreed HTLC against a private Bitcoin Core regtest daemon.

This code constructs and signs transactions. Only Bitcoin Core evaluates scripts.
Private keys and chain data belong in the explicitly supplied scratch directory.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sha256(data):
    return hashlib.sha256(data).digest()


def hash256(data):
    return sha256(sha256(data))


def compact_size(number):
    if number < 253:
        return bytes([number])
    if number <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", number)
    if number <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", number)
    return b"\xff" + struct.pack("<Q", number)


def vector(data):
    return compact_size(len(data)) + data


def push_number(number):
    if not 0 < number < 500_000_000:
        raise ValueError("refund must use a positive Bitcoin block height")
    if number <= 16:
        return bytes([0x50 + number])
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "little")
    if encoded[-1] & 0x80:
        encoded += b"\x00"
    return vector(encoded)


def witness_script(terms):
    btc = terms["bitcoin"]
    return (bytes.fromhex("6382012088a820") + bytes(terms["hashlock"])
            + bytes.fromhex("8821") + bytes(btc["claim_public_key"])
            + bytes.fromhex("ac67") + push_number(btc["refund_height"])
            + bytes.fromhex("b17521") + bytes(btc["refund_public_key"])
            + bytes.fromhex("ac68"))


def public_key(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.CompressedPoint)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def require_private_scratch(work):
    if any((parent / ".git").exists() for parent in (work, *work.parents)):
        raise ValueError("private keys and chain data must stay outside every Git checkout")


def prepare(args):
    work = args.work_dir.resolve()
    require_private_scratch(work)
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    if not 110 <= args.refund_height <= 1_000:
        raise ValueError("harness refund height must be between 110 and 1000")
    if not 1 <= args.confirmations <= 5:
        raise ValueError("harness confirmation depth must be between 1 and 5")
    if not 10_000 <= args.amount_sat <= 100_000_000:
        raise ValueError("harness amount must be between 10000 and 100000000 sat")
    claim = ec.generate_private_key(ec.SECP256K1())
    refund = ec.generate_private_key(ec.SECP256K1())
    secret = secrets.token_bytes(32)
    terms = {"hashlock": list(sha256(secret)), "bitcoin": {
        "amount_sat": args.amount_sat,
        "claim_public_key": list(public_key(claim)),
        "refund_public_key": list(public_key(refund)),
        "refund_height": args.refund_height,
        "required_confirmations": args.confirmations}}
    write_json(work / "private.json", {
        "claim_scalar_hex": format(claim.private_numbers().private_value, "064x"),
        "refund_scalar_hex": format(refund.private_numbers().private_value, "064x"),
        "secret_hex": secret.hex()})
    write_json(work / "public-terms.json", terms)
    print(json.dumps({"prepared": str(work), "public_terms": str(work / "public-terms.json")}))


def load_fixture(work, fixture_path):
    terms = json.loads((work / "public-terms.json").read_text())
    private_path = work / "private.json"
    if private_path.stat().st_mode & 0o077:
        raise ValueError("private.json must not be readable by group or other users")
    private = json.loads(private_path.read_text())
    claim = ec.derive_private_key(int(private["claim_scalar_hex"], 16), ec.SECP256K1())
    refund = ec.derive_private_key(int(private["refund_scalar_hex"], 16), ec.SECP256K1())
    secret = bytes.fromhex(private["secret_hex"])
    assert len(secret) == 32 and list(sha256(secret)) == terms["hashlock"]
    assert list(public_key(claim)) == terms["bitcoin"]["claim_public_key"]
    assert list(public_key(refund)) == terms["bitcoin"]["refund_public_key"]
    script = witness_script(terms)
    binding = {"wallet_fixture_checked": False}
    if fixture_path:
        raw = fixture_path.read_bytes()
        fixture = json.loads(raw)
        offer = fixture["offer"]
        assert offer["hashlock"] == terms["hashlock"], "wallet hashlock differs"
        assert offer["bitcoin"] == terms["bitcoin"], "wallet Bitcoin terms differ"
        assert bytes.fromhex(fixture["witness_script_hex"]) == script, "wallet script differs"
        assert bytes.fromhex(fixture["script_pubkey_hex"]) == b"\x00\x20" + sha256(script)
        binding = {"wallet_fixture_checked": True, "fixture_sha256": sha256(raw).hex(),
                   "offer_id_hex": fixture.get("offer_id_hex")}
    return terms, claim, refund, secret, script, binding


class RpcError(Exception):
    def __init__(self, error):
        self.error = error
        super().__init__(str(error))


class Core:
    def __init__(self, binary, work, core):
        self.binary = binary.resolve()
        self.work = work
        self.datadir = work / "chain"
        self.datadir.mkdir(mode=0o700)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.core = core
        self.process = None
        self.log = None

    def start(self):
        def limit_resources():
            resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
            if hasattr(os, "sched_setaffinity"):
                os.sched_setaffinity(0, {self.core})

        self.log = (self.work / "bitcoind-console.log").open("ab")
        self.process = subprocess.Popen([
            str(self.binary), "-regtest", "-server=1", "-daemon=0",
            f"-datadir={self.datadir}", "-listen=0", "-networkactive=0",
            "-dnsseed=0", "-discover=0", "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1", f"-rpcport={self.port}",
            "-dbcache=32", "-maxmempool=16", "-par=1", "-rpcthreads=1", "-txindex=1",
            "-fallbackfee=0.00001", "-persistmempool=1", "-printtoconsole=1"],
            stdout=self.log, stderr=subprocess.STDOUT, preexec_fn=limit_resources,
            env={**os.environ, "MALLOC_ARENA_MAX": "2"})
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("bitcoind exited; inspect task-local bitcoind-console.log")
            try:
                self.rpc("getblockchaininfo")
                return
            except (OSError, RpcError):
                time.sleep(0.1)
        raise TimeoutError("bitcoind RPC did not become ready")

    def rpc(self, method, *params, wallet=False):
        cookie = (self.datadir / "regtest" / ".cookie").read_text().strip()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}" + ("/wallet/funder" if wallet else "/"),
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                             "params": list(params)}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()})
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        data = json.loads(response.read())
        if data.get("error") is not None:
            raise RpcError(data["error"])
        return data["result"]

    def stop(self, crash=False):
        if self.process is not None and self.process.poll() is None:
            if crash:
                self.process.kill()
            else:
                try:
                    self.rpc("stop")
                except (OSError, RpcError):
                    self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()
        self.process = None


def spend(txid, vout, amount, script, destination, key, secret=None, locktime=0):
    """One-input/one-output BIP143 SIGHASH_ALL native-segwit transaction."""
    outpoint = bytes.fromhex(txid)[::-1] + struct.pack("<I", vout)
    sequence = struct.pack("<I", 0xFFFFFFFE)
    output = struct.pack("<Q", amount - 1_000) + vector(destination)
    version = struct.pack("<I", 2)
    lock_bytes = struct.pack("<I", locktime)
    digest = hash256(version + hash256(outpoint) + hash256(sequence) + outpoint
                     + vector(script) + struct.pack("<Q", amount) + sequence
                     + hash256(output) + lock_bytes + struct.pack("<I", 1))
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(signature)
    signature = utils.encode_dss_signature(r, min(s, CURVE_ORDER - s)) + b"\x01"
    witness = [signature, secret, b"\x01", script] if secret is not None else [signature, b"", script]
    vin = b"\x01" + outpoint + b"\x00" + sequence
    outputs = b"\x01" + output
    witness_bytes = compact_size(len(witness)) + b"".join(vector(item) for item in witness)
    raw = version + b"\x00\x01" + vin + outputs + witness_bytes + lock_bytes
    txid = hash256(version + vin + outputs + lock_bytes)[::-1].hex()
    return raw.hex(), txid


def test_accept(core, raw, expected, label, records):
    result = core.rpc("testmempoolaccept", [raw])[0]
    if result.get("allowed") is not expected:
        raise AssertionError(f"{label}: unexpected Core result {result}")
    records[label] = result
    return result


def require_confirmed_lock(core, outpoint, amount, script_pubkey, depth):
    output = core.rpc("gettxout", *outpoint)
    if (output is None or output["confirmations"] < depth
            or round(output["value"] * 100_000_000) != amount
            or output["scriptPubKey"]["hex"] != script_pubkey.hex()):
        raise ValueError("expected unspent Bitcoin lock lacks the required confirmation depth")
    return output


def run(args):
    started = time.monotonic()
    work = args.work_dir.resolve()
    require_private_scratch(work)
    if args.receipt.exists():
        raise ValueError("receipt path already exists; preserve it and use a fresh run")
    terms, claim_key, refund_key, secret, script, binding = load_fixture(work, args.wallet_fixture)
    btc = terms["bitcoin"]
    depth = btc["required_confirmations"]
    deadline = btc["refund_height"]
    if deadline <= 101 + 3 * depth + 2 or deadline > 1_000:
        raise ValueError("refund height leaves insufficient room for the regtest scenario")
    script_pubkey = b"\x00\x20" + sha256(script)
    receipt = {"schema": "hegemon-bitcoin-regtest-htlc-v1", "status": "incomplete",
               "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "harness_sha256": sha256(Path(__file__).read_bytes()).hex(),
               "bitcoind_sha256": sha256(args.bitcoind.read_bytes()).hex(),
               "scope": "bitcoin-regtest-only", "hegemon_leg_executed": False,
               "mainnet_or_production_authority": False, "public_terms": terms,
               "witness_script_hex": script.hex(), "script_pubkey_hex": script_pubkey.hex(),
               "wallet_binding": binding, "validation": {}, "transactions": {},
               "process_limits": {"cpu_core": args.cpu, "address_space_bytes": 1024 ** 3,
                                  "rpc_loopback_only": True, "p2p_listening": False}}
    if args.release_receipt:
        receipt["bitcoin_release"] = json.loads(args.release_receipt.read_text())
    core = Core(args.bitcoind, work, args.cpu)
    try:
        core.start()
        info = core.rpc("getnetworkinfo")
        assert info["networkactive"] is False
        receipt["core_version"] = info["version"]
        receipt["core_subversion"] = info["subversion"]
        assert core.rpc("getblockchaininfo")["chain"] == "regtest"
        core.rpc("createwallet", "funder")
        miner = core.rpc("getnewaddress", "", "bech32", wallet=True)
        core.rpc("generatetoaddress", 101, miner)
        decoded_script = core.rpc("decodescript", script.hex())
        lock_address = decoded_script["segwit"]["address"]
        assert core.rpc("validateaddress", lock_address)["scriptPubKey"] == script_pubkey.hex()
        payout = core.rpc("getnewaddress", "", "bech32", wallet=True)
        payout_script = bytes.fromhex(core.rpc("validateaddress", payout)["scriptPubKey"])
        locks = []
        for name in ("claim_lock", "refund_lock"):
            txid = core.rpc("sendtoaddress", lock_address, btc["amount_sat"] / 100_000_000, wallet=True)
            tx = core.rpc("getrawtransaction", txid, True)
            candidates = [item for item in tx["vout"] if item["scriptPubKey"]["hex"] == script_pubkey.hex()]
            assert len(candidates) == 1
            output = candidates[0]
            assert round(output["value"] * 100_000_000) == btc["amount_sat"]
            locks.append((txid, output["n"]))
            receipt["transactions"][name] = {"txid": txid, "vout": output["n"]}
        try:
            require_confirmed_lock(core, locks[0], btc["amount_sat"], script_pubkey, depth)
        except ValueError:
            pass
        else:
            raise AssertionError("unconfirmed lock incorrectly passed the reveal gate")
        receipt["validation"]["reveal_before_lock_depth_blocked"] = True
        core.rpc("generatetoaddress", depth, miner)
        for outpoint in locks:
            require_confirmed_lock(core, outpoint, btc["amount_sat"], script_pubkey, depth)
        receipt["lock_confirmed_at_height"] = core.rpc("getblockcount")
        receipt["required_lock_confirmations"] = depth
        # In this offline regtest, no peer can resend blocks after a crash. First
        # establish a durable confirmed-lock checkpoint; the abrupt crash below
        # then targets uncertain claim submission, not unflushed mined blocks.
        checkpoint_hash = core.rpc("getbestblockhash")
        core.stop()
        core.start()
        assert core.rpc("getbestblockhash") == checkpoint_hash
        for outpoint in locks:
            require_confirmed_lock(core, outpoint, btc["amount_sat"], script_pubkey, depth)
        receipt["validation"]["durable_lock_checkpoint_before_submission_crash"] = True
        validation = receipt["validation"]
        bad_secret = bytes([secret[0] ^ 1]) + secret[1:]
        wrong_key = ec.generate_private_key(ec.SECP256K1())
        for label, key, value in (("wrong_preimage", claim_key, bad_secret),
                                  ("wrong_claim_authority", wrong_key, secret),
                                  ("wrong_preimage_length", claim_key, secret[:31])):
            raw, _ = spend(*locks[0], btc["amount_sat"], script, payout_script, key, value)
            test_accept(core, raw, False, label, validation)
        refund_raw, refund_id = spend(*locks[1], btc["amount_sat"], script, payout_script,
                                     refund_key, locktime=deadline)
        test_accept(core, refund_raw, False, "early_refund", validation)
        claim_raw, claim_id = spend(*locks[0], btc["amount_sat"], script, payout_script,
                                   claim_key, secret)
        # Persist exact signed bytes before attempting submission, so an uncertain
        # result can be recovered by txid without re-signing or changing the spend.
        write_json(work / "submitted-transactions.json", {"claim": claim_raw, "refund": refund_raw})
        test_accept(core, claim_raw, True, "valid_claim", validation)
        assert core.rpc("sendrawtransaction", claim_raw) == claim_id
        receipt["transactions"]["claim"] = {"txid": claim_id, "raw_sha256": sha256(bytes.fromhex(claim_raw)).hex()}
        core.stop(crash=True)
        core.start()
        recovered_from_mempool = claim_id in core.rpc("getrawmempool")
        if not recovered_from_mempool:
            test_accept(core, claim_raw, True, "restart_exact_claim_resubmission", validation)
            assert core.rpc("sendrawtransaction", claim_raw) == claim_id
        validation["abrupt_restart"] = {"claim_in_recovered_mempool": recovered_from_mempool,
                                        "exact_transaction_recovered": True}
        core.rpc("generatetoaddress", depth, miner)
        claim_tx = core.rpc("getrawtransaction", claim_id, True)
        assert claim_tx["confirmations"] >= depth and claim_tx["txid"] == claim_id
        witness = claim_tx["vin"][0]["txinwitness"]
        assert len(witness) == 4 and witness[2] == "01" and witness[3] == script.hex()
        recovered_secret = bytes.fromhex(witness[1])
        assert recovered_secret == secret and sha256(recovered_secret) == bytes(terms["hashlock"])
        validation["confirmed_preimage_recovery"] = {"txid": claim_id,
            "confirmations": claim_tx["confirmations"], "preimage_bytes": len(recovered_secret),
            "preimage_sha256": sha256(recovered_secret).hex(), "exact_match": True}
        write_json(work / "recovered-secret.json", {"secret_hex": recovered_secret.hex(),
            "source_claim_txid": claim_id, "confirmations": claim_tx["confirmations"]})
        # This is a newly signed conflicting spend, so rejection is about the
        # consumed output rather than an already-confirmed transaction id.
        conflict_destination = bytes.fromhex(core.rpc("validateaddress", miner)["scriptPubKey"])
        conflicting, _ = spend(*locks[0], btc["amount_sat"], script, conflict_destination, claim_key, secret)
        test_accept(core, conflicting, False, "spent_output_double_spend", validation)
        tip = core.rpc("getblockcount")
        assert tip < deadline
        core.rpc("generatetoaddress", deadline - tip - 1, miner)
        assert core.rpc("getblockcount") == deadline - 1
        test_accept(core, refund_raw, False, "refund_one_block_before_boundary", validation)
        core.rpc("generatetoaddress", 1, miner)
        assert core.rpc("getblockcount") == deadline
        wrong_refund, _ = spend(*locks[1], btc["amount_sat"], script, payout_script,
                                wrong_key, locktime=deadline)
        test_accept(core, wrong_refund, False, "wrong_refund_authority", validation)
        test_accept(core, refund_raw, True, "mature_refund", validation)
        assert core.rpc("sendrawtransaction", refund_raw) == refund_id
        core.rpc("generatetoaddress", depth, miner)
        refund_tx = core.rpc("getrawtransaction", refund_id, True)
        assert refund_tx["confirmations"] >= depth
        assert core.rpc("gettxout", *locks[0]) is None and core.rpc("gettxout", *locks[1]) is None
        receipt["transactions"]["refund"] = {"txid": refund_id,
            "raw_sha256": sha256(bytes.fromhex(refund_raw)).hex(), "locktime": deadline,
            "confirmations": refund_tx["confirmations"]}
        final_hash = core.rpc("getbestblockhash")
        final_height = core.rpc("getblockcount")
        core.stop()
        core.start()
        assert core.rpc("getbestblockhash") == final_hash
        assert core.rpc("getrawtransaction", claim_id, True)["confirmations"] >= depth
        assert core.rpc("getrawtransaction", refund_id, True)["confirmations"] >= depth
        assert core.rpc("gettxout", *locks[0]) is None and core.rpc("gettxout", *locks[1]) is None
        validation["confirmed_state_after_clean_restart"] = True
        receipt["final_height"] = final_height
        receipt["final_block_hash"] = final_hash
        receipt["status"] = "passed"
    finally:
        core.stop()
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        receipt["bitcoind_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        write_json(args.receipt, receipt)
    print(json.dumps({"status": receipt["status"], "receipt": str(args.receipt),
                      "wallet_fixture_checked": binding["wallet_fixture_checked"]}))


def main():
    if not __debug__:
        raise RuntimeError("run without -O: assertion checks are required for this validation harness")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare", help="create private keys and public terms in fresh scratch")
    preparation.add_argument("--work-dir", type=Path, required=True)
    preparation.add_argument("--refund-height", type=int, default=120)
    preparation.add_argument("--amount-sat", type=int, default=1_000_000)
    preparation.add_argument("--confirmations", type=int, default=2)
    preparation.set_defaults(function=prepare)
    runner = commands.add_parser("run", help="run actual Core against a previously prepared scratch directory")
    runner.add_argument("--work-dir", type=Path, required=True)
    runner.add_argument("--bitcoind", type=Path, required=True)
    runner.add_argument("--receipt", type=Path, required=True)
    runner.add_argument("--wallet-fixture", type=Path)
    runner.add_argument("--release-receipt", type=Path)
    runner.add_argument("--cpu", type=int, default=0)
    runner.set_defaults(function=run)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
