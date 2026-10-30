#!/usr/bin/env python3
"""Fresh local Hegemon Development chain plus Bitcoin Core regtest HTLC swaps.

Each scenario starts from new chains and new wallets. Nothing here is production
authority, and the Hegemon node is started with an empty seed list so it does not
join a shared network. Bitcoin Core is regtest only: no peers and no mainnet sync.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from htlc_swap_lib import (
    BitcoinRPC,
    EASY_POW_BITS,
    RehearsalError,
    btc_amount,
    btc_height,
    confirmed_bitcoin_preimage,
    descriptor_checksum,
    hgn_action,
    hgn_height,
    hgn_mine_to,
    hgn_status,
    htlc_capable_manifest,
    last_json,
    party_bitcoin_descriptors,
    plan_swap_deadlines,
    rehearsal_bitcoin_key,
    require_bitcoin_receive,
    require_cli_rejection,
    require_exact_owned_note,
    require_fresh_directory,
    require_loopback_http,
    require_rejected_contract_spend,
    rpc_call,
    run_wallet_cli,
    spend_contract,
    timeout_margin_holds,
    wait_bitcoin_confirmations,
    write_private,
)

REPO = Path(__file__).resolve().parents[1]
FETCH_CORE = REPO / "experimental/htlc-prototype/bitcoin-regtest/fetch_core.sh"
CONTEXT_WRITER = REPO / "scripts/development_wallet_context.py"
DEFAULT_CACHE = Path.home() / ".cache/hegemon/bitcoin-core-31.1"
CORE_VERSION = "31.1"
CORE_ARCHIVE_SHA256 = "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
CORE_FINGERPRINT = "E777299FC265DD04793070EB944D35F9AC3DB76A"
SCENARIOS = ("happy", "no_btc", "both_refund", "late_claim")
MAX_BLOCKS = 10_000
MINE_TIMEOUT = 1800
# Local regtest assumptions for HtlcOffer::check_timeout_margin. Hegemon keeps
# its 60s target spacing. Bitcoin blocks are produced by generatetoaddress, so
# they are modeled as 1s, with 200s of safety. The resulting Hegemon timeout is
# only a few blocks ahead: this chain retargets every 10 blocks and a fast mine
# of hundreds of blocks would become unsolvable. Hegemon's remaining time is
# still strictly longer than Bitcoin's.
LOCAL_HGN_BLOCK_SECONDS = 60
LOCAL_BTC_BLOCK_SECONDS = 1
LOCAL_SAFETY_SECONDS = 200
FEE = 1
MAXIMUM_FEE = 10
BTC_AMOUNT = 100_000
BTC_FEE = 500


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def node_env(miner: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("HEGEMON_")}
    env.update(
        HEGEMON_MINER_ADDRESS=miner,
        HEGEMON_SEEDS="",
        HEGEMON_MINE="0",
        HEGEMON_BOOTSTRAP_AUTHORING="1",
        RAYON_NUM_THREADS="2",
        RUST_LOG="warn",
    )
    return env


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        proc.wait(timeout=10)


def wallet_json(binary: Path, args: list[str], passfiles: list[Path], approve: bool = False) -> dict:
    return last_json(run_wallet_cli(binary, args, passfiles, approve=approve))


def build_binaries() -> dict[str, Path]:
    common = ["cargo", "build", "--release", "--manifest-path", str(REPO / "Cargo.toml")]
    log("building hegemon-node")
    subprocess.check_call(
        [*common, "-p", "hegemon-node", "--features",
         "development-candidate,poseidon2-v8-retained-test-support", "--bin", "hegemon-node"],
        cwd=REPO,
    )
    log("building launch wallet examples")
    subprocess.check_call(
        [*common, "-p", "wallet", "--features", "poseidon2-v8-retained-test-support",
         "--example", "launch_wallet_prepare", "--example", "htlc_public_fixture"],
        cwd=REPO,
    )
    return locate_binaries()


def cargo_release_dirs() -> list[Path]:
    dirs = []
    override = os.environ.get("CARGO_TARGET_DIR")
    if override:
        dirs.append(Path(override) / "release")
    dirs.append(REPO / "target/release")
    return dirs


def locate_binaries() -> dict[str, Path]:
    names = {
        "node": "hegemon-node",
        "wallet": "examples/launch_wallet_prepare",
        "fixture": "examples/htlc_public_fixture",
    }
    binaries = {}
    for key, relative in names.items():
        found = next((directory / relative for directory in cargo_release_dirs()
                      if (directory / relative).is_file()), None)
        binaries[key] = found or (cargo_release_dirs()[0] / relative)
    for name, path in binaries.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RehearsalError(f"missing executable {name}: {path}")
    return binaries


def core_verified(cache: Path) -> bool:
    bitcoind = cache / f"bitcoin-{CORE_VERSION}/bin/bitcoind"
    cli = cache / f"bitcoin-{CORE_VERSION}/bin/bitcoin-cli"
    receipt_path = cache / "release-verification.json"
    if not (bitcoind.is_file() and cli.is_file() and receipt_path.is_file()):
        return False
    receipt = json.loads(receipt_path.read_text())
    return (receipt.get("version") == CORE_VERSION
            and receipt.get("archive_sha256") == CORE_ARCHIVE_SHA256
            and receipt.get("valid_signature_primary_fingerprint") == CORE_FINGERPRINT
            and receipt.get("sha256_manifest_verified") is True)


def ensure_bitcoin_core(cache: Path) -> tuple[Path, Path]:
    if core_verified(cache):
        root = cache / f"bitcoin-{CORE_VERSION}/bin"
        return root / "bitcoind", root / "bitcoin-cli"
    cache.parent.mkdir(parents=True, exist_ok=True)
    # fetch_core.sh creates dest itself and refuses an existing directory.
    staging = cache.parent / f".bitcoin-core-fetch-{os.getpid()}"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        log(f"fetching verified Bitcoin Core {CORE_VERSION} into {cache}")
        subprocess.check_call(["bash", str(FETCH_CORE), str(staging)])
        if cache.exists():
            shutil.rmtree(cache)
        staging.rename(cache)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if not core_verified(cache):
        raise RehearsalError("fetched Bitcoin Core failed the pinned verification receipt")
    root = cache / f"bitcoin-{CORE_VERSION}/bin"
    return root / "bitcoind", root / "bitcoin-cli"


def wait_node(url: str, proc: subprocess.Popen, log_path: Path) -> None:
    require_loopback_http(url)
    deadline = time.monotonic() + 180
    last = "node has not answered yet"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = log_path.read_text(errors="replace")[-2000:]
            raise RehearsalError(f"Hegemon node exited early: {tail}")
        try:
            rpc_call(url, "system_health")
            return
        except (RehearsalError, OSError, TimeoutError) as error:
            last = str(error)
            time.sleep(0.25)
    raise RehearsalError(f"Hegemon node RPC did not become ready: {last}")


def import_private_descriptor(btc: BitcoinRPC, wallet: str, descriptor: str) -> None:
    body = descriptor + "#" + descriptor_checksum(descriptor)
    imported = btc.call(
        "importdescriptors",
        [{"desc": body, "timestamp": "now", "active": False}],
        wallet=wallet,
        sensitive=True,
    )
    if not imported or not imported[0].get("success"):
        raise RehearsalError(f"Bitcoin Core could not import a private descriptor into {wallet}")


def start_bitcoind(bitcoind: Path, root: Path, port: int) -> tuple[subprocess.Popen, BitcoinRPC, str]:
    datadir = root / "bitcoin-regtest"
    datadir.mkdir(mode=0o700)
    proc = subprocess.Popen(
        [str(bitcoind), "-regtest", f"-datadir={datadir}", "-server=1", "-listen=0", "-connect=0",
         "-discover=0", "-dnsseed=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
         "-fallbackfee=0.0002", f"-rpcport={port}", "-printtoconsole=0"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    endpoint = f"http://127.0.0.1:{port}"
    cookie = datadir / "regtest" / ".cookie"
    btc = None
    for _ in range(200):
        if proc.poll() is not None:
            raise RehearsalError("Bitcoin Core exited before regtest RPC became ready")
        if cookie.exists():
            try:
                candidate = BitcoinRPC(endpoint, cookie)
                if candidate.call("getblockchaininfo")["chain"] == "regtest":
                    btc = candidate
                    break
            except Exception:
                pass
        time.sleep(0.1)
    if btc is None:
        raise RehearsalError("Bitcoin Core regtest RPC did not become ready")
    if btc.call("getpeerinfo"):
        raise RehearsalError("private regtest unexpectedly has external peers")
    return proc, btc, endpoint


def fresh_wallet(wallet_cli: Path, store: Path, passfile: Path) -> str:
    phrase = os.urandom(24).hex()
    write_private(passfile, (phrase + "\n").encode())
    created = wallet_json(wallet_cli, ["offline-address", "--store", str(store)], [passfile])
    if not created.get("created") or not isinstance(created.get("address"), str):
        raise RehearsalError("offline wallet did not return a new V8 address")
    reopened = wallet_json(wallet_cli, ["offline-address", "--store", str(store)], [passfile])
    if reopened.get("address") != created["address"] or reopened.get("created") is not False:
        raise RehearsalError("reopened wallet V8 address differs from the address just created")
    return created["address"]


def select_lock_note(status: dict) -> tuple[int, int]:
    notes = [note for note in status.get("ordinary_native_notes", [])
             if isinstance(note.get("native_value_base_units"), int)
             and note["native_value_base_units"] > FEE
             and isinstance(note.get("position"), int)]
    if not notes:
        raise RehearsalError("Alice has no mature spendable Hegemon note to lock")
    note = notes[0]
    return note["position"], note["native_value_base_units"] - FEE


def fund_contract(btc: BitcoinRPC, bob_address: str, contract_address: str, script_pubkey: bytes,
                  amount_sat: int) -> tuple[str, int]:
    funding_tx = btc.call(
        "sendtoaddress", contract_address, btc_amount(amount_sat), wallet="bob")
    btc.call("generatetoaddress", 1, bob_address)
    funding = btc.call("gettransaction", funding_tx, wallet="bob")
    raw = btc.call("getrawtransaction", funding_tx, True, funding["blockhash"])
    vout = next(item["n"] for item in raw["vout"] if item["scriptPubKey"]["hex"] == script_pubkey.hex())
    if btc.call("gettxout", funding_tx, vout, True) is None:
        raise RehearsalError("Bitcoin contract output is not an actual unspent chain output")
    return funding_tx, vout


def run_scenario(binaries: dict[str, Path], bitcoind: Path, scenario: str, root: Path) -> dict:
    require_fresh_directory(root)
    wallet_cli = binaries["wallet"]
    alice_store, bob_store, treasury_store = (root / name for name in ("alice.store", "bob.store", "treasury.store"))
    alice_pass, bob_pass, treasury_pass = (root / name for name in ("alice.pass", "bob.pass", "treasury.pass"))
    log(f"{scenario}: creating fresh wallets")
    alice = fresh_wallet(wallet_cli, alice_store, alice_pass)
    bob = fresh_wallet(wallet_cli, bob_store, bob_pass)
    treasury = fresh_wallet(wallet_cli, treasury_store, treasury_pass)
    if len({alice, bob, treasury}) != 3:
        raise RehearsalError("fresh wallets did not produce distinct V8 addresses")

    printed = json.loads(subprocess.check_output(
        [str(binaries["node"]), "--print-development-candidate-manifest",
         "--development-funding-address", treasury],
        cwd=REPO, timeout=120,
    ))
    manifest = htlc_capable_manifest(printed)
    if manifest.get("pow_bits") != EASY_POW_BITS:
        raise RehearsalError("Development manifest did not receive the local easy PoW target")
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    rpc_port, p2p_port, btc_port = free_port(), free_port(), free_port()
    rpc = f"http://127.0.0.1:{rpc_port}"
    require_loopback_http(rpc)
    node_log = root / "hegemon-node.log"
    log_handle = node_log.open("wb", buffering=0)
    node = subprocess.Popen(
        [str(binaries["node"]), "--dev", "--network", "development",
         "--network-manifest", str(manifest_path), "--development-candidate",
         "--base-path", str(root / "hegemon"), "--rpc-port", str(rpc_port),
         "--rpc-methods", "unsafe", "--listen-addr", f"127.0.0.1:{p2p_port}",
         "--port", str(p2p_port), "--name", f"htlc-e2e-{scenario}"],
        stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
        env=node_env(alice), start_new_session=True, cwd=REPO,
    )
    bitcoin = None
    receipt: dict = {
        "schema": "hegemon-local-htlc-swap-e2e-v1",
        "scenario": scenario,
        "production_authorized": False,
        "hegemon_seeds": "",
        "bitcoin_chain": "regtest",
        "roles": {
            "alice_hegemon": "miner_and_refund",
            "bob_hegemon": "claim",
            "alice_bitcoin": "claim_with_secret",
            "bob_bitcoin": "refund_after_timeout",
        },
    }
    try:
        wait_node(rpc, node, node_log)
        config = rpc_call(rpc, "hegemon_nodeConfig")
        if config.get("networkProfile") != "development" or config.get("networkManifest") != manifest:
            raise RehearsalError("node is not running the fresh HTLC Development manifest")
        if rpc_call(rpc, "hegemon_privateSpendParameters").get("production_authorized") is not False:
            raise RehearsalError("Development node advertised production authority")
        context_path = root / "context.json"
        subprocess.check_call([sys.executable, str(CONTEXT_WRITER), "--rpc", rpc, "--out", str(context_path)])
        context = json.loads(context_path.read_text())
        for store, passfile in ((alice_store, alice_pass), (bob_store, bob_pass), (treasury_store, treasury_pass)):
            wallet_json(wallet_cli, ["init", "--store", str(store), "--context", str(context_path),
                                     "--rpc", rpc, "--retained-test"], [passfile])
        log(f"{scenario}: mining Hegemon reward to maturity")
        hgn_mine_to(rpc, 121, MINE_TIMEOUT)
        alice_status = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, max_blocks=MAX_BLOCKS)
        if not alice_status.get("ordinary_native_notes"):
            hgn_mine_to(rpc, hgn_height(rpc) + 1, MINE_TIMEOUT)
            alice_status = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, max_blocks=MAX_BLOCKS)
        position, value = select_lock_note(alice_status)
        receipt["hegemon_lock_input"] = {"position": position, "value_base_units": value + FEE, "fee": FEE}

        log(f"{scenario}: starting fresh Bitcoin regtest")
        bitcoin, btc, _endpoint = start_bitcoind(bitcoind, root, btc_port)
        for name in ("alice", "bob"):
            btc.call("createwallet", name, False, False, "", False, True)
        alice_pub, alice_wif = rehearsal_bitcoin_key()
        bob_pub, bob_wif = rehearsal_bitcoin_key()
        import_private_descriptor(btc, "alice", f"wpkh({alice_wif})")
        import_private_descriptor(btc, "bob", f"wpkh({bob_wif})")
        bob_address = btc.call("getnewaddress", "bob-coins", "bech32", wallet="bob")
        btc.call("generatetoaddress", 101, bob_address)
        timeout_height, refund_height = plan_swap_deadlines(
            hgn_height(rpc), btc_height(btc), context["deactivation_height_exclusive"],
            hegemon_block_seconds=LOCAL_HGN_BLOCK_SECONDS,
            bitcoin_block_seconds=LOCAL_BTC_BLOCK_SECONDS,
            safety_seconds=LOCAL_SAFETY_SECONDS)
        if timeout_height - hgn_height(rpc) > 20:
            raise RehearsalError("HTLC timeout is too far ahead for this chain's 10-block retarget")
        if not timeout_margin_holds(
            hgn_height(rpc), btc_height(btc), timeout_height, refund_height,
            LOCAL_HGN_BLOCK_SECONDS, LOCAL_BTC_BLOCK_SECONDS, LOCAL_SAFETY_SECONDS,
        ):
            raise RehearsalError("planned HTLC timeouts violate the cross-chain margin")
        secret = bytearray(os.urandom(32))
        secret_path = root / "preimage.bin"
        write_private(secret_path, bytes(secret))
        hashlock = hashlib.sha256(secret).hexdigest()
        offer_path = root / "offer.json"
        offer_info = wallet_json(wallet_cli, [
            "htlc", "offer-create", "--context", str(context_path),
            "--claim-store", str(bob_store), "--refund-store", str(alice_store),
            "--hashlock", "0x" + hashlock, "--value", str(value), "--maximum-fee", str(MAXIMUM_FEE),
            "--timeout-height", str(timeout_height), "--bitcoin-amount-sat", str(BTC_AMOUNT),
            "--bitcoin-claim-public-key", "0x" + alice_pub, "--bitcoin-refund-public-key", "0x" + bob_pub,
            "--bitcoin-refund-height", str(refund_height), "--bitcoin-required-confirmations", "1",
            "--out", str(offer_path), "--retained-test",
        ], [bob_pass, alice_pass])
        offer = json.loads(offer_path.read_text())
        if offer_info["claim_address"] != bob or offer_info["refund_address"] != alice:
            raise RehearsalError("offer parties are not Bob-claims-HGN and Alice-refunds-HGN")
        swap_id = offer_info["swap_id"]
        bitcoin_terms = offer["bitcoin"]
        terms_path = root / "terms.json"
        write_private(terms_path, json.dumps({
            "hashlock": list(bytes.fromhex(hashlock)),
            "bitcoin": bitcoin_terms,
        }).encode())
        fixture = json.loads(subprocess.check_output([str(binaries["fixture"]), str(terms_path)], timeout=60))
        witness_script = bytes.fromhex(fixture["witness_script_hex"])
        script_pubkey = bytes.fromhex(fixture["script_pubkey_hex"])
        decoded = btc.call("decodescript", witness_script.hex())
        contract_address = decoded["segwit"]["address"]
        if decoded["segwit"].get("hex") != script_pubkey.hex():
            raise RehearsalError("Bitcoin Core decoded a different witness program than the wallet fixture")
        descriptors = party_bitcoin_descriptors(hashlock, alice_pub, alice_wif, bob_pub, bob_wif, refund_height)
        if alice_wif in descriptors["bob"] or bob_wif in descriptors["alice"]:
            raise RehearsalError("a party descriptor contains the counterparty's private key")
        public = btc.call("getdescriptorinfo", descriptors["public"])["descriptor"]
        if btc.call("deriveaddresses", public)[0] != contract_address:
            raise RehearsalError("Bitcoin Core public miniscript does not match the wallet witness script")
        import_private_descriptor(btc, "alice", descriptors["alice"])
        import_private_descriptor(btc, "bob", descriptors["bob"])
        receipt["deadlines"] = {"hegemon_timeout_height": timeout_height, "bitcoin_refund_height": refund_height}

        funded = scenario != "no_btc"
        funding_tx = vout = None
        if funded:
            funding_tx, vout = fund_contract(btc, bob_address, contract_address, script_pubkey, BTC_AMOUNT)
            receipt["bitcoin_contract"] = {"funding_txid": funding_tx, "contract_address": contract_address}
            if not timeout_margin_holds(
                hgn_height(rpc), btc_height(btc), timeout_height, refund_height,
                LOCAL_HGN_BLOCK_SECONDS, LOCAL_BTC_BLOCK_SECONDS, LOCAL_SAFETY_SECONDS,
            ):
                raise RehearsalError("funding confirmations consumed the HTLC timeout margin")
        else:
            receipt["bitcoin_contract"] = {"funded": False, "bitcoin_height": btc_height(btc)}

        for store, passfile in ((bob_store, bob_pass), (alice_store, alice_pass)):
            wallet_json(wallet_cli, ["htlc", "offer-accept", "--store", str(store), "--context", str(context_path),
                                     "--rpc", rpc, "--retained-test", "--offer", str(offer_path)], [passfile])
        agreement = root / "agreement.bin"
        wallet_json(wallet_cli, ["htlc", "agreement-create", "--store", str(alice_store), "--context", str(context_path),
                                 "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--to", bob], [alice_pass])
        wallet_json(wallet_cli, ["htlc", "agreement-export", "--store", str(alice_store), "--context", str(context_path),
                                 "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--to", bob,
                                 "--out", str(agreement)], [alice_pass])
        wallet_json(wallet_cli, ["htlc", "agreement-import", "--store", str(bob_store), "--context", str(context_path),
                                 "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--input", str(agreement),
                                 "--diversifier-index", "0"], [bob_pass])
        log(f"{scenario}: proving Hegemon lock")
        receipt["hegemon_lock"] = hgn_action(
            wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, "lock", position, bob,
            root, manifest_path, MAX_BLOCKS)

        def reject_early_hegemon_refund() -> None:
            before = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            locked = before["swaps"][0]["locked_note_positions"]
            if not locked:
                raise RehearsalError("Alice has no canonical locked-note occurrence")
            artifact = root / "premature-refund.json"
            require_cli_rejection(wallet_cli, [
                "htlc", "prepare-refund", "--store", str(alice_store), "--context", str(context_path),
                "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--input-position", str(locked[0]),
                "--fee", str(FEE), "--to", alice, "--out", str(artifact),
            ], [alice_pass], artifact, "premature Hegemon refund")
            after = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            if len(after["swaps"][0]["attempts"]) != len(before["swaps"][0]["attempts"]):
                raise RehearsalError("rejected premature refund created an accepted HTLC attempt")

        def refund_hegemon() -> None:
            if hgn_height(rpc) < timeout_height:
                hgn_mine_to(rpc, timeout_height, MINE_TIMEOUT)
            status = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            locked = status["swaps"][0]["locked_note_positions"]
            if not locked:
                raise RehearsalError("Alice has no canonical locked-note occurrence to refund")
            log(f"{scenario}: proving Hegemon refund")
            receipt["hegemon_refund"] = hgn_action(
                wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, "refund", locked[0], alice,
                root, manifest_path, MAX_BLOCKS)
            status = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            require_exact_owned_note(status, value - FEE, receipt["hegemon_refund"]["output_commitment"])
            receipt["hegemon_refund"]["returned_base_units"] = value - FEE

        def claim_bitcoin() -> bytes:
            assert funding_tx is not None and vout is not None
            destination = btc.call("getnewaddress", "alice-claim", "bech32", wallet="alice")
            preimage = bytes(secret_path.read_bytes())
            txid = spend_contract(
                btc, "alice", funding_tx, vout, BTC_AMOUNT, script_pubkey, witness_script,
                destination, 0xFFFFFFFF, 0, preimage)
            confirmed = wait_bitcoin_confirmations(btc, txid, "alice", 1, bob_address)
            revealed = confirmed_bitcoin_preimage(btc, txid, "alice", bytes.fromhex(hashlock))
            if revealed != preimage:
                raise RehearsalError("Bitcoin chain witness differs from Alice's secret")
            claim_block = confirmed["blockhash"]
            btc.call("invalidateblock", claim_block)
            try:
                confirmed_bitcoin_preimage(btc, txid, "alice", bytes.fromhex(hashlock))
            except RehearsalError:
                receipt.setdefault("bitcoin_claim", {})["orphan_witness_refused"] = True
            else:
                raise RehearsalError("orphaned Bitcoin claim witness was treated as confirmed")
            btc.call("reconsiderblock", claim_block)
            restored = wait_bitcoin_confirmations(btc, txid, "alice", 1, bob_address)
            revealed = confirmed_bitcoin_preimage(btc, txid, "alice", bytes.fromhex(hashlock))
            revealed_path = root / "revealed-on-bitcoin.bin"
            write_private(revealed_path, revealed)
            receipt["bitcoin_claim"] = {
                "txid": txid,
                "received_sat": BTC_AMOUNT - BTC_FEE,
                "confirmations": restored["confirmations"],
                "destination": require_bitcoin_receive(btc, txid, "alice", destination, BTC_AMOUNT - BTC_FEE),
                "orphan_witness_refused": True,
                "secret_source": "confirmed Bitcoin witness",
            }
            return revealed_path

        def refund_bitcoin() -> None:
            assert funding_tx is not None and vout is not None
            current = btc_height(btc)
            if current < refund_height:
                btc.call("generatetoaddress", refund_height - current, bob_address)
            destination = btc.call("getnewaddress", "bob-refund", "bech32", wallet="bob")
            txid = spend_contract(
                btc, "bob", funding_tx, vout, BTC_AMOUNT, script_pubkey, witness_script,
                destination, 0xFFFFFFFE, refund_height)
            confirmed = wait_bitcoin_confirmations(btc, txid, "bob", 1, bob_address)
            receipt["bitcoin_refund"] = {
                "txid": txid,
                "returned_sat": BTC_AMOUNT - BTC_FEE,
                "confirmations": confirmed["confirmations"],
                "destination": require_bitcoin_receive(btc, txid, "bob", destination, BTC_AMOUNT - BTC_FEE),
            }

        if scenario == "happy":
            invalid = os.urandom(32)
            while hashlib.sha256(invalid).hexdigest() == hashlock:
                invalid = os.urandom(32)
            probe = btc.call("getnewaddress", "probe", "bech32", wallet="bob")
            require_rejected_contract_spend(
                btc, "alice", funding_tx, vout, BTC_AMOUNT, script_pubkey, witness_script, probe,
                0xFFFFFFFF, 0, invalid, "wrong_secret", receipt)
            require_rejected_contract_spend(
                btc, "bob", funding_tx, vout, BTC_AMOUNT, script_pubkey, witness_script, probe,
                0xFFFFFFFE, refund_height, None, "premature_refund", receipt)
            wrong_path = root / "wrong-preimage.bin"
            write_private(wrong_path, invalid)
            require_cli_rejection(wallet_cli, [
                "htlc", "secret-import", "--store", str(bob_store), "--context", str(context_path),
                "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--input", str(wrong_path),
            ], [bob_pass], root / "wrong-secret.json", "wrong Hegemon secret")
            reject_early_hegemon_refund()
            revealed_path = claim_bitcoin()
            wallet_json(wallet_cli, [
                "htlc", "secret-import", "--store", str(bob_store), "--context", str(context_path),
                "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--input", str(revealed_path),
            ], [bob_pass])
            bob_status = hgn_status(wallet_cli, bob_store, bob_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            locked = bob_status["swaps"][0]["locked_note_positions"]
            if not locked:
                raise RehearsalError("Bob has no canonical locked-note occurrence")
            log(f"{scenario}: proving Hegemon claim")
            receipt["hegemon_claim"] = hgn_action(
                wallet_cli, bob_store, bob_pass, context_path, rpc, swap_id, "claim", locked[0], bob,
                root, manifest_path, MAX_BLOCKS)
            bob_status = hgn_status(wallet_cli, bob_store, bob_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            require_exact_owned_note(bob_status, value - FEE, receipt["hegemon_claim"]["output_commitment"])
            receipt["hegemon_claim"]["received_base_units"] = value - FEE
            receipt["outcome"] = "Alice owns the Bitcoin output and Bob owns the Hegemon note"
        elif scenario == "no_btc":
            reject_early_hegemon_refund()
            refund_hegemon()
            receipt["outcome"] = "Bob never funded Bitcoin; Alice's Hegemon note returned after timeout"
        elif scenario == "both_refund":
            probe = btc.call("getnewaddress", "probe", "bech32", wallet="bob")
            require_rejected_contract_spend(
                btc, "bob", funding_tx, vout, BTC_AMOUNT, script_pubkey, witness_script, probe,
                0xFFFFFFFE, refund_height, None, "premature_refund", receipt)
            reject_early_hegemon_refund()
            refund_bitcoin()
            refund_hegemon()
            receipt["outcome"] = "neither party claimed; both assets returned after their own timeouts"
        elif scenario == "late_claim":
            revealed_path = claim_bitcoin()
            if hgn_height(rpc) < timeout_height:
                hgn_mine_to(rpc, timeout_height, MINE_TIMEOUT)
            alice_status = hgn_status(wallet_cli, alice_store, alice_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            locked = alice_status["swaps"][0]["locked_note_positions"]
            if not locked:
                raise RehearsalError("Alice has no locked note to refund ahead of Bob")
            saved_position = locked[0]
            refund_hegemon()
            wallet_json(wallet_cli, [
                "htlc", "secret-import", "--store", str(bob_store), "--context", str(context_path),
                "--rpc", rpc, "--retained-test", "--swap-id", swap_id, "--input", str(revealed_path),
            ], [bob_pass])
            before = hgn_status(wallet_cli, bob_store, bob_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            artifact = root / "late-claim.json"
            require_cli_rejection(wallet_cli, [
                "htlc", "prepare-claim", "--store", str(bob_store), "--context", str(context_path),
                "--rpc", rpc, "--retained-test", "--swap-id", swap_id,
                "--input-position", str(saved_position), "--fee", str(FEE), "--to", bob,
                "--out", str(artifact),
            ], [bob_pass], artifact, "late Hegemon claim after refund")
            after = hgn_status(wallet_cli, bob_store, bob_pass, context_path, rpc, swap_id, MAX_BLOCKS)
            if len(after["swaps"][0]["attempts"]) != len(before["swaps"][0]["attempts"]):
                raise RehearsalError("rejected late claim created an accepted HTLC attempt")
            receipt["late_claim_rejected"] = True
            receipt["outcome"] = "Alice took Bitcoin and, after the Hegemon timeout, refunded Hegemon; Bob's later claim was rejected"
        else:
            raise RehearsalError(f"unknown scenario {scenario}")
        for index in range(len(secret)):
            secret[index] = 0
        receipt["swap_id"] = swap_id
        receipt["status"] = "passed"
        return receipt
    finally:
        stop_process(bitcoin)
        stop_process(node)
        log_handle.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--bitcoin-core-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--keep", action="store_true", help="keep the scenario directory after success")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--work-root", type=Path, default=Path("/tmp/hegemon-htlc-e2e"))
    args = parser.parse_args()
    os.umask(0o077)
    binaries = locate_binaries() if args.no_build else build_binaries()
    bitcoind, _cli = ensure_bitcoin_core(args.bitcoin_core_dir)
    if args.work_root.is_symlink() or (args.work_root.exists() and not args.work_root.is_dir()):
        raise RehearsalError("work root must be a real directory")
    args.work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.work_root, 0o700)
    selected = SCENARIOS if args.scenario == "all" else (args.scenario,)
    summary = []
    failed = False
    for scenario in selected:
        root = args.work_root / scenario
        if root.exists():
            shutil.rmtree(root)
        started = time.monotonic()
        try:
            receipt = run_scenario(binaries, bitcoind, scenario, root)
        except (RehearsalError, subprocess.CalledProcessError, OSError, KeyError, TimeoutError) as error:
            failed = True
            receipt = {"schema": "hegemon-local-htlc-swap-e2e-v1", "scenario": scenario,
                       "status": "failed", "production_authorized": False, "error": str(error)[:500]}
            log(f"{scenario}: failed: {error}")
        else:
            log(f"{scenario}: passed")
            if not args.keep:
                shutil.rmtree(root, ignore_errors=True)
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary.append(receipt)
        if root.exists():
            (root / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "failed" if failed else "passed", "scenarios": summary}, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RehearsalError as error:
        print(f"local HTLC swap test stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
