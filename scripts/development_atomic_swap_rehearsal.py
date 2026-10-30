#!/usr/bin/env python3
"""Run a real two-chain HTLC rehearsal against local Bitcoin Core regtest and Hegemon RPC.

This orchestrator never fabricates balances or block observations. The Hegemon
wallet CLI prepares every carrier and submits through its durable journal. The
Bitcoin signatures are produced by Bitcoin Core's descriptor wallet. Private
inputs and the private Core datadir live only below the caller's mode-0700 root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

from htlc_swap_lib import (
    BitcoinRPC,
    RehearsalError,
    btc_height,
    confirmed_bitcoin_preimage,
    descriptor_checksum,
    hgn_action,
    hgn_height,
    hgn_mine_to,
    hgn_status,
    last_json,
    private_file,
    rehearsal_bitcoin_key,
    require_bitcoin_receive,
    require_cli_rejection,
    require_exact_owned_note,
    require_rejected_contract_spend,
    rpc_call,
    run_wallet_cli,
    spend_contract,
    wait_bitcoin_confirmations,
    wallet_common,
    write_private,
)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--bitcoin-cli", type=Path, required=True)
    parser.add_argument("--wallet-cli", type=Path, required=True)
    parser.add_argument("--public-fixture", type=Path, required=True)
    parser.add_argument("--hgn-rpc", required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--claim-store", type=Path, required=True)
    parser.add_argument("--refund-store", type=Path, required=True)
    parser.add_argument("--claim-passfile", type=Path, required=True)
    parser.add_argument("--refund-passfile", type=Path, required=True)
    parser.add_argument("--lock-input-position", type=int, required=True)
    parser.add_argument("--miner-address", required=True, help="Configured disposable Hegemon development miner address")
    parser.add_argument("--value", type=int, required=True, help="Hegemon base units; lock input must equal value plus fee")
    parser.add_argument("--timeout-height", type=int, required=True, help="Absolute Hegemon refund parent height")
    parser.add_argument("--bitcoin-amount-sat", type=int, default=100000)
    parser.add_argument("--bitcoin-refund-height", type=int, default=120)
    parser.add_argument("--private-root", type=Path, required=True, help="Must be a new or empty mode-0700 directory")
    parser.add_argument("--bitcoin-rpc-port", type=int, default=18443)
    parser.add_argument("--scenario", choices=("claim", "timeout"), required=True)
    args = parser.parse_args()
    for path in (args.bitcoind, args.bitcoin_cli, args.wallet_cli, args.public_fixture):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RehearsalError(f"required executable is not executable: {path}")
    for path in (args.claim_passfile, args.refund_passfile):
        private_file(path, 4096)
    if args.private_root.exists():
        if args.private_root.is_symlink() or not args.private_root.is_dir():
            raise RehearsalError("private root must be a real directory, never a symlink")
        if any(args.private_root.iterdir()):
            raise RehearsalError("private root must be empty; existing data is never overwritten")
    args.private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.private_root, 0o700)
    datadir = args.private_root / "bitcoin-regtest"
    datadir.mkdir(mode=0o700)
    manifest = json.loads(args.runtime_manifest.read_text())
    context = json.loads(args.context.read_text())
    if manifest.get("profile") != "development":
        raise RehearsalError("atomic rehearsal accepts only a Development manifest")

    daemon = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={datadir}", "-server=1",
        "-listen=0", "-connect=0", "-discover=0", "-dnsseed=0", "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1", "-fallbackfee=0.0002",
        f"-rpcport={args.bitcoin_rpc_port}", "-printtoconsole=0"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    receipt: dict = {"schema": "hegemon-bitcoin-regtest-atomic-swap-rehearsal-v1", "scenario": args.scenario,
                     "hegemon_miner_payout_address": args.miner_address,
                     "proof": "execution receipt only; no formal or release authority"}
    try:
        cookie = datadir / "regtest" / ".cookie"
        endpoint = f"http://127.0.0.1:{args.bitcoin_rpc_port}"
        btc = None
        for _ in range(200):
            if daemon.poll() is not None:
                raise RehearsalError("Bitcoin Core exited before regtest RPC became ready")
            if cookie.exists():
                try:
                    btc = BitcoinRPC(endpoint, cookie)
                    if btc.call("getblockchaininfo")["chain"] == "regtest":
                        break
                except Exception:
                    pass
            time.sleep(0.1)
        if btc is None:
            raise RehearsalError("Bitcoin Core regtest RPC did not become ready")
        if btc.call("getpeerinfo"):
            raise RehearsalError("private regtest unexpectedly has external peers")
        # Each Core descriptor wallet receives exactly its own ephemeral branch
        # key. The opposite branch key enters its counterpart's wallet only.
        for name in ("claim", "refund", "miner"):
            btc.call("createwallet", name, False, False, "", False, True)
        claim_pub, claim_wif = rehearsal_bitcoin_key()
        refund_pub, refund_wif = rehearsal_bitcoin_key()
        claim_key_desc = f"wpkh({claim_wif})"
        refund_key_desc = f"wpkh({refund_wif})"
        for wallet, desc in (("claim", claim_key_desc), ("refund", refund_key_desc)):
            imported = btc.call("importdescriptors", [{"desc": desc + "#" + descriptor_checksum(desc),
                "timestamp": "now", "active": False}], wallet=wallet, sensitive=True)
            if not imported or not imported[0].get("success"):
                raise RehearsalError("Bitcoin Core could not import a private party key descriptor")
        secret = bytearray(os.urandom(32))
        secret_path = args.private_root / "bitcoin-preimage.bin"
        write_private(secret_path, bytes(secret))
        hashlock = hashlib.sha256(secret).hexdigest()
        # The offer CLI uses two unlocked, context-pinned wallet stores and writes
        # a mode-0600 public offer; no private key or preimage enters that file.
        offer_path = args.private_root / "offer.json"
        out = run_wallet_cli(args.wallet_cli, ["htlc", "offer-create", "--context", str(args.context),
            "--claim-store", str(args.claim_store), "--refund-store", str(args.refund_store),
            "--hashlock", "0x" + hashlock, "--value", str(args.value),
            "--maximum-fee", "10", "--timeout-height", str(args.timeout_height),
            "--bitcoin-amount-sat", str(args.bitcoin_amount_sat), "--bitcoin-claim-public-key", "0x" + claim_pub,
            "--bitcoin-refund-public-key", "0x" + refund_pub, "--bitcoin-refund-height", str(args.bitcoin_refund_height),
            "--bitcoin-required-confirmations", "1", "--out", str(offer_path), "--retained-test"],
            [args.claim_passfile, args.refund_passfile])
        offer_info = last_json(out)
        offer = json.loads(offer_path.read_text())
        swap_id = offer_info["swap_id"]
        bitcoin_terms = {"amount_sat": offer["bitcoin"]["amount_sat"],
            "claim_public_key": offer["bitcoin"]["claim_public_key"],
            "refund_public_key": offer["bitcoin"]["refund_public_key"],
            "refund_height": offer["bitcoin"]["refund_height"],
            "required_confirmations": offer["bitcoin"]["required_confirmations"]}
        terms_path = args.private_root / "terms.json"
        write_private(terms_path, json.dumps({"hashlock": list(bytes.fromhex(hashlock)), "bitcoin": bitcoin_terms}).encode())
        fixture = json.loads(subprocess.check_output([str(args.public_fixture), str(terms_path)], timeout=60))
        witness_script = bytes.fromhex(fixture["witness_script_hex"])
        contract_script_pubkey = bytes.fromhex(fixture["script_pubkey_hex"])
        decoded = btc.call("decodescript", witness_script.hex())
        contract_address = decoded["segwit"]["address"]
        if decoded["segwit"].get("hex") != contract_script_pubkey.hex():
            raise RehearsalError("Bitcoin Core decoded a different witness program than the wallet fixture")
        public_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_pub})),"
                            f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_pub}))))")
        public_descriptor = btc.call("getdescriptorinfo", public_descriptor)["descriptor"]
        if btc.call("deriveaddresses", public_descriptor)[0] != contract_address:
            raise RehearsalError("Bitcoin Core public miniscript does not match the wallet witness script")
        claim_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_wif})),"
                           f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_pub}))))")
        refund_descriptor = (f"wsh(or_i(and_v(v:sha256({hashlock}),pk({claim_pub})),"
                            f"and_v(v:after({bitcoin_terms['refund_height']}),pk({refund_wif}))))")
        for wallet, descriptor in (("claim", claim_descriptor), ("refund", refund_descriptor)):
            imported = btc.call("importdescriptors", [{"desc": descriptor + "#" + descriptor_checksum(descriptor),
                "timestamp": "now", "active": False}], wallet=wallet, sensitive=True)
            if not imported or not imported[0].get("success"):
                raise RehearsalError("Bitcoin Core could not import a private HTLC branch descriptor")
        miner = btc.call("getnewaddress", "regtest-miner", "bech32", wallet="miner")
        btc.call("generatetoaddress", 101, miner)
        funding_tx = btc.call("sendtoaddress", contract_address,
                              str(Decimal(bitcoin_terms["amount_sat"]) / Decimal(100_000_000)), wallet="miner")
        btc.call("generatetoaddress", 1, miner)
        funding = btc.call("gettransaction", funding_tx, wallet="miner")
        raw_funding = btc.call("getrawtransaction", funding_tx, True, funding["blockhash"])
        vout = next(x["n"] for x in raw_funding["vout"] if x["scriptPubKey"]["hex"] == contract_script_pubkey.hex())
        if btc.call("gettxout", funding_tx, vout, True) is None:
            raise RehearsalError("Bitcoin contract output is not an actual unspent chain output")
        receipt["bitcoin_contract"] = {"funding_txid": funding_tx, "contract_address": contract_address,
            "witness_script_sha256": hashlib.sha256(witness_script).hexdigest(), "confirmations": funding["confirmations"]}
        invalid_preimage = os.urandom(32)
        while hashlib.sha256(invalid_preimage).hexdigest() == hashlock:
            invalid_preimage = os.urandom(32)
        probe_address = btc.call("getnewaddress", "negative-probe", "bech32", wallet="miner")
        require_rejected_contract_spend(btc, "claim", funding_tx, vout, bitcoin_terms["amount_sat"],
            contract_script_pubkey, witness_script, probe_address, 0xFFFFFFFF, 0, invalid_preimage,
            "wrong_secret", receipt)
        require_rejected_contract_spend(btc, "refund", funding_tx, vout, bitcoin_terms["amount_sat"],
            contract_script_pubkey, witness_script, probe_address, 0xFFFFFFFE,
            bitcoin_terms["refund_height"], None, "premature_refund", receipt)
        for store, passfile in ((args.claim_store, args.claim_passfile), (args.refund_store, args.refund_passfile)):
            run_wallet_cli(args.wallet_cli, ["htlc", "offer-accept", *wallet_common(store, args.context, args.hgn_rpc),
                "--offer", str(offer_path)], [passfile])
        encrypted_agreement = args.private_root / "encrypted-agreement.bin"
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-create", *wallet_common(args.refund_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--to", offer_info["claim_address"]], [args.refund_passfile])
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-export", *wallet_common(args.refund_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--to", offer_info["claim_address"], "--out", str(encrypted_agreement)], [args.refund_passfile])
        run_wallet_cli(args.wallet_cli, ["htlc", "agreement-import", *wallet_common(args.claim_store, args.context, args.hgn_rpc),
            "--swap-id", swap_id, "--input", str(encrypted_agreement), "--diversifier-index", "0"], [args.claim_passfile])
        receipt["hegemon_lock"] = hgn_action(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id, "lock", args.lock_input_position,
            offer_info["claim_address"], args.private_root, args.runtime_manifest)

        wrong_path = args.private_root / "wrong-preimage.bin"
        write_private(wrong_path, invalid_preimage)
        require_cli_rejection(args.wallet_cli, ["htlc", "secret-import",
            *wallet_common(args.claim_store, args.context, args.hgn_rpc), "--swap-id", swap_id,
            "--input", str(wrong_path)], [args.claim_passfile],
            args.private_root / "wrong-secret.json", "wrong Hegemon secret")
        refund_before = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id)
        locked_positions = refund_before["swaps"][0]["locked_note_positions"]
        if not locked_positions:
            raise RehearsalError("refund wallet has no canonical locked-note occurrence")
        premature_path = args.private_root / "premature-refund.json"
        require_cli_rejection(args.wallet_cli, ["htlc", "prepare-refund",
            *wallet_common(args.refund_store, args.context, args.hgn_rpc), "--swap-id", swap_id,
            "--input-position", str(locked_positions[0]), "--fee", "1", "--to", offer_info["refund_address"],
            "--out", str(premature_path)], [args.refund_passfile], premature_path,
            "premature Hegemon refund")
        refund_after = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
            args.context, args.hgn_rpc, swap_id)
        if len(refund_after["swaps"][0]["attempts"]) != len(refund_before["swaps"][0]["attempts"]):
            raise RehearsalError("rejected premature refund created an accepted HTLC attempt")
        receipt["hegemon_negative_tests"] = {
            "wrong_secret_import_rejected": True,
            "premature_refund_rejected_before_artifact": True,
            "premature_refund_created_no_attempt": True}

        if args.scenario == "claim":
            btc_destination = btc.call("getnewaddress", "claimed-contract", "bech32", wallet="claim")
            secret_for_spend = bytes(private_file(secret_path, 32))
            btc_claim = spend_contract(btc, "claim", funding_tx, vout, bitcoin_terms["amount_sat"],
                contract_script_pubkey, witness_script, btc_destination,
                0xFFFFFFFF, 0, secret_for_spend)
            btc_claim_confirmed = wait_bitcoin_confirmations(btc, btc_claim, "claim", 1, miner)
            revealed = confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            if revealed != secret_for_spend:
                raise RehearsalError("Bitcoin chain witness differs from the original private secret")
            revealed_path = args.private_root / "revealed-on-bitcoin-chain-secret.bin"
            for i in range(len(secret)):
                secret[i] = 0
            claim_status = hgn_status(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id)
            positions = claim_status["swaps"][0]["locked_note_positions"]
            if not positions:
                raise RehearsalError("claim wallet has no canonical locked-note occurrence")
            receipt["bitcoin_claim"] = {"txid": btc_claim, "confirmations": btc_claim_confirmed["confirmations"],
                "received_sat": bitcoin_terms["amount_sat"] - 500, "secret_source": "confirmed Bitcoin witness"}
            receipt["bitcoin_claim"]["destination"] = require_bitcoin_receive(
                btc, btc_claim, "claim", btc_destination, bitcoin_terms["amount_sat"] - 500)
            claim_block = btc_claim_confirmed["blockhash"]
            btc.call("invalidateblock", claim_block)
            try:
                confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            except RehearsalError:
                receipt["bitcoin_claim"]["orphan_witness_refused"] = True
            else:
                raise RehearsalError("wallet treated orphaned Bitcoin claim witness as confirmed")
            btc.call("reconsiderblock", claim_block)
            restored = wait_bitcoin_confirmations(btc, btc_claim, "claim", 1, miner)
            revealed = confirmed_bitcoin_preimage(btc, btc_claim, "claim", bytes.fromhex(hashlock))
            if revealed != secret_for_spend:
                raise RehearsalError("reconsidered active-chain witness differs from the original secret")
            write_private(revealed_path, revealed)
            receipt["bitcoin_claim"]["reconsidered_confirmations"] = restored["confirmations"]
            run_wallet_cli(args.wallet_cli, ["htlc", "secret-import", *wallet_common(args.claim_store, args.context, args.hgn_rpc),
                "--swap-id", swap_id, "--input", str(revealed_path)], [args.claim_passfile])
            receipt["hegemon_claim"] = hgn_action(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id, "claim", positions[0],
                offer_info["claim_address"], args.private_root, args.runtime_manifest)
            claim_status = hgn_status(args.wallet_cli, args.claim_store, args.claim_passfile,
                args.context, args.hgn_rpc, swap_id)
            require_exact_owned_note(claim_status, args.value - 1,
                                     receipt["hegemon_claim"]["output_commitment"])
            receipt["hegemon_claim"]["received_base_units"] = args.value - 1
            receipt["outcome"] = "confirmed Bitcoin and Hegemon claimant ownership changes"
        else:
            current_btc = btc_height(btc)
            refund_height = bitcoin_terms["refund_height"]
            if current_btc < refund_height:
                btc.call("generatetoaddress", refund_height - current_btc, miner)
            btc_destination = btc.call("getnewaddress", "refunded-contract", "bech32", wallet="refund")
            btc_refund = spend_contract(btc, "refund", funding_tx, vout, bitcoin_terms["amount_sat"],
                contract_script_pubkey, witness_script, btc_destination,
                0xFFFFFFFE, refund_height)
            btc_refund_confirmed = wait_bitcoin_confirmations(btc, btc_refund, "refund", 1, miner)
            refund_destination = require_bitcoin_receive(
                btc, btc_refund, "refund", btc_destination, bitcoin_terms["amount_sat"] - 500)
            if hgn_height(args.hgn_rpc) < args.timeout_height:
                hgn_mine_to(args.hgn_rpc, args.timeout_height)
            refund_status = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id)
            positions = refund_status["swaps"][0]["locked_note_positions"]
            if not positions:
                raise RehearsalError("refund wallet has no canonical locked-note occurrence")
            receipt["bitcoin_refund"] = {"txid": btc_refund, "confirmations": btc_refund_confirmed["confirmations"],
                "returned_sat": bitcoin_terms["amount_sat"] - 500, "claim_branch_absent": True,
                "destination": refund_destination}
            receipt["hegemon_refund"] = hgn_action(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id, "refund", positions[0],
                offer_info["refund_address"], args.private_root, args.runtime_manifest)
            refund_status = hgn_status(args.wallet_cli, args.refund_store, args.refund_passfile,
                args.context, args.hgn_rpc, swap_id)
            require_exact_owned_note(refund_status, args.value - 1,
                                     receipt["hegemon_refund"]["output_commitment"])
            receipt["hegemon_refund"]["returned_base_units"] = args.value - 1
            receipt["outcome"] = "counterparty absent; both chain assets returned after their own timeouts"
        receipt["swap_id"] = swap_id
        receipt["offer_hashlock"] = "0x" + hashlock
        receipt["private_artifacts"] = "mode-0600 files retained under the caller-owned private root"
        receipt["unrun"] = ["Hegemon canonical reorg recovery"]
        print(json.dumps(receipt, sort_keys=True))
        for i in range(len(secret)):
            secret[i] = 0
        _ = (endpoint, context)
        return 0
    finally:
        daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RehearsalError as error:
        print(f"atomic rehearsal stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
