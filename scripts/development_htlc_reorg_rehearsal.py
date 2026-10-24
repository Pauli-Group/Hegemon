#!/usr/bin/env python3
"""Rehearse exact retained HTLC Claim recovery across a local Development reorg."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from development_atomic_swap_rehearsal import (  # noqa: E402
    RehearsalError, hgn_status, rpc_call, run_wallet_cli, wallet_common,
)


def height(rpc: str) -> int:
    value = rpc_call(rpc, "chain_getHeader")["number"]
    return int(value, 16) if str(value).startswith("0x") else int(value)


def block_hash(rpc: str, h: int) -> str:
    return rpc_call(rpc, "chain_getBlockHash", [h])


def cumulative_work(rpc: str) -> int:
    value = rpc_call(rpc, "chain_getHeader")["cumulativeWork"]
    if isinstance(value, int):
        return value
    return int(value, 16) if str(value).startswith("0x") else int(value, 10)


def wait_height(rpc: str, target: int, timeout: int = 180) -> int:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            current = height(rpc)
            if current >= target:
                return current
        except Exception as error:
            last_error = error
        time.sleep(0.25)
    raise RehearsalError(f"node did not reach height {target}; last RPC error: {last_error}")


def no_peers(rpc: str) -> None:
    if rpc_call(rpc, "system_health").get("peers") != 0:
        raise RehearsalError("fork B connected to peers before its private branch was built")


def mine_until_greater_work(rpc: str, reference_work: int, minimum_height: int,
                            maximum_height: int) -> tuple[int, int]:
    rpc_call(rpc, "hegemon_startMining", [{"threads": 1}])
    try:
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            no_peers(rpc)
            current_height = height(rpc)
            current_work = cumulative_work(rpc)
            if current_height >= minimum_height and current_work > reference_work:
                break
            if current_height >= maximum_height:
                raise RehearsalError("isolated branch reached its height cap before exceeding reference work")
            time.sleep(0.25)
        else:
            raise RehearsalError("fork B did not exceed frozen node-A cumulative work")
    finally:
        rpc_call(rpc, "hegemon_stopMining")
    no_peers(rpc)
    current_height = height(rpc)
    current_work = cumulative_work(rpc)
    if current_height > maximum_height or current_height < minimum_height or current_work <= reference_work:
        raise RehearsalError("stopped B branch fails the strict height and cumulative-work gate")
    return current_height, current_work


def mine_to(rpc: str, target: int) -> int:
    """Bounded replay miner, separate from the isolated cumulative-work gate."""
    rpc_call(rpc, "hegemon_startMining", [{"threads": 1}])
    try:
        return wait_height(rpc, target, 600)
    finally:
        rpc_call(rpc, "hegemon_stopMining")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native-chain", type=Path, required=True,
                   help="native-chain.sled directory from the stopped common-checkpoint copy")
    p.add_argument("--b-base", type=Path, required=True, help="new, empty node-B base path")
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--context", type=Path, required=True)
    p.add_argument("--private-root", type=Path, required=True)
    p.add_argument("--wallet-cli", type=Path, required=True)
    p.add_argument("--store", type=Path, required=True)
    p.add_argument("--passfile", type=Path, required=True)
    p.add_argument("--runtime-manifest", type=Path, required=True)
    p.add_argument("--a-rpc", default="http://127.0.0.1:19944")
    p.add_argument("--b-rpc", default="http://127.0.0.1:19947")
    p.add_argument("--sync-timeout-seconds", type=int, default=600,
                   help="bounded P2P branch adoption/replay wait (1..1200 seconds)")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="direct node-B argv after --, configured for B base/RPC/P2P ports")
    a = p.parse_args()
    if not 1 <= a.sync_timeout_seconds <= 1200:
        raise RehearsalError("sync timeout must be between 1 and 1200 seconds")
    if not a.native_chain.is_dir() or a.native_chain.is_symlink():
        raise RehearsalError("native-chain.sled must be a real directory snapshot")
    if not a.command or a.command[0] != "--" or len(a.command) < 2:
        raise RehearsalError("supply the direct node-B command after --")
    if a.b_base.exists() or a.private_root.exists():
        raise RehearsalError("node-B base and private output root must be new paths")
    receipt = json.loads(a.receipt.read_text())
    checkpoint = receipt["pre_claim_checkpoint"]
    claim = receipt["hegemon_claim"]
    common_height = int(checkpoint["height"])
    claim_height = int(claim["canonical_confirmation"]["height"])
    if claim_height != common_height + 1:
        raise RehearsalError("Claim receipt is not the first block after the common checkpoint")
    old_bytes = bytes(claim["canonical_confirmation"]["block_hash"])
    old_hash = "0x" + old_bytes.hex()
    original_artifact = json.loads(Path(claim["artifact"]).read_text())
    commitment = original_artifact["output_commitment"]
    if "output_commitment" in claim and claim["output_commitment"] != commitment:
        raise RehearsalError("claim receipt output commitment differs from its original artifact")
    original_carrier = base64.b64decode(original_artifact["inline_args_base64"], validate=True)
    context = json.loads(a.context.read_text())

    a_header = rpc_call(a.a_rpc, "chain_getHeader")
    if a_header.get("chainId", "").lower() != context["chain_id"].lower():
        raise RehearsalError("node A chain id differs from the handoff context")
    if block_hash(a.a_rpc, 0).lower() != context["genesis_hash"].lower():
        raise RehearsalError("node A genesis differs from the handoff context")
    if block_hash(a.a_rpc, common_height).lower() != checkpoint["common_hash"].lower():
        raise RehearsalError("node A no longer has the supplied common checkpoint")
    if block_hash(a.a_rpc, claim_height).lower() != old_hash.lower():
        raise RehearsalError("Claim receipt block is not currently canonical on node A")
    reference_work = cumulative_work(a.a_rpc)

    a.b_base.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copytree(a.native_chain, a.b_base / "native-chain.sled")
    a.private_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = a.command[1:]
    env = dict(os.environ)
    env["HEGEMON_SEEDS"] = ""
    proc = subprocess.Popen(command, env=env, start_new_session=True)
    try:
        wait_height(a.b_rpc, common_height)
        if height(a.b_rpc) != common_height:
            raise RehearsalError("fork B did not start exactly at the common checkpoint")
        if block_hash(a.b_rpc, 0).lower() != context["genesis_hash"].lower():
            raise RehearsalError("node B genesis differs from the handoff context")
        if block_hash(a.b_rpc, common_height).lower() != checkpoint["common_hash"].lower():
            raise RehearsalError("node B snapshot differs from the common checkpoint")
        no_peers(a.b_rpc)
        branch_height, branch_work = mine_until_greater_work(
            a.b_rpc, reference_work, common_height + 2, common_height + 11)
        branch_hash = block_hash(a.b_rpc, branch_height)
        rpc_call(a.b_rpc, "hegemon_stopMining")
        proc.terminate()
        proc.wait(timeout=20)
        env["HEGEMON_SEEDS"] = "127.0.0.1:31335"
        proc = subprocess.Popen(command, env=env, start_new_session=True)

        deadline = time.monotonic() + a.sync_timeout_seconds
        while time.monotonic() < deadline:
            if height(a.a_rpc) >= branch_height:
                adopted_hash = block_hash(a.a_rpc, branch_height)
                adopted_work = cumulative_work(a.a_rpc)
                if adopted_hash == branch_hash and adopted_work >= branch_work:
                    break
            time.sleep(0.5)
        if (height(a.a_rpc) < branch_height
                or block_hash(a.a_rpc, branch_height) != branch_hash
                or cumulative_work(a.a_rpc) < branch_work
                or block_hash(a.a_rpc, claim_height).lower() == old_hash.lower()):
            raise RehearsalError("node A did not adopt B's exact higher-work branch and orphan the Claim")
        status = hgn_status(a.wallet_cli, a.store, a.passfile, a.context, a.a_rpc, receipt["swap_id"])
        swap = status["swaps"][0]
        if any(n.get("commitment") == commitment for n in status["ordinary_native_notes"]):
            raise RehearsalError("orphaned Claim output remains owned after canonical wallet sync")
        attempt = claim["attempt_id"]
        record = next(x for x in swap["attempts"] if x["attempt_id"] == attempt)
        if record.get("canonical_confirmation") is not None:
            raise RehearsalError("orphaned Claim retains canonical confirmation")
        recovered_path = a.private_root / "recovered.json"
        run_wallet_cli(a.wallet_cli, ["htlc", "recover", *wallet_common(a.store, a.context, a.a_rpc),
            "--attempt-id", attempt, "--out", str(recovered_path)], [a.passfile])
        recovered = json.loads(recovered_path.read_text())
        recovered_carrier = base64.b64decode(recovered["inline_args_base64"], validate=True)
        if recovered.get("attempt_id") != attempt or recovered_carrier != original_carrier:
            raise RehearsalError("recovered retained Claim bytes differ from original carrier")
        run_wallet_cli(a.wallet_cli, ["htlc", "submit", *wallet_common(a.store, a.context, a.a_rpc),
            "--runtime-manifest", str(a.runtime_manifest), "--attempt-id", attempt], [a.passfile])
        mine_to(a.a_rpc, branch_height + 1)
        wait_height(a.b_rpc, branch_height + 1, a.sync_timeout_seconds)
        target = branch_height + 1
        if block_hash(a.a_rpc, target) != block_hash(a.b_rpc, target):
            raise RehearsalError("nodes did not converge after exact Claim carrier resubmission")
        final = hgn_status(a.wallet_cli, a.store, a.passfile, a.context, a.a_rpc, receipt["swap_id"])
        record = next(x for x in final["swaps"][0]["attempts"] if x["attempt_id"] == attempt)
        if not record.get("canonical_confirmation"):
            raise RehearsalError("resubmitted Claim lacks canonical confirmation")
        value = claim["received_base_units"]
        if not any(n.get("commitment") == commitment and n.get("native_value_base_units") == value
                   for n in final["ordinary_native_notes"]):
            raise RehearsalError("replayed Claim output is not owned at the receipt value")
        print(json.dumps({"common_checkpoint_hash": checkpoint["common_hash"],
            "frozen_a_cumulative_work_hex": format(reference_work, "x"),
            "isolated_b_cumulative_work_hex": format(branch_work, "x"),
            "isolated_b_height": branch_height, "isolated_b_hash": branch_hash,
            "orphaned_claim_hash": old_hash, "canonical_replay_hash": block_hash(a.a_rpc, target),
            "original_carrier_sha256": hashlib.sha256(original_carrier).hexdigest(),
            "recovered_same_carrier": True, "orphaned_output_dropped": True,
            "new_confirmation": record["canonical_confirmation"], "owned_output_value": value,
            "private_keys_emitted": False}, sort_keys=True))
    finally:
        proc.terminate()
        proc.wait(timeout=20)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RehearsalError as error:
        print(f"HTLC reorg rehearsal stopped: {error}", file=sys.stderr)
        raise SystemExit(2)
