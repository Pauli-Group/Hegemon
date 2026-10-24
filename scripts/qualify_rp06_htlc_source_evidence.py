#!/usr/bin/env python3
"""Read-only inventory for the frozen RP06/HTLC qualification inputs.

This tool checks source-owned byte pins, document schemas, public network context,
and historical source labels. It does not run a prover, validate a theorem,
re-execute broad receipt assertions, or authorize/activate a profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping

SCHEMA = "hegemon.rp06-htlc.public-source-evidence-qualification.v1"
RUNTIME_SOURCE_COMMIT = "185a132b821ad319a49f4a8746c6110ea7ba0476"
HISTORICAL_WALLET_COMMIT = "7b972f7b48f8884840191ff0a4cfc9b1d57d828d"
PRECONDITION_PATH = Path(
    "/private/tmp/premainnet-soak-20261004/lifecycle-precondition-public-receipt.json"
)
PRECONDITION_SHA256 = "b3b2ba2acdfb868e233019bc234ff88a7d166453150f636d4fac02964988f9f8"
CONTEXT_PATH = Path(
    "/private/tmp/premainnet-local-runtime-20261004/context-node-derived-final.json"
)
CONTEXT_SHA256 = "1710b9cf9708c65b68e426aa388a12e84ccd6fc96a85f93ecb3c856dadee170f"
SOAK_PATH = Path(
    "/private/tmp/premainnet-soak-20261004/runs/soak-185a-20261004T195115Z/summary.json"
)
BUNDLE_PRECONDITION_FILENAME = "precondition.json"
BUNDLE_CONTEXT_FILENAME = "context.json"
BUNDLE_SOAK_FILENAME = "measured-soak-summary.json"

EXPECTED_NETWORK = {
    "profile": "development",
    "chain_id": "0xbd8b0375ed9362d491108a27b7cabecd349ee1a8cbca6bbb97d5e530d4104c22",
    "genesis_hash": "0x05402871bc6b6612baa61d06e5318b270b678ef9d367213e7f4a7a9319c9ffb8",
    "manifest_digest": "0x4068482f8230bc64de08da5fa3b751f5cc237b9de200add185e5ed8c5623994a6c1f986fbda048759ba0b22853c4d1bd5c2caa63ccdfd61029e33c7f472ebf3e",
}

# These are the explicit files named by the HTLC relation_digest source function,
# plus RP06's profile, encoder, semantics and type inputs. They are source-role
# inventories, not a claim that this list alone computes either relation program.
SHARED_ENGINE = ("circuits/transaction/src/smallwood_engine.rs",)
RP06_SOURCES = (
    "circuits/transaction/src/smallwood_poseidon2_v8_rp06.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_program.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_types.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_hash_schedule.rs",
    "circuits/transaction/src/smallwood_semantics.rs",
    "circuits/transaction/src/smallwood_engine.rs",
    "circuits/transaction-core/src/poseidon2_width16.rs",
    "circuits/transaction-core/src/constants.rs",
    "circuits/hegemon-field/src/lib.rs",
)
HTLC_SOURCES = (
    "circuits/transaction/src/smallwood_htlc.rs",
    "circuits/transaction/src/smallwood_htlc/circuit.rs",
    "circuits/transaction/src/smallwood_htlc/sha256.rs",
    "circuits/transaction/src/smallwood_poseidon2_v8_hash_schedule.rs",
    "circuits/transaction-core/src/poseidon2_width16.rs",
    "circuits/transaction-core/src/constants.rs",
    "circuits/hegemon-field/src/lib.rs",
    "circuits/transaction/src/smallwood_engine.rs",
    "circuits/transaction/src/smallwood_semantics.rs",
    "protocol/versioning/src/launch_candidate_identity.rs",
)
SOURCE_ROLES = {
    "shared_engine": SHARED_ENGINE,
    "rp06": RP06_SOURCES,
    "htlc": HTLC_SOURCES,
}

# SHA-256 values are copied into source so a precondition's own digest fields
# cannot choose what this checker accepts. A matching digest verifies bytes only.
RECEIPT_PINS: dict[str, dict[str, Any]] = {
    "linux_source_build": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/linux-node-build-185a132b8-native-rebuild02-public-receipt.json",
        "sha256": "a9984247923fb796363c88d7fb1abc3e592494819d180c02f6494eb891cc341d",
        "schema": "hegemon.linux-node-update-build-receipt.v1",
        "source_commit": RUNTIME_SOURCE_COMMIT,
    },
    "linux_activation_prepared": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/linux-activation-prepared-185a132b8-public-receipt.json",
        "sha256": "ab4bf96397999897a9648352136919c92180e18682f718f8e5123c2911746618",
        "schema": "hegemon.linux-activation-prepared.v1",
        "source_commit": RUNTIME_SOURCE_COMMIT,
    },
    "all_four_restart": {
        "path": "/private/tmp/premainnet-crosshost-runtime-20261004/after-sync-restart-20261004T193412Z-6cfdea0e/restart-receipt.json",
        "sha256": "d8be5a9be55e48097126d12dbb1b3ec76dd430cba7605934dd4637831a353922",
        "schema": "hegemon.after-sync-restart-receipt.v1",
        "source_commit": RUNTIME_SOURCE_COMMIT,
    },
    "historical_body_equality": {
        "path": "/private/tmp/premainnet-final-bodycheck-20261004/post-all4-restart-h56-01-all4-canonical-body-public-receipt.json",
        "sha256": "f120e3e863cc82879f0cb690b3303738f72aab3316f4af05985a7c53014b1594",
        "schema": "hegemon-all4-canonical-header-body-check-v1",
        "source_commit": None,
    },
    "new_block_equality": {
        "path": "/private/tmp/premainnet-crosshost-runtime-20261004/one-shot-mining-20261004T193626Z-8b58df40/probe-receipt.json",
        "sha256": "88883c9d6d3eaef25e4b2627c96a6a076b68079eb34c9f699a05384d13bf707b",
        "schema": "hegemon.post-update-mining-probe-receipt.v1",
        "source_commit": RUNTIME_SOURCE_COMMIT,
    },
    "actual_owned_miner_payouts": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/updated-miner-payouts-h65-public-receipt.json",
        "sha256": "00dbdb80c618459d5a416d4ec2f93c63964c991f018618a17f961c9bf10e1202",
        "schema": "hegemon.updated-miner-payout-receipt.v1",
        "source_commit": RUNTIME_SOURCE_COMMIT,
    },
    "four_linux_funded_transfers": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/linux-funding-flow-01-public-summary.json",
        "sha256": "ac018359cb44fff8bf08397a807d632ddafa9c9dccb1bb6f6ffbb872b4c5f6c1",
        "schema": "hegemon.linux-wallet-funding-flow-receipt.v1",
        "source_commit": HISTORICAL_WALLET_COMMIT,
    },
    "funding_recipient_ownership": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/linux-funding-recipient-final-public-receipt.json",
        "sha256": "016bc0103bbc1b3af121aab075c48a0491df663b8443bf7cc433efcde187b7c1",
        "schema": None,
        "required_keys": ("refund", "signer1", "signer2"),
        "exact_keys": True,
        "source_commit": None,
    },
    "cross_host_treasury": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/treasury-spend-03/public-receipt.json",
        "sha256": "f8db84815793d7e6c1b3c3743adc8e91bff0987efe94a9777fd589285c141f28",
        "schema": None,
        "required_keys": ("authority", "canonical_approvals", "context", "expected_miner_payout_address", "final_submission", "negative_checks", "network_profile", "review"),
        "exact_keys": True,
        "source_commit": None,
    },
    "cross_host_swap_claim": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/atomic-linux-claim-01-public-receipt.json",
        "sha256": "32e2c1894a9742931d79049859d69b47ea8e4766cbb8e9ca3dc851c4744ef34f",
        "schema": "hegemon-bitcoin-regtest-atomic-swap-rehearsal-v1",
        "source_commit": None,
    },
    "cross_host_swap_timeout": {
        "path": "/private/tmp/premainnet-local-runtime-20261004/atomic-linux-timeout-01-public-receipt.json",
        "sha256": "332fd6c24fcfe2f390a00a04b260b1bd7863782fbc5b5d244bb08ff9a184b204",
        "schema": "hegemon-bitcoin-regtest-atomic-swap-rehearsal-v1",
        "source_commit": None,
    },
}
BUNDLE_RECEIPT_FILENAMES = {role: f"{role}.json" for role in RECEIPT_PINS}

OPEN_GATES = (
    "formal_relation_semantics",
    "accepted_source_bridge",
    "composed_knowledge_soundness",
    "complete_public_simulation",
    "shared_query_lifetime_bound",
    "frozen_identity_proofs_and_same_bytes_lifecycle",
    "independent_review",
    "source_owned_release_authority",
)
MAX_JSON_BYTES = 2 * 1024 * 1024


class QualificationInputError(ValueError):
    """A required public input is absent, malformed, or disagrees with its pin."""


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        if path.is_symlink() or not path.is_file():
            raise QualificationInputError(f"{label}: missing or non-regular file")
        if path.stat().st_size > MAX_JSON_BYTES:
            raise QualificationInputError(f"{label}: exceeds public JSON size limit")
        raw = path.read_bytes()
        value = json.loads(raw)
    except QualificationInputError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationInputError(f"{label}: malformed or unreadable JSON") from exc
    if not isinstance(value, dict):
        raise QualificationInputError(f"{label}: JSON root must be an object")
    return value, raw


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_blob(repo: Path, revision: str, relative: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "show", f"{revision}:{relative}"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise QualificationInputError(
            f"source inventory: cannot read {revision}:{relative}"
        ) from exc
    return result.stdout


def _inventory_digest(entries: list[dict[str, Any]]) -> str:
    h = hashlib.sha256()
    h.update(b"hegemon.rp06-htlc.source-role-inventory.v1\0")
    for entry in entries:
        path = entry["path"].encode()
        digest = bytes.fromhex(entry["sha256"])
        h.update(len(path).to_bytes(4, "little"))
        h.update(path)
        h.update(entry["bytes"].to_bytes(8, "little"))
        h.update(digest)
    return h.hexdigest()


def inspect_sources(
    repo: Path,
    blob_reader: Callable[[str, str], bytes] | None = None,
    current_reader: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Bind named source roles to frozen Git blobs and compare only those blobs to 7b."""
    read_blob = blob_reader or (lambda rev, path: _source_blob(repo, rev, path))
    file_digests: dict[str, dict[str, Any]] = {}
    source_matches: dict[str, bool] = {}
    for paths in SOURCE_ROLES.values():
        for relative in paths:
            if relative in file_digests:
                continue
            frozen = read_blob(RUNTIME_SOURCE_COMMIT, relative)
            if current_reader is None:
                try:
                    working = (repo / relative).read_bytes()
                except OSError as exc:
                    raise QualificationInputError(f"source inventory: missing {relative}") from exc
            else:
                working = current_reader(relative)
            file_digests[relative] = {
                "sha256": _sha256(frozen),
                "bytes": len(frozen),
                "working_tree_matches_frozen": working == frozen,
            }
            source_matches[relative] = working == frozen
    roles: dict[str, Any] = {}
    for role, paths in SOURCE_ROLES.items():
        entries = [{"path": p, **file_digests[p]} for p in paths]
        historical = [
            {"path": p, "unchanged_from_7b": read_blob(HISTORICAL_WALLET_COMMIT, p) == read_blob(RUNTIME_SOURCE_COMMIT, p)}
            for p in paths
        ]
        roles[role] = {
            "source_inventory_sha256": _inventory_digest(entries),
            "files": entries,
            "unchanged_from_historical_7b": all(x["unchanged_from_7b"] for x in historical),
            "historical_file_comparison": historical,
        }
    if not all(source_matches.values()):
        changed = sorted(p for p, matches in source_matches.items() if not matches)
        raise QualificationInputError("working source differs from frozen 185a blobs: " + ", ".join(changed))
    return {
        "runtime_source_commit": RUNTIME_SOURCE_COMMIT,
        "role_inventory_kind": "named source-role byte inventory; not relation program regeneration",
        "roles": roles,
    }


def _same_network(document: Mapping[str, Any], expected: Mapping[str, str], label: str) -> None:
    for key, expected_value in expected.items():
        actual = document.get(key)
        if actual != expected_value:
            raise QualificationInputError(f"{label}: network {key} mismatch")


def inspect_public_evidence(
    precondition_path: Path,
    context_path: Path,
    soak_path: Path,
    *,
    pins: Mapping[str, Mapping[str, Any]] = RECEIPT_PINS,
    precondition_sha256: str = PRECONDITION_SHA256,
    context_sha256: str = CONTEXT_SHA256,
    expected_network: Mapping[str, str] = EXPECTED_NETWORK,
    evidence_bundle_dir: Path | None = None,
    bundle_role_filenames: Mapping[str, str] = BUNDLE_RECEIPT_FILENAMES,
    precondition_provenance_path: Path | None = None,
) -> dict[str, Any]:
    if evidence_bundle_dir is not None:
        if evidence_bundle_dir.is_symlink() or not evidence_bundle_dir.is_dir():
            raise QualificationInputError("evidence bundle: missing or non-directory path")
        precondition_path = evidence_bundle_dir / BUNDLE_PRECONDITION_FILENAME
        context_path = evidence_bundle_dir / BUNDLE_CONTEXT_FILENAME
        soak_path = evidence_bundle_dir / BUNDLE_SOAK_FILENAME
        if precondition_provenance_path is None:
            precondition_provenance_path = PRECONDITION_PATH
    elif precondition_provenance_path is None:
        precondition_provenance_path = precondition_path
    precondition, precondition_bytes = _read_json(precondition_path, "precondition")
    if _sha256(precondition_bytes) != precondition_sha256:
        raise QualificationInputError("precondition: frozen digest mismatch")
    if precondition.get("schema") != "hegemon.development-rehearsal-precondition-v1":
        raise QualificationInputError("precondition: schema mismatch")
    if precondition.get("source_commit") != RUNTIME_SOURCE_COMMIT:
        raise QualificationInputError("precondition: source commit mismatch")
    if precondition.get("production_authorized") is not False:
        raise QualificationInputError("precondition: production authorization must be false")
    network = precondition.get("network_identity")
    if not isinstance(network, dict):
        raise QualificationInputError("precondition: missing network identity")
    _same_network(network, expected_network, "precondition")
    if precondition.get("status") != "PASS" or precondition.get("completed") is not True:
        raise QualificationInputError("precondition: expected completed public precondition")

    evidence = precondition.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(pins):
        raise QualificationInputError("precondition: required evidence role set mismatch")
    receipt_results: dict[str, Any] = {}
    for role, pin in pins.items():
        record = evidence.get(role)
        if not isinstance(record, dict):
            raise QualificationInputError(f"evidence role {role}: missing record")
        if record.get("path") != pin["path"] or record.get("sha256") != pin["sha256"]:
            raise QualificationInputError(f"evidence role {role}: source-owned path/digest mismatch")
        if evidence_bundle_dir is None:
            path = Path(str(pin["path"]))
            bundle_member = None
        else:
            member = bundle_role_filenames.get(role)
            if not isinstance(member, str) or not member or Path(member).name != member:
                raise QualificationInputError(f"evidence role {role}: invalid source-owned bundle filename")
            path = evidence_bundle_dir / member
            bundle_member = member
        receipt, raw = _read_json(path, f"evidence role {role}")
        if _sha256(raw) != pin["sha256"]:
            raise QualificationInputError(f"evidence role {role}: immutable digest mismatch")
        if pin.get("schema") is not None and receipt.get("schema") != pin["schema"]:
            raise QualificationInputError(f"evidence role {role}: schema mismatch")
        required_keys = tuple(pin.get("required_keys", ()))
        if pin.get("exact_keys", False) and set(receipt) != set(required_keys):
            raise QualificationInputError(f"evidence role {role}: root field set mismatch")
        for key in required_keys:
            if key not in receipt:
                raise QualificationInputError(f"evidence role {role}: required field {key} missing")
        expected_commit = pin.get("source_commit")
        actual_commit = receipt.get("source_commit")
        if expected_commit is not None and actual_commit != expected_commit:
            raise QualificationInputError(f"evidence role {role}: provenance mismatch")
        if role == "four_linux_funded_transfers":
            if receipt.get("chain_id") != expected_network["chain_id"] or receipt.get("genesis_hash") != expected_network["genesis_hash"]:
                raise QualificationInputError(f"evidence role {role}: network context mismatch")
            if receipt.get("network_manifest_digest") != expected_network["manifest_digest"]:
                raise QualificationInputError(f"evidence role {role}: manifest context mismatch")
        receipt_results[role] = {
            "path": pin["path"],
            "bundle_member": bundle_member,
            "sha256_verified": True,
            "schema_verified": pin.get("schema") is not None,
            "shape_verified": pin.get("schema") is None and bool(required_keys),
            "schema": pin.get("schema"),
            "source_commit": actual_commit,
            "provenance": (
                "historical-wallet-flow-at-7b; later node admission source is 185a"
                if role == "four_linux_funded_transfers"
                else "source commit explicitly pinned"
                if expected_commit is not None
                else "receipt digest pinned; source commit unspecified"
            ),
            "receipt_assertions_independently_verified": False,
        }

    context, context_bytes = _read_json(context_path, "public context")
    if _sha256(context_bytes) != context_sha256:
        raise QualificationInputError("public context: frozen digest mismatch")
    context_network = {key: value for key, value in expected_network.items() if key != "profile"}
    _same_network(context, context_network, "public context")
    if context.get("activation_height") != 1 or context.get("deactivation_height_exclusive") != 10001:
        raise QualificationInputError("public context: activation interval mismatch")

    soak, soak_bytes = _read_json(soak_path, "measured soak summary")
    if soak.get("schema") != "hegemon.development-soak-summary-v1":
        raise QualificationInputError("measured soak summary: schema mismatch")
    if soak.get("source_commit") != RUNTIME_SOURCE_COMMIT:
        raise QualificationInputError("measured soak summary: source commit mismatch")
    if soak.get("precondition_receipt") != str(precondition_provenance_path):
        raise QualificationInputError("measured soak summary: precondition path mismatch")
    if soak.get("precondition_status") != "PASS" or soak.get("production_authorized") is not False:
        raise QualificationInputError("measured soak summary: invalid public precondition/authority fields")
    status = soak.get("status")
    if status not in {"RUNNING", "PASS", "FAIL"}:
        raise QualificationInputError("measured soak summary: unsupported monitor status")
    duration_sample_thresholds_satisfied = False
    if status == "PASS":
        elapsed = soak.get("elapsed_seconds")
        sample_count = soak.get("sample_count")
        target_hours = soak.get("target_hours")
        target_samples = soak.get("target_samples_minimum")
        def finite_number(value: Any) -> bool:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
            try:
                return math.isfinite(value)
            except OverflowError:
                return False

        integer_counts = (
            isinstance(sample_count, int) and not isinstance(sample_count, bool)
            and isinstance(target_samples, int) and not isinstance(target_samples, bool)
        )
        if not finite_number(elapsed) or not finite_number(target_hours) or not integer_counts:
            raise QualificationInputError("measured soak summary: PASS has invalid duration/sample numeric fields")
        if elapsed < 86400 or target_hours < 24 or target_samples < 2880 or sample_count < target_samples:
            raise QualificationInputError("measured soak summary: PASS lacks 24-hour/sample evidence")
        duration_sample_thresholds_satisfied = True
    soak_observation = {
        "path": str(SOAK_PATH if evidence_bundle_dir is not None else soak_path),
        "bundle_member": BUNDLE_SOAK_FILENAME if evidence_bundle_dir is not None else None,
        "sha256_observed": _sha256(soak_bytes),
        "digest_is_frozen": False,
        "status": status,
        "monitor_reported_operational_pass": status == "PASS",
        "monitor_reported_duration_and_sample_thresholds_satisfied": duration_sample_thresholds_satisfied,
        "monitor_report_bytes_authenticated": False,
        "body_equality_independently_verified": False,
        "process_continuity_independently_verified": False,
        "counts_as_qualification": False,
    }

    return {
        "precondition": {
            "path": str(precondition_provenance_path),
            "bundle_member": BUNDLE_PRECONDITION_FILENAME if evidence_bundle_dir is not None else None,
            "sha256_verified": True,
            "schema": precondition["schema"],
            "source_commit": precondition["source_commit"],
            "production_authorized": False,
        },
        "network_context": {
            **expected_network,
            "bundle_member": BUNDLE_CONTEXT_FILENAME if evidence_bundle_dir is not None else None,
            "sha256_verified": True,
            "activation_height": context["activation_height"],
            "deactivation_height_exclusive": context["deactivation_height_exclusive"],
        },
        "retained_public_receipts": receipt_results,
        "measured_soak": soak_observation,
    }


def build_report(
    repo: Path,
    precondition_path: Path,
    context_path: Path,
    soak_path: Path,
    evidence_bundle_dir: Path | None = None,
) -> dict[str, Any]:
    report = {
        "schema": SCHEMA,
        "inventory_status": "OPEN",
        "runtime_source_commit": RUNTIME_SOURCE_COMMIT,
        "source_bindings": inspect_sources(repo),
        "public_evidence": inspect_public_evidence(
            precondition_path, context_path, soak_path, evidence_bundle_dir=evidence_bundle_dir
        ),
        "gates": {name: "OPEN" for name in OPEN_GATES},
        "gate_requirements": {
            "formal_relation_semantics": "separate RP06 and HTLC relation proofs, including authorization, conservation, network, and timeout/hashlock predicates",
            "accepted_source_bridge": "bind the production parser, source table, response selector, and accepted query to the mathematical endpoints",
            "composed_knowledge_soundness": "transport the source-specific geometry and density through accepted executions, PCS/PIOP, and Fiat-Shamir/QROM",
            "complete_public_simulation": "prove adaptive simulation of the complete initialized public proof view under the changed framing",
            "shared_query_lifetime_bound": "derive one global-query bound across both families and every cryptographic role",
            "frozen_identity_proofs_and_same_bytes_lifecycle": "retain two independent proofs per frozen identity and carry unchanged bytes through wallet, RPC, relay, mempool, mining, block, restart, reorg, and fresh-node checks",
            "independent_review": "bind an independent review to the same source, identity, and retained proof digests",
            "source_owned_release_authority": "source-owned execution commands, review trust roots, hermetic release roots, and profile authorization remain unprovided; launch capability and successor profile registries remain empty",
        },
        "production_authorized": False,
        "authorization_path": None,
        "interpretation": [
            "Git blob and receipt digests establish byte identity only.",
            "Receipt fields and PASS labels are inventoried; their broad assertions are not verified by hashing.",
            "RP06, HTLC, and the shared engine have separate named source-role inventories.",
            "The 7b wallet-flow provenance is retained separately from 185a node admission source.",
            "Soak RUNNING/PASS/FAIL values are monitor reports only; PASS requires 24-hour/sample fields and still does not verify body equality or process continuity.",
            "Any soak result is not a proof-system qualification gate.",
        ],
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--precondition", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--soak", type=Path)
    parser.add_argument(
        "--evidence-bundle-dir",
        type=Path,
        help="read fixed precondition.json/context.json/measured-soak-summary.json and role-named receipt files from this directory",
    )
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    if args.evidence_bundle_dir is not None and any(
        path is not None for path in (args.precondition, args.context, args.soak)
    ):
        parser.error("--evidence-bundle-dir cannot be combined with individual evidence paths")
    try:
        report = build_report(
            args.repo,
            args.precondition or PRECONDITION_PATH,
            args.context or CONTEXT_PATH,
            args.soak or SOAK_PATH,
            args.evidence_bundle_dir,
        )
    except QualificationInputError as exc:
        print(json.dumps({"schema": SCHEMA, "inventory_status": "INVALID", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    if args.require_qualified:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
