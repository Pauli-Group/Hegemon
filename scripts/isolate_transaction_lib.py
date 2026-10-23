#!/usr/bin/env python3
"""Run the selected transaction libtests in fresh serial processes.

This releases allocator state between tests; an exact failing or oversized test
still fails. Ignored tests and explicit release exclusions are never passes.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys

ALLOWED_SKIPS = frozenset([
    'private_multisig_accumulator::tests::private_multisig_accumulator_matches_lean_vectors',
    'proof::tests::lean_generated_transaction_proof_wrapper_wire_vectors_match_production',
    'smallwood_frontend::tests::lean_generated_smallwood_candidate_wrapper_admission_vectors_match_production',
    'smallwood_frontend::tests::lean_generated_smallwood_production_constraint_maps_match_every_production_row',
    'smallwood_frontend::tests::lean_generated_legacy_level5_transcript_binding_vectors_match_runtime_codec',
    'asset_recovery_capsule_v1::tests::actual_graph_rejects_wrong_secret_owner_commitment_and_ciphertext',
    'asset_recovery_capsule_v1::tests::segment_graphs_repeat_opening_checks_and_cover_exact_chacha_stream',
    'asset_recovery_chacha_v1::tests::four_block_240_byte_graph_matches_host_and_rejects_mutations',
    'asset_recovery_geometry_v1::emit_exact_graph_costs',
    'asset_spend_v1::tests::asset_spend_combined_graph_reuses_policy_for_all_operations',
    'asset_spend_v1::tests::asset_spend_combined_policy_credentials_cover_entire_reference_window',
    'asset_spend_v1::tests::asset_spend_credential_horizon_covers_later_policy_branch',
    'asset_spend_v1::tests::asset_spend_policy_height_authority_and_release_are_mandatory',
    'asset_spend_v1::tests::asset_spend_recovery_shares_nullifier_and_cannot_bypass_current_policy',
    'asset_spend_v1::tests::asset_spend_policy_credentials_bind_full_owner_and_zero_change',
    'smallwood_frontend::tests::lean_generated_smallwood_verifier_statement_projection_vectors_match_production',
    'smallwood_recursive::tests::lean_generated_smallwood_recursive_envelope_wire_vectors_match_production',
    'smallwood_htlc_transport::tests::strict_source_projection_stays_inside_independent_carrier_cap',
])


def run(command, timeout):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command!r}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result.stdout


def names(output, allow_empty=False):
    result = []
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([^\s]+): test", line)
        if not match:
            raise RuntimeError(f"invalid libtest inventory line: {line!r}")
        result.append(match.group(1))
    if len(result) != len(set(result)) or (not result and not allow_empty):
        raise RuntimeError("duplicate or empty libtest inventory")
    return set(result)


def discover(cargo, timeout):
    output = run([cargo, "test", "--locked", "-p", "transaction-circuit", "--lib",
                  "--no-run", "--message-format=json"], timeout)
    executables = []
    for line in output.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if (row.get("reason") == "compiler-artifact"
                and row.get("profile", {}).get("test") is True
                and re.search(r"#transaction-circuit@[A-Za-z0-9.+-]+$", row.get("package_id", ""))
                and row.get("target", {}).get("name") == "transaction_circuit"
                and "lib" in row.get("target", {}).get("kind", [])
                and row.get("executable")):
            executables.append(Path(row["executable"]).resolve())
    if len(executables) != 1 or not executables[0].is_file():
        raise RuntimeError("Cargo must identify exactly one existing libtest executable")
    return executables[0]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--skip", action="append", default=[], choices=sorted(ALLOWED_SKIPS))
    parser.add_argument("--timeout", type=float, help="optional per-command timeout in seconds")
    args = parser.parse_args(argv)
    if ((args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0))
            or len(args.skip) != len(set(args.skip))):
        raise RuntimeError("timeout must be positive and skips must be unique")
    binary = discover(args.cargo, args.timeout)
    before = digest(binary)
    listed = names(run([str(binary), "--list", "--format", "terse"], args.timeout))
    ignored = names(run([str(binary), "--ignored", "--list", "--format", "terse"],
                        args.timeout), allow_empty=True)
    excluded = set(args.skip)
    if not ignored <= listed or not excluded <= listed:
        raise RuntimeError("ignored or excluded test is absent from complete inventory")
    selected = listed - excluded
    runnable = sorted(selected - ignored)
    if not runnable:
        raise RuntimeError("selection contains no executable tests")
    for name in runnable:
        output = run([str(binary), name, "--exact", "--nocapture", "--test-threads=1"],
                     args.timeout)
        results = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; "
                             r"(\d+) ignored; (\d+) measured; (\d+) filtered out;.*$",
                             output, re.MULTILINE)
        if results != [("1", "0", "0", "0", str(len(listed) - 1))]:
            raise RuntimeError(f"invalid exact-test result for {name}: {output}")
        print(output.rstrip(), flush=True)
        print(f"PASS {name}", flush=True)
    if digest(binary) != before:
        raise RuntimeError("libtest executable changed during run")
    inventory = {"all": sorted(listed), "ignored": sorted(ignored), "excluded": sorted(excluded)}
    selection_sha = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    print(json.dumps({"status": "PASS", "discovered": len(listed), "ignored": len(ignored),
                      "excluded": len(excluded), "selected": len(selected),
                      "selected_ignored": len(selected & ignored), "executed": len(runnable),
                      "binary_sha256": before, "selection_sha256": selection_sha,
                      "inventory": inventory}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
