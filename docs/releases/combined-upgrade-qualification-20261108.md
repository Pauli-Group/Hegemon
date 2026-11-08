# Combined candidate qualification procedure

This procedure prepares software evidence only. Production/mainnet activation,
deployment, publication and physical ASIC qualification remain false. The root
coordinator supplies actual receipts and independent review; none are generated
by this document or the pending candidate configuration.

## Six actual suite commands

Freeze the complete source after integration, formal metadata maintenance and
source review. Each `qualification_commands` entry uses this argv shape, with
one of the six names from `check_combined_upgrade_candidate.py` and actual pins:

```text
python3 -I -B scripts/qualify_combined_upgrade.py
  --suite SUITE
  --artifact-manifest {artifact_manifest}
  --runtime-receipt release-evidence/combined-upgrade-20261108/RUN/receipt.json
  --runtime-receipt-sha256 ACTUAL_RECEIPT_SHA256
  --runtime-runner-sha256 ACTUAL_RUNNER_SHA256
  --runtime-io-sha256 ACTUAL_IO_SHA256
  --runtime-node-sha256 ACTUAL_REHEARSAL_NODE_SHA256
  --runtime-private-spend-sha256 ACTUAL_REHEARSAL_PRIVATE_SPEND_SHA256
```

These are argv elements, not shell commands or unfilled authorized configuration.
Use a bounded `timeout_seconds` no greater than 7200. Every target actually runs
the focused source suites; source-bound public external rehearsal evidence is
explicitly labeled and never replaces that target's actual final proof/H0 checks.
The ordinary final binaries retain activation `None`; the runtime transcript
records distinct feature-bearing rehearsal executables and hashes.

The producer executes exact Rust tests with a one-pass/zero-ignored predicate,
the adapter socket tests, no_std compilation and ASERT Lean/vector regeneration.
The ignored 180-block treasury reorg/restart/fresh-sync test is explicitly executed
with `--ignored --exact`. Packed witness validity is not counted as a generated
proof: the treasury spend gate additionally requires the funded runtime proof.

Before source freeze, `--focused-only --suite NAME` executes available focused
tests without an artifact manifest. Its distinct preparation receipt lists the
remaining runtime gates and cannot satisfy the final checker. A runtime-only
suite with no local test executor rejects rather than reporting a zero-test pass.

Retain only public receipts, audit output, logs inspected for private inputs,
and public proof/action/carrier wire bytes in the candidate evidence namespace.
Do not retain wallets, passphrases, seeds or private witness/prover material there.
The external receipt binds complete frozen source records, exact runtime argv,
reviewed harness/executable pins, six actual proof artifacts and process closure.

The runtime harness contains explicit live CPU-author catchup after activation,
fresh encrypted recovery and unchanged action resubmission after reorg. The
producer requires actual matching public transcripts and structured observations
for each; absent or incomplete execution remains a hard failure. Copying PASS
JSON does not satisfy them.

## Formal governance maintenance

Changed `node/src/native/{mod,block_flow,node_impl}.rs` are explicit governance
policy inputs. After a fresh real governance run, refresh both claims evidence
and active-goal acceptance evidence, then blueprint digests. There is no writer
CLI: apply the printed digests explicitly, recording actual time/log hashes.

```bash
cargo test --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml governance_
cargo run --locked --manifest-path scripts/hegemon_formal_core/Cargo.toml -- print-governance-policy-inputs-digest config/formal-security-claims.json
cargo run --locked --manifest-path scripts/hegemon_formal_core/Cargo.toml -- print-governance-policy-inputs-digest config/active-goal-progress.json
cargo run --locked --manifest-path scripts/hegemon_formal_core/Cargo.toml -- print-blueprint-review-digests config/formal-security-blueprint.json
```

Preserve review status, `needs_review`, assumptions, theorem statements,
authorization and historical goal status. A report digest for exactly 14 passed
governance tests can remain unchanged only if the fresh actual report is identical.
Determine affected blueprint nodes from exact CLI output, not the historical
86-node ASERT refresh count. Blueprint digests include recursively expanded Rust
sources and associated evidence/design/method bytes, so update these last.

```bash
bash scripts/check_formal_core.sh checker
bash scripts/check_formal_core.sh lean
bash scripts/check_formal_core.sh vectors
bash scripts/check_formal_core.sh policy
bash scripts/check_asert_formal.sh
bash scripts/check_formal_crypto.sh full
```

The policy mode includes inventory, system-model gates, claims, blueprint,
bridge vectors, historical backend rejection/posture and dependency audit;
`cargo-audit 0.22.2` is required. Ordinary policy success does not claim TLC or
Apalache execution without their explicit pinned-tool execution paths.

The old blueprint has no treasury- or ASERT-specific node. Generic PoW and mined
work theorems do not prove the new treasury schedule, fresh-versus-historical
clock policy, retry liveness or operational recovery. The standalone ASERT model
checks 14 Lean roots plus 62 arithmetic and 45 activation finite cases, without
general Rust refinement, ancestry/authenticity/liveness or release authority.
Any additive treasury model retains its own stated finite/conditional scope.
Do not change the separate `EXPECTED_V8_ATOMIC_RUNTIME_GATE_AST_BLAKE3` policy pin
merely to make a checker pass; an affected atomic function needs explicit review.

All 41 proof-source inputs and `Cargo.lock` remain fixed. Metadata maintenance
does not require a new proof relation or permit relabeling historical receipts.

## Lightweight producer verification

```bash
python3 -I -B scripts/test_qualify_combined_upgrade.py
python3 -I -B scripts/test_check_combined_upgrade_candidate.py
python3 -I -B scripts/prepare_premainnet_release_test.py
python3 -I -B scripts/test_check_ci_release_gate_policy.py
python3 -I -B scripts/prepare_premainnet_release.py --check --combined-candidate
```

These Python controls test mutation rejection and command wiring. They are not
native, funded runtime, final artifact, independent review or production evidence.
