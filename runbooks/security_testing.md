# Security Testing Runbook

This runbook explains how to run, debug, and report on the adversarial security pipelines introduced in `docs/SECURITY_REVIEWS.md` and referenced by the `security-adversarial` CI job.

## 1. When to run this

- Before tagging a release.
- After modifying transaction witnesses, note hashing, consensus/network handshakes, or wallet address derivations.
- Whenever the `security-adversarial` job fails in CI.

## 2. Commands

All commands assume repository root. Use a deterministic proptest cap so local results match CI.

```bash
export PROPTEST_MAX_CASES=64

# Transaction witness fuzzing
cargo test -p transaction-circuit --test security_fuzz -- --nocapture

# Network handshake adversarial tests
cargo test -p network --test adversarial -- --nocapture

# Wallet address fuzz/mutation tests
cargo test -p wallet --test address_fuzz -- --nocapture

# Cross-component adversarial flow
cargo test security_pipeline -- --nocapture
```

Collect the last 50 lines of each command’s output and attach them to the incident ticket or PR.

## 3. Formal model checks

Run these whenever you touch circuit balance logic or consensus view/commit rules:

```bash
# MASP balance + nullifier uniqueness
cd circuits/formal
# TLC
/path/to/tlc -deadlock -workers 4 transaction_balance.tla -config transaction_balance.cfg
# Apalache (optional)
apalache-mc check --max-steps=15 --inv=BalanceInvariant transaction_balance.tla

# HotStuff safety/liveness
cd ../../consensus/spec/formal
/path/to/tlc -deadlock hotstuff_safety.tla -config hotstuff_safety.cfg
apalache-mc check --max-steps=10 --inv=NoDoubleCommit hotstuff_safety.tla
```

If TLC/Apalache is unavailable on the build host, note that in the PR and paste the command you ran elsewhere.

## 4. Failure triage

1. Capture artifacts:
   - For fuzz failures, save the minimal counterexample (proptest prints the seed) and include it in the GitHub issue.
   - For handshake/address failures, dump the serialized transcript or address string to help reproducer.
   - For model checking failures, keep the `*.out` file TLC/Apalache emits.
2. File/locate a tracking issue referencing the failing command, seed, and Git commit.
3. Update `docs/SECURITY_REVIEWS.md` with a temporary finding ID if the issue came from an external audit.
4. Patch the code, add a regression test if missing, and rerun the entire command list before closing the incident.

## 5. Escalation

- Cryptographic bugs → ping the cryptography lead and open a private issue. Reference the relevant finding in `docs/SECURITY_REVIEWS.md` once disclosed.
- Consensus/network bugs → notify the on-call mining node operator list or pool maintainers; pause releases until the adversarial run passes.
- Wallet/address bugs → notify the wallet maintainer channel and consider disabling affected address derivations until patched.

Document every incident in the PR or issue timeline so auditors can reconstruct the response.
