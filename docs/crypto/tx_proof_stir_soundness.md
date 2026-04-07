# Transaction Proof STIR Spike And Release Gate

This note records the exact Hegemon-specific STIR spike, the conservative release gate applied to it, and the measured outcome on the current transaction-proof surface.

It is intentionally narrow. This is not a claim that Hegemon has a production STIR backend. It is the exact engineering note needed to answer one product question:

Can a conservative STIR-class transparent PCS, with no compromise on Hegemon's `128-bit` post-quantum release bar, plausibly deliver the `2x` transaction-proof size reduction we want on the current tx circuit?

The answer from the current spike is no.

## What stayed fixed

The spike does not touch the transaction statement, witness generation path, or main prover/verifier release plumbing.

The preserved Hegemon surfaces are:

- [p3_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/p3_air.rs)
- [p3_prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/p3_prover.rs)
- [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)

The spike is isolated in:

- [main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/spikes/stir-tx-pcs/src/main.rs)
- [Cargo.toml](/Users/pldd/Projects/Reflexivity/Hegemon/spikes/stir-tx-pcs/Cargo.toml)
- [tx_proof_stir_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_stir_spike.json)

## Exact Hegemon-matched surface

The baseline tx proof remains:

- total bytes: `354081`
- opening-proof bytes: `349177`
- non-opening bytes: `4904`

Source:

- [tx_proof_profile_sweep.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_profile_sweep.json)

The code-derived tx proof surface used for the STIR spike is:

- starting degree: `8192`
- starting rate: `2^-4`
- security target: `128`

Those values come from:

- [p3_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/p3_air.rs)
- [p3_config.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/p3_config.rs)
- [lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/protocol/versioning/src/lib.rs)

## Conservative release gate

The public STIR prototype lets proof-of-work bits fill missing security. Hegemon does not count that toward the tx proof release bar.

The release gate used by the spike is therefore stricter than the prototype defaults:

- `SoundnessType::Provable` only
- `protocol_security_level >= 128`
- every derived STIR `pow_bits` entry must be `0`

This exact gate is encoded in:

- [main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/spikes/stir-tx-pcs/src/main.rs)

Why this is conservative:

- The STIR prototype's own parameter formulas expose both repetition counts and remaining PoW bits.
- The recent concrete-security caution from Block and Tiwari shows why many-round Fiat-Shamir analyses should not be treated casually and why conjectural or grinding-assisted margins should not be silently promoted to release claims.

Primary sources:

- STIR prototype formulas and parameters: `https://github.com/WizardOfMenlo/stir`
- Alexander R. Block and Pratyush Ranjan Tiwari, “On the Concrete Security of Non-interactive FRI,” ePrint 2024/1161, https://eprint.iacr.org/2024/1161.pdf

The Block-Tiwari caution is the reason Hegemon does not accept:

- conjectural STIR soundness as a release claim
- PoW/grinding bits as part of the `128-bit` tx-proof bar

## Candidate grid that was actually measured

The checked-in spike measures a small but real parameter grid over the academic STIR implementation:

- folding factors `4`, `8`, `16`, `32`
- stopping degrees `32`, `64`, `128`, `256`
- provable `p=128` candidates
- one provable grinding-assisted comparison family at `p=112`
- one conjectural comparison family near the prototype's paper-like settings

For each candidate, the spike runs:

- STIR proof generation and verification
- the prototype's own FRI control
- the same Goldilocks-compatible field family
- the same starting degree and rate

It then projects the measured `STIR / FRI` proof-byte ratio back onto Hegemon's real measured opening-proof bytes.

## Measured outcome

The best release-supported candidate is:

- `provable_nogrind_k16_stop64_p128`

Its exact spike result is:

- STIR bytes: `43426`
- FRI control bytes: `56529`
- measured STIR/FRI ratio: `0.7682`

Projected onto Hegemon's real tx proof:

- projected opening bytes: `268241`
- projected total bytes: `273145`
- projected total shrink: `1.2963x`

That candidate is release-supported because it is:

- provable
- `protocol_security_level = 128`
- zero-PoW

Two comparison points matter:

- Best unsupported conjectural candidate: `conjectural_k16_stop64_p106`
  - projected total bytes: `266570`
  - projected total shrink: `1.3283x`
- Best unsupported grinding-assisted candidate: `provable_grinding_k16_stop64_p112`
  - projected total bytes: `267446`
  - projected total shrink: `1.3239x`

So even the unsupported “smaller” candidates still do not reach `2x` total shrink on this tx circuit.

The checked-in JSON summary makes the main point explicit:

- best release-supported candidate: `provable_nogrind_k16_stop64_p128`
- best release-supported projected total bytes: `273145`
- any release candidate hits `2x`: `false`

Source:

- [tx_proof_stir_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_stir_spike.json)

## What this means

The STIR spike did clear the security bar in the narrow sense:

- there are conservative, provable, zero-PoW candidates at Hegemon's exact tx degree/rate

But it failed the product objective that motivated the spike:

- no conservative candidate gets close to a real `2x` total tx-proof reduction
- the best release-safe point is only about `1.30x`

So the correct product decision is:

- do not rewrite the tx proof stack around STIR on the basis of this spike
- keep the current release tx FRI profile unchanged
- treat STIR as a measured negative result for the current `2x` goal on this exact tx circuit

## Reproduction

From the repository root:

```sh
cargo run --manifest-path spikes/stir-tx-pcs/Cargo.toml --release -- --json > docs/crypto/tx_proof_stir_spike.json
cargo test --manifest-path spikes/stir-tx-pcs/Cargo.toml
```

The spike is additive and does not modify the live transaction prover path.
