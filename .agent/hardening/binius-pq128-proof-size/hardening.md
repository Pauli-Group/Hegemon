# Hardening decision

## Verdict

Reject the two-tier Binius leaf/aggregate proposal.

- Every Hegemon shielded transaction must remain self-contained and carry its own canonical proof.
- Peers, miners, blocks, sync, reorg replay, and fresh nodes must validate the same proof bytes.
- A block aggregate or off-chain proof cache cannot replace transaction validity.
- Poseidon remains inactive, and current Binius and Flock implementations do not meet the standalone contract.

## Quantitative result

The claimed 3,633,941-byte block assumed rather than measured a one-MiB aggregate. Measured weak-profile leaf proofs would require roughly 148-159 MiB for 520 relayed actions before strict-PQ widening, and no qualifying recursive verifier or aggregate benchmark exists. The binding target is instead one standalone artifact at or below 124,080 bytes with composed PQ128 security.

## Rejected proposal

See [Binius aggregated V5](proposals/binius-aggregated-v5.md) for the falsified design and missing assumptions.

## Selected implementation path

Use one [standalone SHAKE256 binary proof](proposals/standalone-shake256.md) per canonical transaction. Initial capacity is derived from the measured strict-PQ artifact rather than preserving the unsupported 520-transfer target.

## Rejected alternatives

- Direct Flock transaction proofs leak private witnesses and miss 128 bits.
- Direct IronSpartan bit-blasts BLAKE2b and is already 246,048 bytes for one compression at an insufficient security profile.
- Current wrapped Binius ZK is 298,304 to 321,120 bytes at an insufficient profile.
- Putting any of those proofs in every canonical action destroys the 520-action byte target.
- Re-enabling Poseidon replaces a proof-size problem with an unresolved primitive-security problem.

## Implementation authority

This portfolio grants no implementation authority. The current active transfer route remains fail-closed until a standalone proof satisfies the product invariant and release gates.
