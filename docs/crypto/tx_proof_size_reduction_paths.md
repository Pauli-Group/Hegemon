# Transaction Proof Size Reduction Paths

This note answers one narrow product question: where should Hegemon spend effort if it wants a real `2x` or `3x` transaction-proof size reduction while keeping the current transparent, post-quantum baseline?

The answer comes from the exact current proof composition, not from generic proof-system marketing.

## Current proof composition

The exact current release transaction proof is measured by [tx_proof_profile_sweep.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_profile_sweep.json).

At the active release profile:

- Total bytes: `354081`
- Commitments bytes: `115`
- Opened-values bytes: `4788`
- Opening-proof bytes: `349177`
- Non-opening bytes floor: `4904`
- Opening-proof share of total: about `98.6%`

Inside the opening proof, the dominant serialized component is the query-proof list:

- Opening query proofs: `348405` bytes

So the tx proof is not large because of public inputs, digest encodings, or some huge verifier profile blob. It is large because the current transparent PCS spends almost all of its bytes answering many opening queries.

## What lowering FRI queries buys today

The current code-derived sweep at fixed `log_blowup = 4` gives:

- `32 -> 354081` bytes
- `28 -> 310631` bytes
- `24 -> 267031` bytes
- `20 -> 223474` bytes
- `16 -> 179934` bytes

That means `16` queries gives almost a `2x` total-byte win on the exact shipped tx circuit.

But that path is blocked by the current release rule. At fixed `log_blowup = 4`, the heuristic FRI term falls from `128` bits at `32` queries to only `64` bits at `16` queries. Under the current Hegemon release discipline, this is not acceptable.

So the honest reading is:

- query cuts are good for bytes,
- query cuts are not currently good enough for the release security floor.

## Exact shrink target for a PCS replacement

Because almost all proof bytes are in the opening layer, the required target for a replacement PCS can be computed exactly.

To get a full `2x` total-proof reduction from the current `354081` bytes, the opening proof must fall to about `172136` bytes. That means the opening proof itself must shrink by about `2.03x`.

To get a full `3x` total-proof reduction, the opening proof must fall to about `113123` bytes. That means the opening proof itself must shrink by about `3.09x`.

These are the real targets. Any candidate that does not plausibly hit them on the opening layer will not produce the desired total-byte win.

## STIR spike

The first serious spike to run is a STIR-class transparent PCS.

Reason:

- It attacks the exact dominant cost center: opening proofs.
- It preserves the transparent hash-based story instead of adding a second major lattice review surface.
- It is the strongest near-term candidate for a real `2x` win without changing the transaction statement itself.

The current tx-circuit spike uses the range reported by the STIR paper for argument-size improvements over optimized FRI arguments and applies it only to the opening-proof component.

Primary source:

- “STIR: Reed-Solomon Proximity Testing with Fewer Queries,” ePrint 2024/390, https://eprint.iacr.org/2024/390

Applied to the exact current Hegemon tx proof:

- If only the opening proof shrinks by `1.25x`, projected total bytes are `284246`
- If only the opening proof shrinks by `2.46x`, projected total bytes are `146846`

Interpretation:

- The low end does not reach `2x` total reduction.
- The strong end does cross `2x` total reduction.
- STIR is therefore the best current product-path candidate for a real `2x` tx-proof win.

## SmallWood spike

If the target is not merely `2x`, but a real `3x` or better, the next spike to run before any lattice PCS work is a SmallWood-class small-instance transparent PCS.

Reason:

- Hegemon’s current tx AIR has only `8192` rows.
- That is exactly the regime where a small-instance proof system is plausible.
- The target for `3x` total shrink is clear: opening proof at or below about `113123` bytes.

Primary source:

- “SmallWood: Practical Transparent Arguments for Small Circuits,” ePrint 2025/1085, https://eprint.iacr.org/2025/1085

The current repo spike is deliberately labeled as a spike, not a claim. It asks a single optimistic question:

- what would total proof size be if the opening proof were only `25 KiB`?

On the current proof composition, that would project to:

- `30504` total bytes

That is far beyond the `3x` target. It does not prove Hegemon can get there. It does prove that if a SmallWood-class system works well in this exact `8192`-row regime, the total-byte upside could be very large.

## Why not start with lattice PCS

There are lattice polynomial-commitment papers with attractive asymptotic claims. That does not make them the first Hegemon move.

The current tx proof is already transparent and post-quantum. The dominant gap is byte cost in the opening layer. Hash-based transparent PCS work attacks that gap directly without forcing Hegemon to add another lattice security surface to the transaction proof stack while the native backend is already carrying lattice review burden elsewhere.

So the ordering should stay:

1. Keep the current release profile at `(4, 32, 0)`.
2. Do not ship a lower-query release profile under the current rule.
3. Prototype a STIR-class replacement first for a realistic `2x` attempt.
4. If `3x` still matters, run a SmallWood-class spike next.
5. Only then reconsider lattice PCS.

## Practical recommendation

The repo’s own numbers now justify one blunt recommendation:

- For a release-safe proof-size win now, keep the release FRI profile unchanged.
- For the next serious engineering project, prototype STIR on the tx circuit.
- For the next aggressive research spike beyond that, prototype SmallWood before lattice PCS.

That ordering follows directly from the measured proof composition, not from theory fashion.
