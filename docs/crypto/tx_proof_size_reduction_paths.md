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

The first serious spike was a STIR-class transparent PCS.

That spike is now checked in, measured, and conservative:

- report artifact: [tx_proof_stir_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_stir_spike.json)
- release-gate note: [tx_proof_stir_soundness.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_stir_soundness.md)

Primary source for the protocol family:

- “STIR: Reed-Solomon Proximity Testing with Fewer Queries,” ePrint 2024/390, https://eprint.iacr.org/2024/390

The measured release-safe result is weaker than the earlier optimistic paper-based projection.

Best conservative candidate:

- `provable_nogrind_k16_stop64_p128`
- STIR bytes in the academic prototype: `43426`
- FRI control bytes in the same prototype: `56529`
- measured STIR/FRI ratio: `0.7682`

Projected onto the exact current Hegemon tx proof:

- projected opening bytes: `268241`
- projected total bytes: `273145`
- projected total shrink: `1.2963x`

The important negative result is explicit:

- no release-supported candidate hits `2x` total reduction
- even the unsupported conjectural/grinding-assisted comparison points stay around `1.32x`, not `2x`

So the STIR spike was the right first research branch, but it did not justify a tx-proof-system migration for the current `2x` goal.

## SmallWood spike

If the target is not merely `2x`, but a real `3x` or better, the next spike to run before any lattice PCS work is a SmallWood-class small-instance transparent PCS.

Reason:

- after the measured STIR shortfall, SmallWood is the strongest remaining transparent/hash-based candidate with real literature and real code
- the target for `3x` total shrink is still clear: opening proof at or below about `113123` bytes

Primary source:

- “SmallWood: Practical Transparent Arguments for Small Circuits,” ePrint 2025/1085, https://eprint.iacr.org/2025/1085

The current repo investigation is now more concrete than the earlier optimistic placeholder:

- note: [tx_proof_smallwood_investigation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_investigation.md)
- shape spike: [tx_proof_smallwood_shape_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_shape_spike.json)
- size probe: [tx_proof_smallwood_size_probe.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_size_probe.md)

The paper and official prototype are real, but the caveat is now split cleanly into two parts:

- SmallWood’s advertised sweet spot is an extended witness around `2^6` to `2^16` field elements
- Hegemon’s current tx AIR is much larger than that if translated directly:
  - base witness cells: about `851968`
  - full main trace cells: about `1196032`
- Hegemon’s compact native tx-validity relation is inside that window:
  - raw witness elements: `3991`
  - raw witness bits: `32787`
  - padded witness size: `4096 = 2^12`

The shape spike now also fixes the first concrete frontend target:

- recommended LPPC witness layout: `512` rows x `8` packed elements
- padded capacity: `4096`
- zero padding: `105` elements
- witness polynomial degree: `9`
- opened-evaluation payload floor: `8324` bytes

The companion `TxLeafPublicRelation` is even smaller:

- raw witness elements: `90`
- raw witness bits: `4935`
- padded witness size: `128 = 2^7`

But `TxLeafPublicRelation` is not the right tx-proof replacement target because it still wraps an external STARK receipt. The real SmallWood candidate is `NativeTxValidityRelation`.

So SmallWood is not a drop-in PCS replacement for the current tx AIR path.

It only makes sense if Hegemon is willing to build a new PACS / LPPC style tx frontend around `NativeTxValidityRelation`-style witness semantics instead of the AIR trace.

There is also a hard release-discipline caveat now backed by the prototype code:

- every official Goldilocks-oriented SmallWood profile currently uses nonzero grinding bits
- under Hegemon’s current no-compromise `128-bit` rule, that means none of those profiles is directly shippable
- so a Hegemon-specific no-grinding parameter search is mandatory before SmallWood can become more than a research branch

The key new result from the size probe is that SmallWood is no longer merely a shape-fit story.

Using the official prototype with a conservative expanded Hegemon-native witness model:

- current tx proof: `354081` bytes
- best official-profile structural probe: `75128` bytes
- best default-profile structural probe: `82776` bytes
- stronger no-grinding DECS-style points still stay in about the `83 KB .. 121 KB` range

So the likely SmallWood win is no longer “maybe `2x` if everything goes right.”

It is:

- roughly `3x .. 4.7x`, if the semantic prototype preserves the structural result

The older optimistic question is still useful as an upper bound:

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

The repo’s own numbers now justify a sharper recommendation than before:

- For a release-safe proof-size win now, keep the release FRI profile unchanged.
- Do not claim STIR is a `2x` answer for the current tx circuit. The measured conservative spike says otherwise.
- If the target remains a real `2x` or `3x`, move next to a SmallWood-class semantic tx frontend before entertaining lattice PCS.
- SmallWood is now the first branch in the repo with a measured path to `3x+` transaction-proof shrink under a conservative Hegemon witness expansion model.

That ordering now follows from measured negative evidence on STIR and a more realistic SmallWood fit analysis, not from theory fashion.
