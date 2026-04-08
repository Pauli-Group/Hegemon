# Transaction Proof SmallWood Investigation

This note answers one narrow product question:

Is SmallWood a credible next branch for a real `2x` to `3x` Hegemon transaction-proof size reduction while keeping the `128-bit` post-quantum security baseline?

The answer is:

- yes, as a serious research branch,
- no, as a drop-in replacement for the current tx AIR / Plonky3 stack.

SmallWood is much more plausible than a lattice PCS as the next aggressive proof-size branch. But it only makes sense if Hegemon is willing to build a new transaction arithmetization around SmallWood's PACS / LPPC world. It is not an “opening-layer swap” like the STIR spike.

The repo now also carries a code-derived shape report for this question:

- [tx_proof_smallwood_shape_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_shape_spike.json)
- [tx_proof_smallwood_size_probe.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_size_probe.md)
- [tx_proof_smallwood_no_grinding_soundness.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_no_grinding_soundness.md)

## Primary sources

- SmallWood paper: https://eprint.iacr.org/2025/1085.pdf
- NIST SmallWood slides: https://csrc.nist.gov/csrc/media/presentations/2026/mpts2026-4c2/images-media/mpts2026-4c2-slides-smallwood-zkp-matthieu.pdf
- Official prototype repository: https://github.com/CryptoExperts/smallwood

## What SmallWood actually is

The SmallWood paper is not “another FRI variant.” It is a different transparent proof stack.

At the construction level, the paper builds:

- `DECS`: a small-domain degree-enforcing commitment
- `LVCS`: a linear-vector commitment layer on top of DECS
- `SmallWood-PCS`: a full polynomial commitment scheme built from that LVCS
- `SmallWood-ARK`: a non-interactive zero-knowledge argument obtained by combining a PACS PIOP with SmallWood-PCS and then applying Fiat-Shamir

The key point is that the proving frontend is not AIR/FRI/STARK-shaped. It is PACS / LPPC-shaped.

That matters for Hegemon because the current transaction proof is AIR-based, not PACS-based:

- [p3_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/p3_air.rs)
- [p3_prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/p3_prover.rs)
- [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)

So SmallWood is not a PCS swap inside the current tx prover. It is a different proof system with a different frontend.

## What the paper really claims

The paper's main regime is explicit:

- relatively small extended witnesses, typically `2^6` to `2^16` field elements
- committed polynomials typically up to about `2^16` degree
- arithmetic circuits up to about `2^14` non-linear gates in the benchmark section

The paper claims that in this range SmallWood beats Ligero-style and TCitH-style schemes on proof size, especially:

- over larger fields
- for higher-degree constraints

The arithmetic-circuit results are concrete. For circuits of size `|C| = 2^12`:

- over a `256-bit` field, SmallWood-ARK reports about `86.6 KB` at `N = 8192` for degree-2 gates
- over a `256-bit` field, about `94.8 KB` at `N = 8192` for degree-8 gates
- over a `64-bit` field, about `40.8 KB` at `N = 8192` for degree-2 gates
- over a `64-bit` field, about `45.7 KB` at `N = 8192` for degree-8 gates

Those are impressive numbers. But they are numbers for SmallWood's own PACS/circuit regime, not for Hegemon's current AIR.

## Security model and release-discipline caveat

SmallWood is transparent and hash-based, which is good for Hegemon's PQ posture.

But the paper's concrete-size story also uses:

- the random oracle model
- explicit Fiat-Shamir compilation
- explicit grinding / proof-of-work parameters `κ1, κ2, κ3, κ4`
- a random salt

The paper is clear that grinding is used to relax individual soundness terms and reduce proof size.

That is an immediate Hegemon caution point. In the STIR spike, the release gate rejected candidates that relied on grinding to fill the security gap. If Hegemon keeps the same release discipline here, the paper's headline sizes are not automatically admissible as release numbers.

So for Hegemon the right reading is:

- SmallWood may still be compatible with the `128-bit` baseline,
- but the paper's concrete sizes could not be promoted directly to Hegemon release claims without a Hegemon-specific no-compromise parameter note.

That note now exists for the active integrated witness-free candidate statement. The current no-grinding candidate profile is `rho = 2`, `nb_opened_evals = 3`, `beta = 3`, `decs_nb_evals = 4096`, `decs_nb_opened_evals = 65`, `decs_eta = 10`, zero grinding bits, and it clears the term-wise `128-bit` bar for the live integrated bridge geometry. The integrated backend is now past the old scalar fallback: the packed semantic relation is real, the exact serialized proof envelope for the current Rust candidate now projects to `302828` bytes, and the passing release roundtrip emits `302836` proof bytes. That is below both the shipped `354081`-byte tx proof and the `524288`-byte native `tx_leaf` cap. So the open problem remains runtime, not proof-size feasibility.

## Official implementation status

There is an official SmallWood codebase:

- prototype repo: `https://github.com/CryptoExperts/smallwood`

That is materially better than a paper-only situation.

Useful facts from the repo:

- it is a prototype implementation in C, not production-ready
- it exposes internal modules for DECS, LVCS, PCS, PIOP, and the full SmallWood proof layer
- it has a generic LPPC interface for statements
- it already has a `f64` / Goldilocks-oriented branch in the CAPSS side of the repo

The official Goldilocks-oriented profiles also expose the first concrete release blocker for Hegemon:

- `f64_short`: opening grinding `4` bits, DECS grinding `7` bits
- `f64_default`: opening grinding `4` bits, DECS grinding `6` bits
- `f64_fast`: opening grinding `8` bits, DECS grinding `8` bits

So every official Goldilocks profile currently relies on nonzero grinding. Under Hegemon's current release discipline, those profiles are useful research baselines but not release-safe parameter sets.

Relevant prototype files:

- `/tmp/smallwood-repo/smallwood/smallwood/smallwood.h`
- `/tmp/smallwood-repo/smallwood/pcs/pcs.h`
- `/tmp/smallwood-repo/smallwood/piop/piop.h`
- `/tmp/smallwood-repo/smallwood/lppc/lppc.h`

This means a Hegemon spike can build on real code instead of reimplementing the paper from scratch.

## Mapping to Hegemon's current tx proof surface

This is the critical section.

SmallWood's claimed sweet spot is around an extended witness of at most `2^16 = 65536` field elements.

Hegemon's current tx AIR is much larger than that if translated naively.

From the current AIR code:

- `MIN_TRACE_LENGTH = 8192`
- witness-side base trace width is `104`
- full main trace width including schedule columns is `146`

Those values come from:

- [p3_air.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/p3_air.rs)
- [range.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction-core/src/range.rs)

That implies:

- base witness cells: `8192 * 104 = 851968`
- full main-trace cells: `8192 * 146 = 1196032`

Compared to the top of SmallWood's advertised sweet spot:

- base witness is about `13.0x` larger than `2^16`
- full main trace is about `18.25x` larger than `2^16`

So the direct conclusion is:

- a naive “current AIR witness -> SmallWood” translation is outside the regime the paper optimizes for

This is the single most important product fact from the investigation.

The shape spike now gives the second half of the answer from code instead of guesswork.

Hegemon also has two compact native-backend relation surfaces:

- `TxLeafPublicRelation`
- `NativeTxValidityRelation`

From the checked-in spike report:

- `TxLeafPublicRelation`: `90` witness elements, `4935` witness bits, padded witness size `128 = 2^7`
- `NativeTxValidityRelation`: `3991` witness elements, `32787` witness bits, padded witness size `4096 = 2^12`

So the actual architectural split is now explicit:

- `TransactionAirP3`: too large for SmallWood's intended witness regime
- `NativeTxValidityRelation`: inside that regime with room to spare

That is a materially stronger result than “SmallWood seems plausible.” It means Hegemon already has a live tx-validity witness surface that is the right size for a serious LPPC / PACS spike.

The same report also shows where that witness mass sits. `NativeTxValidityRelation` is dominated by:

- `input_merkle_sibling_byte`: `3072` witness elements, `24576` bits

So the next prototype target is not a vague “smaller tx witness.” It is a Merkle-heavy, note-heavy compact witness whose total padded size is still only `2^12`.

## Concrete frontend shape

The shape spike now goes one step further and proposes an actual first LPPC witness layout for that native relation instead of stopping at “it fits.”

The recommended first frontend shape is:

- `512` witness rows
- `8` packed witness elements per row
- total padded witness capacity `4096`
- zero padding `105` witness elements

The same spike compared three simple packings:

- `1024 x 4`: valid but row-heavy
- `512 x 8`: recommended balanced target
- `256 x 16`: valid but degree-heavy

For the recommended `512 x 8` candidate, the code-derived frontend numbers are:

- witness polynomial degree: `9`
- opened-evaluation payload floor: `8324` bytes

The prototype-derived degree growth at that shape is:

- semantic constraint degree `2` -> masked polynomial degree `10`, masked linear degree `16`
- semantic constraint degree `3` -> masked polynomial degree `19`, masked linear degree `16`
- semantic constraint degree `5` -> masked polynomial degree `37`, masked linear degree `16`

That gives Hegemon a concrete first SmallWood recipe:

- preserve `NativeTxValidityRelation` semantics,
- encode it as a `512 x 8` LPPC matrix witness,
- keep the proof target in the padded `2^12` regime,
- and reject any candidate profile that still needs grinding to reach the security bar.

## What would have to change for SmallWood to make sense

To use SmallWood seriously for Hegemon tx proofs, the project would have to do more than “swap the PCS.”

It would need:

1. A new tx frontend relation in PACS / LPPC form.
   The current AIR/witness path would not be preserved. The SmallWood prototype accepts LPPC-shaped matrix witnesses, not the current Plonky3 AIR trace.

2. A frontend built around the compact native tx-validity witness, not around the AIR trace.
   The shape spike now shows that `NativeTxValidityRelation` already lands at padded witness size `4096`, inside the paper's intended regime. So the right job is no longer “invent a smaller witness somehow.” The right job is “encode the existing compact tx-validity semantics as an LPPC / PACS statement.”

3. A Hegemon-specific `128-bit` no-compromise security note and no-grinding parameter search.
   That prerequisite is now satisfied for the implemented witness-free candidate statement, but not yet for the future full-semantic tx-validity arithmetization.

4. A benchmark path against the exact current tx statement.
   Apples-to-apples comparison must use the same public tx relation, not a toy circuit or CAPSS signature benchmark.

5. A prototype integration surface.
   The official code is in C and prototype quality. Hegemon would need either:
   - a clean FFI-based spike, or
   - a narrow Rust port of just the pieces needed for tx benchmarking.

## Best-case and worst-case reading

Best-case reading:

- SmallWood has real code, real proofs, and real arithmetic-circuit numbers that are much better than Hegemon's current `354081`-byte tx proof.
- Hegemon already likes transparent hash-based systems.
- The repo even has a Goldilocks-oriented implementation branch, so the field story is not absurd.
- The code-derived shape spike shows a live Hegemon tx-validity witness at padded size `4096`, which is squarely in SmallWood's intended witness window.

Worst-case reading:

- Hegemon's current tx AIR is far outside SmallWood's sweet spot.
- Reaching SmallWood's good regime still requires a fresh LPPC / PACS prover frontend and therefore a new prover stack, even though the compact native witness is now known to be in-range.
- The paper's best concrete sizes use grinding, which Hegemon may not want to count toward a release claim.

Both readings are true at once.

## Product decision

SmallWood is the right next aggressive research branch if the target remains:

- a real `2x` to `3x` tx-proof reduction,
- with a transparent hash-based PQ story,
- after the measured STIR shortfall.

But the scope must be described honestly:

- SmallWood is not a drop-in replacement for the current tx AIR path.
- It is a new transaction-proof frontend/backend project built around `NativeTxValidityRelation`-style witness semantics, not around `TransactionAirP3`.

So the right recommendation is:

- treat SmallWood as the best current `3x`-class research candidate
- only pursue it if Hegemon is willing to prototype a new PACS/LPPC-style tx relation
- do not describe it as a low-risk or incremental migration

The sharper version is:

- do not waste time trying to bolt SmallWood onto `TransactionAirP3`
- do use `NativeTxValidityRelation` as the exact proving target
- start with the `512 x 8` LPPC frontend
- require a no-grinding profile before taking any measured size seriously as a release number

One more update is now important.

The first structural size probe against the official SmallWood code shows that once the native witness is expanded to include the real Poseidon2 subtrace, SmallWood still appears to land in roughly the `75 KB .. 121 KB` range depending on packing and DECS settings.

That means the SmallWood branch is no longer just “theoretically plausible.”

It now has a measured path to roughly `3x .. 4.7x` tx-proof shrink against the current `354081`-byte baseline, provided the full semantic frontend preserves the structural result.

## Concrete next step if pursued

If Hegemon chooses to pursue SmallWood, the next step should be a narrow spike:

1. Define a minimal Hegemon tx-validity relation in LPPC/PACS form that matches `NativeTxValidityRelation` semantics.
2. Keep the padded witness at the current code-derived `4096`-element surface using the `512 x 8` frontend instead of falling back to the AIR trace.
3. Use the official prototype as the benchmark engine.
4. Preserve the current witness-free no-grinding profile discipline instead of quietly falling back to grinding-assisted settings.
5. Measure proof size and proving time under the same Hegemon-specific no-compromise `128-bit` gate already written down for the current witness-free candidate statement.

If that spike cannot get the tx witness into the paper's intended regime, SmallWood should be dropped as a tx-proof candidate regardless of how good the paper's generic numbers look.
