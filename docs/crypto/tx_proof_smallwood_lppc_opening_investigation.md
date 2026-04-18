# SmallWood LPPC Frontend and Opening-Layer Investigation

This note answers one narrow question on the current tree:

What is left to do if Hegemon wants to beat Hegemon’s current SmallWood tx proof materially, and how much of that job belongs to a real semantic LPPC frontend versus a new opening layer?

The answer is now concrete:

- the current bridge-side geometry work is close to exhausted,
- a real semantic LPPC frontend is still the highest-value branch,
- the new structural semantic LPPC frontier on the current engine is much stronger than the earlier conservative bridge-side estimate,
- and opening-layer work is now the fallback branch, not the precondition for a plausible sub-`80 kB` line.

## Current exact baseline

The current shipped line is measured in:

- [tx_proof_smallwood_current_size_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_current_size_report.json)

Current shipped numbers:

- structural upper bound: `90830`
- current exact sampled proof bytes on the current benchmark witness: `87086 .. 87214`
- remaining DECS multiproof headroom on the live opened set: at most `8` duplicate sibling nodes, or `256` raw digest bytes before multiproof flags / format overhead
- wrapper: `12`
- transcript: `9488`
- sampled commitments / auth paths: `7321 .. 7449`
- opened values: `23944`
- opening payload: `46321`

Inside the current opening payload:

- opened witness rows: `30157`
- DECS high coefficients: `14500`
- PCS recombination tails: `1108`
- DECS masking evals: `556`

So the current proof is no longer large because of wrapper fluff or public metadata. The dominant remaining cost is still the opening line, and inside that opening line the biggest two objects are:

- `opened_witness_bytes`
- `decs_high_coeffs_bytes`

That matters because those are the two buckets the semantic LPPC branch is most likely to shrink even if the rest of the engine stays unchanged.

## New projection-only semantic LPPC frontier

The repo now has a real semantic LPPC frontend seam and a checked structural projection path:

- [tx_proof_smallwood_semantic_lppc_frontier_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_lppc_frontier_report.json)

This is not a fake “idealized raw witness” note anymore. The new module:

- materializes the exact `NativeTxValidityRelation` witness order from `TransactionWitness`,
- binds the same native statement hash and serialized public-input digest the shipped tx proof uses,
- fixes the semantic LPPC v1 window at `4096` elements,
- and runs that exact witness shape through the current SmallWood structural projection and soundness machinery.

The current measured frontier on the active no-grinding profile is:

| shape | constraint estimate | projected bytes |
|---|---:|---:|
| `1024 x 4` | `1270` | `52874` |
| `512 x 8` | `712` | `36346` |
| `256 x 16` | `433` | `31154` |

All three points still clear the exact current no-grinding `128-bit` structural floor in the report.

The crucial caveat is unchanged:

- these are **structural projections**, not full prove/verify roundtrips yet,
- so they prove the frontend size potential, not that the current row-polynomial prover can already consume the new semantic LPPC witness directly.

That said, the direction of the result is no longer ambiguous. If the semantic LPPC frontend can be realized without reintroducing large bridge-local witness baggage, the current opening line is already compatible with a proof far below `80 kB`.

## Exact current-engine opening-layer spike

The repo now also has the next stronger check:

- [tx_proof_smallwood_semantic_lppc_identity_spike_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_lppc_identity_spike_report.json)

This report is generated from sampled real current-engine SmallWood prove/verify roundtrips over the same semantic LPPC witness window, but using identity constraints over the full packed witness matrix. That makes it an opening-layer/backend spike, not a valid tx-proof replacement.

The exact current-engine bytes are:

| shape | exact bytes | projected bytes |
|---|---:|---:|
| `1024 x 4` | `49843` | `52874` |
| `512 x 8` | `33347` | `36346` |
| `256 x 16` | `28283` | `31154` |

That result matters more than it first looks:

- the current SmallWood opening layer is **not** where the semantic LPPC branch is losing ground,
- the structural projections were conservative rather than optimistic,
- and the current engine can already carry that witness window at lower exact byte counts once the statement is reduced to identity form.

But that was still only the pure packed witness window. The next question was whether the current backend can still win once the nonlinear relation needs some lane-visible helper rows back.

## Current-backend helper floor

The repo now measures that directly in:

- [tx_proof_smallwood_semantic_helper_floor_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_helper_floor_report.json)

This branch is still not a full semantic tx proof. It is a structural lower bound for the exact current backend once the witness carries:

- the packed semantic `NativeTxValidityRelation` window,
- the grouped Poseidon trace,
- and the minimum lane-visible helper rows the current nonlinear relation would need back:
  - input value / asset rows,
  - input direction-bit rows,
  - input `current / left / right` aggregate rows,
  - output value / asset rows.

The measured frontier is:

| shape | helper rows | total secret rows | bytes |
|---|---:|---:|---:|
| `32x` | `264` | `392` | `113362` |
| `64x` | `264` | `328` | `99794` |
| `128x` | `264` | `296` | `117586` |

The exact current-engine identity spike for the winning `64x` point also matches the projection exactly:

- `99794` bytes

That is the decisive current-backend result:

- the pure semantic lower bound is `97130`,
- but the moment the current nonlinear adapter needs lane-visible helper rows back as explicit opened rows, the floor jumps to `99794`,
- which is already above the shipped `90830`-byte structural upper bound.

So the blocker is now much narrower and more concrete:

- on the current backend, a true semantic adapter has almost no room left if helper structure returns as explicit opened rows,
- and the live question is now whether that helper surface can move through a smaller transport path.

## Auxiliary-subtrace path is dead on the current engine

The next obvious fallback was: keep the small semantic LPPC witness window and move the explicit Poseidon2 subtraces into the auxiliary-witness channel.

The repo now measures that directly in:

- [tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_lppc_auxiliary_poseidon_spike_report.json)

The measured current-engine projection with the full current Poseidon2 subtrace carried as auxiliary witness is:

| shape | auxiliary words | projected bytes |
|---|---:|---:|
| `1024 x 4` | `54912` | `493536` |
| `512 x 8` | `54912` | `477072` |
| `256 x 16` | `54912` | `472008` |

Those numbers are not close to the current shipped proof. They are all about `5.4x .. 5.7x` worse than the current checked `87086 .. 87214`-byte band and far above the `90830`-byte structural upper bound.

There is now also a stronger exact result on the current engine:

- the exact `512 x 8` auxiliary spike roundtrips cleanly,
- and it lands exactly where the projection said it would: `477072` bytes.

The earlier fail-closed exact result was caused by an engine bug, not by a good design property. The verifier replay path was incorrectly substituting auxiliary witness words for linear targets during transcript recomputation. Once that was fixed, the exact spike matched the structural projection and stayed obviously dead on bytes.

That means the auxiliary-subtrace branch is still dead, but now for the honest reason:

- it is far too large,
- not because the engine replay path happened to reject it.

So the next branch is not:

- “semantic LPPC witness + auxiliary Poseidon baggage”

It is:

- a truly semantic LPPC frontend that keeps the hash work row-local and low-degree without smuggling the current bridge subtrace through the auxiliary witness channel.

## Compact helper-aux backend floor

The same backend fix exposed one live current-engine branch:

- [tx_proof_smallwood_semantic_helper_aux_report.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_semantic_helper_aux_report.json)

This branch keeps:

- the packed semantic `NativeTxValidityRelation` window,
- the grouped Poseidon trace in the opened row domain,

but moves only the lane-visible helper rows into the auxiliary witness channel instead of paying for them as explicit opened rows.

The measured frontier is:

| shape | auxiliary helper words | witness rows | bytes |
|---|---:|---:|---:|
| `32x` | `264` | `2048` | `105970` |
| `64x` | `264` | `1216` | `92402` |
| `128x` | `264` | `800` | `110194` |

The exact current-engine identity spike for the winning `64x` point also matches the projection exactly:

- `92402` bytes

This was the first real current-backend branch that beat the old `98532`-byte shipped line. It no longer beats the current shipped inline-Merkle line, which now has a `90830`-byte structural upper bound and current exact sampled proofs in the `87086 .. 87214` band.

## 2026-04-17 semantic-adapter floor rerun

The next concrete semantic branch is now measured too.

It keeps:

- inline Merkle aggregate transport,
- skip-initial-MDS grouped Poseidon rows,
- and derives the remaining lane-local helper surface from the semantic witness instead of shipping it through the auxiliary vector.

That frontier currently lands at:

| shape | auxiliary helper words | projected bytes | exact bytes |
|---|---:|---:|---:|
| `32x` | `0` | `101698` | not run |
| `64x` | `0` | `88994` | `86795 .. 86955` |
| `128x` | `0` | `107218` | not run |

This is the first semantic-adapter floor that beats the current shipped proof exactly on the current tree.

But the win is only:

- `87086 - 86955 = 131` bytes at the high end of the current exact band
- `87086 - 86795 = 291` bytes at the low end of the current exact band

So the branch is a useful floor, not a promotion candidate:

- it proves the semantic route can beat the shipped line without restoring helper rows,
- but it misses the low-`80s` target by a lot,
- and it misses the low-`80s` ExecPlan material keep bar too.

The important surprise is that the structural projection was conservative here:

- projected: `88994`
- exact: `86795 .. 86955`

So the semantic branch should now be judged on exact proofs, not only structural projections.

## 2026-04-17 opening branch rerun

The opening-layer branch remains a measured negative result on the current tree.

Revalidated on the current shipped line:

- current tiled planner: `90830`
- shared-row LVCS projection: `92326`
- shared-row subset width drops from `128` to `64`
- but the soundness floor also drops to `110.62` bits

And the two-opening frontier is still empty:

- `smallwood two-opening frontier active=90830 top=[]`

So the current opening-layer redesign status is still:

- shared-row LVCS rewrite: dead
- two-opening profile: dead
- no current backend-only opening branch has crossed the low-`80s` bar

## What the bridge-side work already proved

The live bridge and compact-binding experiments are now enough to say what the current engine does and does not reward.

Measured branches:

- bridge baseline: `100956`
- compact bindings: `99828`
- former shipped default, compact bindings + skip initial MDS row: `98532`
- current shipped default, compact bindings + inline Merkle + skip initial MDS row: structural upper bound `90830`, checked exact sampled proofs in the `87086 .. 87214` band

The important observation is not just that the gains were small. It is where the gains landed.

Comparing the active bridge report against the compact-binding report:

- `transcript_bytes`: unchanged
- `commitment_bytes`: unchanged
- `opened_values_bytes`: unchanged
- `pcs_subset_evals_bytes`: unchanged
- `decs_auth_paths_bytes`: unchanged
- only `opened_witness_bytes` and `decs_high_coeffs_bytes` moved materially

So on the current backend, frontend shrink does **not** currently buy:

- smaller subset-eval payloads,
- smaller auth paths,
- or a smaller transcript.

It mostly buys a smaller opened-witness surface and smaller DECS high-coefficient payloads.

That is the exact reason the bridge-side frontier is no longer the main game.

## What a real semantic LPPC frontend means here

The right semantic target is not the old AIR trace. It is:

- [NativeTxValidityRelation](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs)

The current code-derived witness surface for that relation is already checked in:

- raw witness elements: `3991`
- padded witness size: `4096 = 2^12`
- recommended raw LPPC layout: `512 x 8`

Sources:

- [tx_proof_smallwood_shape_spike.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_shape_spike.json)
- [tx_proof_smallwood_investigation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_investigation.md)

The important caveat is also explicit now:

- `4096` elements is the **raw semantic witness** target,
- not the full extended proving surface once Poseidon2 work is accounted for.

The more realistic size prior is still the conservative size probe:

- [tx_proof_smallwood_size_probe.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_smallwood_size_probe.md)

That note uses the official SmallWood prototype with a conservative Hegemon-native expanded witness model and lands in roughly:

- `75 kB .. 121 kB`

So the right reading is:

- the semantic LPPC branch is real,
- but it should be judged against the current shipped line (`90830` upper bound, `87086 .. 87214` checked exact bytes),
- not against the overly optimistic raw-`4096` witness story alone.

## What the semantic LPPC frontend can actually remove

Relative to the current row-aligned bridge, a real semantic LPPC frontend can drop whole classes of bridge-specific structure:

- grouped-row Poseidon boundary rows,
- bridge-local continuation framing,
- row-aligned current/left/right Merkle aggregate neighborhoods,
- bridge-shaped secret rows whose only job is to make the current row-polynomial local gate geometry work.

What it must still carry is the actual semantic mass:

- note values and asset ids,
- note recipient/auth/randomness material,
- Merkle sibling bytes,
- ciphertext hashes,
- fee / value-balance fields,
- stablecoin binding fields,
- enough hash-trace structure to prove note commitments, nullifiers, and Merkle nodes honestly.

That is why the semantic LPPC branch can beat the current bridge materially, but not magically collapse to the raw `4096`-element witness floor.

## Exact frontend-only thresholds on the current engine

If the transcript, commitments, and opened-values buckets stay fixed and only the current opening payload shrinks, then the exact totals are:

| opening_payload shrink | total proof bytes |
|---:|---:|
| `10%` | `95505` |
| `20%` | `90054` |
| `30%` | `84604` |
| `40%` | `79153` |
| `50%` | `73702` |

This is the useful engineering reading:

- `< 95 kB` requires only about an `11%` shrink in the current `54508`-byte opening payload
- `< 90 kB` requires about a `20%` shrink
- `< 85 kB` requires about a `29%` shrink
- `< 80 kB` requires about a `38%` shrink

The current bridge-side work only achieved about a `2%` opening-payload reduction:

- `54508 -> 53380`

So the next frontend branch has to be much more structural than the compact-binding cleanup if it is going to matter.

## Expected gain from a real semantic LPPC frontend

The earlier conservative estimate treated the semantic LPPC branch as “probably enough for `< 90 kB`, maybe not enough for `< 80 kB`.” The new structural frontier changes that reading.

The current evidence now says:

- bridge-local cleanup is still only worth a couple of kilobytes,
- the semantic LPPC frontend itself is the real lever,
- and the current opening line is already compatible with that witness window in exact prove/verify runs.

But the helper-floor spike changes what “real lever” means.

The main risk is no longer “will the opening layer kill us?” The main risk is:

- whether the current backend can expose enough lane-local structure to the nonlinear relation without restoring so much helper baggage that the branch loses immediately.

Right now the evidence says the answer is probably **no** on the current backend model:

- pure semantic lower bound: `97130`
- compact helper-aux floor: `92402`
- lane-visible helper floor: `99794`
- shipped default proof: structural upper bound `90830`, checked exact sampled proofs `87086 .. 87214`

That means the semantic LPPC frontend is still the right conceptual direction, but the live backend question is now narrower. The moment the nonlinear relation pays for helper rows as explicit opened rows, the branch is underwater. If the helper surface moves through auxiliary instead, the backend floor drops below the shipped default again.

## The current/left/right Merkle aggregate rows are structural on the current engine

There is one more dead branch that is worth naming explicitly because it looks attractive on paper.

The obvious next shrink after the compact-binding branch is:

- remove the per-level `current / left / right` Merkle aggregate witness rows,
- keep only the direction bits plus the packed Poseidon subtrace,
- and derive the Merkle join relation directly from the Poseidon row starts.

That does **not** work on the current row-polynomial backend.

The blocker is not arithmetic degree. The blocker is the opened-witness view itself.

Today the nonlinear adapter receives:

- one scalar per packed row polynomial at the random evaluation point,
- not the per-lane values inside that packed row.

The grouped Poseidon rows are lane-packed by permutation group. So for any given Merkle level:

- the prior digest you want (`current`) lives in the output lane of one specific permutation inside a group,
- the left/right absorbed digests live in the start rows of one or two specific permutations inside that same group,
- but the nonlinear adapter does not know or recover those individual packed-lane values from the one opened row scalar.

That means a naive “inline Poseidon” branch cannot soundly replace the explicit aggregate rows. The only ways around this on the current engine are:

- keep dedicated aggregate rows that linear constraints bind to the relevant lane-specific Poseidon data, or
- redesign the backend/opening model so the nonlinear adapter gets lane-aware openings.

So the `current / left / right` rows are not just lazy frontend baggage. On the current backend they are the mechanism that makes lane-specific Merkle linkage visible to the nonlinear relation at all.

That narrows the remaining honest options:

- a real semantic frontend that still carries some explicit lane-independent Merkle linkage rows, or
- a deeper backend redesign that changes the opened-witness model.

## What the opening-layer branch has to attack

On the current exact proof, a new opening layer matters only if it materially reduces one or more of these buckets:

- `opened_witness_bytes = 34876`
- `decs_high_coeffs_bytes = 17648`
- `pcs_subset_evals_bytes = 24776`
- `decs_auth_paths_bytes = 11720`

Those four buckets alone are `87246 - 12 = 87234` bytes of the current checked sampled proof, and the structural upper-bound report still allocates `90830 - 12 = 90818` bytes inside the wrapper.

That gives two different opening-layer targets.

### Opening target A: better opening line on the same statement

This branch keeps the winning statement and changes how openings are authenticated / transmitted.

The point is to shrink:

- opened witness row scalars,
- DECS high-coefficient payloads,
- ideally subset-eval payloads too.

If an opening-layer branch cuts the whole opening-related surface (`commitment + opened_values + opening_payload`) by:

| full opening-ish shrink | total proof bytes |
|---:|---:|
| `10%` | `91814` |
| `20%` | `82672` |
| `30%` | `73530` |

So even a modest real opening-layer win is much more powerful than another local bridge cleanup.

But after the exact identity spike, this branch is no longer the first thing to do. The current opening layer already matches the semantic LPPC structural frontier exactly on the identity statement.

### Opening target B: combine semantic LPPC and a better opening line

This is the branch that actually targets the aggressive proof bands.

If the real semantic LPPC frontend lands well above the new structural frontier, then a new opening line is still the best second-stage attack. In that case, if the semantic LPPC frontend gets the proof only into the high `80`s or low `90`s and a new opening line then cuts the remaining opening surface by another `10% .. 20%`, the resulting total still lands plausibly in the:

- low `80 kB`
- or even high `70 kB`

That remains the fallback path for a strong sub-`80 kB` tx proof if the real semantic frontend loses too much of the new structural win.

## What to implement first

The right order is narrower now.

### 1. Treat the current-backend semantic adapter as mostly killed

Concrete implementation seam:

- add a new module such as `circuits/transaction/src/smallwood_lppc_frontend.rs`
  or another clearly named sibling under `circuits/transaction/src/`
- target [NativeTxValidityRelation](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), not the AIR trace
- keep the frontend witness shape explicit and parameterized:
  - `512 x 8` first
  - `1024 x 4` and `256 x 16` only as comparison points

The exact current-backend evidence is now:

- identity semantic LPPC window: `31154 .. 52874`
- current-backend lower bound with grouped Poseidon plus structural Merkle linkage: `97130`
- compact helper-aux floor with grouped Poseidon plus helper transport in auxiliary: `92402`
- current-backend helper floor once lane-visible nonlinear helper rows return: `99794`

So a real semantic adapter on the current backend is no longer “mostly killed.” It is now conditional:

- if the adapter has to restore explicit helper rows, it loses,
- if the adapter can consume helper structure through the auxiliary path without inflating that path, there is still a real current-backend win left.

### 2. Attack the opened-row model or opening layer next

That leaves two serious branches:

- change the backend/opened-row model so the nonlinear adapter can see lane-local structure without paying the duplicated helper-row tax, or
- keep the current statement winner and shrink the opening/authentication surface directly.

### 3. Only revisit the semantic LPPC frontend if the backend model changes

The next opening-layer branches should be aimed at the exact dominant current buckets:

- row-opening payload,
- DECS high coefficients,
- subset-eval payloads.

The opening-layer branch is only worth integrating if it clearly beats the semantic LPPC line by at least another:

- `10% .. 15%`

on exact total proof bytes while preserving the same no-grinding `128-bit` rule.

## Bottom line

The repo is already past the “maybe SmallWood helps” stage.

The exact current situation is now:

- the bridge-side local cleanup frontier is mostly exhausted,
- the pure semantic LPPC witness window is still dramatically smaller,
- the current backend loses that win once the nonlinear relation has to regain lane-visible helper rows as explicit opened rows,
- but the compact helper-aux floor now lands at `92402`, which is still above the shipped `90830`-byte structural upper bound.

So the correct next move is no longer “frontend churn is dead on this backend.” The next move is narrower and more technical:

It is:

1. use the compact helper-aux floor as the new backend target for a real semantic adapter,
2. or attack the opening/authentication surface on the shipped winning statement,
3. and kill the branch honestly if the real adapter cannot stay close to the `92402` helper-aux floor.
