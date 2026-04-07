# Transaction Proof SmallWood Size Probe

This note answers the question the earlier shape note did not finish:

Would a SmallWood-style transaction proof actually reduce Hegemon transaction proof size, or was the whole branch a category error?

The answer is now concrete:

- yes, it can reduce proof size materially,
- but only if the proving frontend includes the real native hash trace and uses an aggressive LPPC packing,
- and the good result comes from a new tx-proof frontend, not from swapping SmallWood into the current AIR.

## Current baseline

The current shipped Hegemon transaction proof is:

- `354081` bytes

Source:

- [tx_proof_profile_sweep.json](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/tx_proof_profile_sweep.json)

## What was measured

The SmallWood codebase was compiled directly from the official prototype under `/tmp/smallwood-repo`, using a synthetic LPPC statement with the same witness shape and the same effective constraint degree Hegemon would need for Poseidon2-heavy native tx validity.

Important point:

- this is not a fake paper extrapolation,
- but it is also not a full semantic implementation of Hegemon tx validity inside SmallWood yet.

The probe uses the official `smallwood_max_sizeof_proof(...)` path, which sizes the proof from:

- witness row count,
- packing factor,
- constraint degree,
- `rho`,
- number of opened evaluations,
- PCS/LVCS/DECS parameters.

That is the right thing to test here because proof size in the prototype is dominated by those structural parameters, not by the content of the witness or by the particular algebra inside the callback bodies.

## Why the first naive result was misleading

If SmallWood is pointed only at the raw native tx witness surface:

- raw native witness elements: `3991`
- recommended raw LPPC shape from the earlier spike: `512 x 8`

then the official prototype gives proof sizes around:

- `33896` bytes (`short`)
- `36168` bytes (`default`)
- `41416` bytes (`fast`)

Those numbers are excellent, but they are incomplete because they omit the internal hash-trace witness required to prove tx validity.

So that raw-witness-only result is not the real tx-proof answer.

## Expanded native witness estimate

To get the real answer, the probe expands the native witness by the Poseidon2 work needed for transaction validity.

The conservative accounting is:

- raw native witness: `3991` field elements
- `145` Poseidon2 permutations
- `384` witness elements per permutation

giving:

- conservative expanded witness: `59671` field elements

The `145` permutations come from the current native tx semantics:

- `1` PRF-key derivation
- `2` nullifier hashes
- `4` note commitments
- `64` Merkle nodes, each requiring two rate-6 Poseidon2 permutations
- `1` balance-tag hash, requiring two rate-6 Poseidon2 permutations

The `384` elements per permutation come from a conservative “full state per step” trace:

- Poseidon2 width `12`
- `1 + 8 + 22 + 8 = 39` round/linear steps would be too pessimistic for this implementation
- Hegemon’s actual helper has `31` nonlinear/linear update steps plus the initial linear layer
- so `32 * 12 = 384` witness elements per permutation is a conservative first frontend budget

There is also a tighter estimate:

- `57931` field elements using `372 = 31 * 12` elements per permutation

The probe kept both.

## Size result on the expanded witness

Using the official Goldilocks-oriented SmallWood prototype family and Hegemon’s effective constraint degree `8`, the conservative expanded witness gives:

- packing `4`: `571816` bytes
- packing `8`: `295480` bytes
- packing `16`: `160680` bytes
- packing `32`: `99928` bytes
- packing `64`: `82776` bytes
- packing `128`: `100728` bytes

So the best point in this sweep is:

- packing `64`
- rows `933`
- proof size `82776` bytes

That is about:

- `4.28x` smaller than the current `354081`-byte tx proof

The tighter expanded-witness estimate is slightly better:

- packing `64`
- rows `906` would be the same order of magnitude
- the nearby measured conservative/tight packing sweep at `32` already showed the tighter model only improves size modestly

The key product conclusion is already obvious from the conservative model:

- SmallWood is not merely viable,
- it can plausibly cut tx proof size by more than `4x`.

## Official profile comparison at the best packing

At the best observed packing (`64`) and conservative expanded witness:

- `short`: `75128` bytes
- `default`: `82776` bytes
- `fast`: `89536` bytes

So the best official-profile point in this probe is:

- `75128` bytes

That is about:

- `4.71x` smaller than the current tx proof

## No-grinding conservative sensitivity

The official prototype profiles use grinding, which Hegemon does not want to rely on for a release claim.

To test whether the size win survives more conservative settings, the probe also ran with:

- `opening_pow_bits = 0`
- `decs_pow_bits = 0`

and increased DECS opening / repetition counts.

At packing `64`, rows `933`, degree `8`, `beta = 3`:

- opened `17`, eta `8`: `82776` bytes
- opened `17`, eta `10`: `88136` bytes
- opened `17`, eta `12`: `93496` bytes
- opened `21`, eta `8`: `91672` bytes
- opened `21`, eta `10`: `97096` bytes
- opened `21`, eta `12`: `102520` bytes
- opened `25`, eta `8`: `100568` bytes
- opened `25`, eta `10`: `106056` bytes
- opened `25`, eta `12`: `111544` bytes
- opened `29`, eta `8`: `109464` bytes
- opened `29`, eta `10`: `115016` bytes
- opened `29`, eta `12`: `120568` bytes

So even after pushing the DECS side materially harder, the proof still stays around:

- `83 KB` to `121 KB`

That is still about:

- `2.94x` to `4.28x` smaller than the current `354081`-byte tx proof

## What this means

The SmallWood conclusion is now much sharper than before.

Wrong path:

- point SmallWood at `TransactionAirP3`
- or pretend the raw `3991`-element witness is the whole proving story

Right path:

- build a new tx-proof frontend around Hegemon’s compact native witness semantics,
- include the real Poseidon2 subtrace,
- and use an aggressive LPPC packing, likely around `64`

So the honest product answer is:

- SmallWood is not a category error,
- SmallWood is not “maybe someday,”
- SmallWood is a real `3x+` transaction-proof-size candidate for Hegemon.

## Remaining blockers

Three things are still unresolved before this becomes a release path:

1. The probe is structural, not semantic.
   It measures the proof size on the right witness/degree surface using the official prototype, but it does not yet implement full Hegemon tx-validity callbacks.

2. The public statement should stay direct and hash-friendly.
   If Hegemon insists on proving the current native digest wrappers inside this frontend, it inherits extra Blake3-style work that this probe intentionally did not include.

3. The `128-bit` no-compromise release note is still required.
   The size win survives stronger DECS settings, but Hegemon still needs a precise no-grinding parameter note before calling any one point a release profile.

## Product decision

SmallWood is no longer just a research curiosity.

Based on the official prototype sizing and a conservative Hegemon-expanded witness model:

- expected tx proof size is roughly `75 KB` to `121 KB`
- current tx proof size is `354081` bytes
- expected win is roughly `3x` to `4.7x`

That is enough to justify the next real engineering step:

- implement the actual Hegemon `NativeTxValidityRelation` callbacks in a SmallWood LPPC/PACS frontend
- and kill the branch only if the real semantic prototype destroys the structural win measured here
