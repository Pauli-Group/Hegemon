# Hidden quantum patches: physical proof boundary

## Checked result

`SmallWoodV8Smz9HiddenPatch.lean` constructs a genuine complex-linear isometry
for a finite coherent oracle query and quantifies over complex-linear isometric
inter-query gates. It proves, for a uniform hidden secret `r`, fixed reference
oracle `O`, secret-indexed oracle `O_r`, and a normalized initial state,

\[
\mathbb E_r\|\psi_r-\psi_0\|^2\le 4q^2p,
\qquad
\mathbb E_r\|\psi_r-\psi_0\|\le\sqrt{4q^2p}.
\]

The input-level premise is that `O_r` and `O` agree outside `S_r` and every fixed
raw query input belongs to `S_r` with probability at most `p`. The entire
reference circuit, initial state and inter-query gates are independent of `r`.
These are physical circuit and input-distribution premises, not an assumed
final-state distance. The proof uses an explicit changed-input projection,
the one-query bound `4 * projection mass`, a reference-state telescope,
Cauchy--Schwarz and an exact swap of finite sums.

The same module proves the actual source-shaped no-multiplicity statement:
eight canonical little-endian index bytes occupy positions `151..158`, and
the tape occupies `159..222`. The index constructor's base-256 weighted sum is
proved equal to the original `Fin 8388608` value. Explicit raw-input decoders
recover both the index and all 64 tape bytes from every constructed leaf.
Consequently, the image of every unopened leaf set under the simultaneous
source-shaped patch constructor lies inside one independently indexed tape
fiber for each raw input. That fiber has exact probability `2^-512`, with
**no multiplicative number-of-leaves factor**. The literal `sourceOverlay`
updates precisely those constructed inputs and persists throughout the query
circuit.

The full endpoint uses `LeafInput + Other` as a finite raw-input partition.
`LeafInput` includes every 1,407-byte string, not merely well-framed leaves;
`Other` contains the remaining inputs in the bounded experiment. A coherent
query can mix both sides. The complement oracle remains unchanged. This is
proved directly for the full oracle, without adding an assumed simulation
cost or silently restricting the adversary to leaf queries.

The operational theorem `full_source_overlay_cq_born_distance_le` includes a
final genuine linear event projection, arbitrary retained quantum workspace,
and a common final isometry/event that may depend on the retained classical
secret. Its checked safe bound is

\[
|\Pr[\mathrm{accept\ overlay}]-\Pr[\mathrm{accept\ reference}]|
 \le 2\sqrt{4q^2\,2^{-512}}=4q\,2^{-256}.
\]

The extra factor two is the explicitly proved elementary measurement bound,
not a trace-distance equality. All oracle queries in the continuation must be
included in `q`; the final secret-controlled isometry contains no oracle
calls. Additional measured randomness can be represented in the retained
workspace. Applying this finite physical circuit model to arbitrary channel
implementations still requires their appropriate dilation/refinement.

For a fixed public opening context, unused coordinates of the uniform tape
table can serve as independent dummy tapes on opened indices: the overlay
reads only unopened coordinates. The game integration must establish that
padding equivalence, the fresh conditional tape law, and independence of the
fixed reference oracle/circuit/initial state. The constructor and its source
anchors do not certify compiled Rust serialization or operating-system RNGs.

The checked theorem is an ordinary physical hybrid plus an operational Born
measurement bound. It is **not** a checked `4q^2p` trace-distance theorem;
taking a square root loses half the entropy exponent. The stronger claim
below must not be substituted for it in a formal privacy certificate until
its remaining operator argument is checked.

## Stronger discarded-secret theorem: mathematical argument

The following argument has been independently checked mathematically, but its
full operator/averaged-density bridge is not yet mechanized in the module.
Write `Delta_r = O_r - O` and let `delta_r = psi_r - psi_0`. Since the oracle
difference is block-diagonal in the raw input register, has operator norm at
most two on each changed block, and each block is changed with probability at
most `p`,

\[
\|\mathbb E_r\Delta_r\|_{op}\le2p.
\]

Use the forward reference-state telescope

\[
\delta_r=\sum_{j=0}^{q-1}V_{r,j}\Delta_r\phi_j,
\]

where every pre-query reference state `phi_j` is independent of `r` and the
suffix `V_{r,j}` contains `q-j-1` remaining oracle queries. Separate each suffix
into its reference suffix and their difference. The reference-suffix terms
have total averaged norm at most `2qp`. For a fixed unit test vector `v`,
move the remaining suffix difference to the adjoint side of the inner product.
Cauchy--Schwarz, the backwards reference hybrid for `q-j-1` queries, and the
one-query changed-input mass bound give

\[
\left|\mathbb E_r\langle(V_{r,j}^*-V_{0,j}^*)v,
                    \Delta_r\phi_j\rangle\right|
 \le 4(q-j-1)p.
\]

Summing and taking the supremum over fixed unit vectors yields

\[
\|\mathbb E_r\delta_r\|\le2qp+2q(q-1)p=2q^2p.
\]

Expanding the averaged pure-state density difference around the fixed
reference state and applying the rank-one trace-norm identity gives

\[
\frac12\left\|\mathbb E_r|\psi_r\rangle\langle\psi_r|
             -|\psi_0\rangle\langle\psi_0|\right\|_1
 \le \|\mathbb E_r\delta_r\|
       +\tfrac12\mathbb E_r\|\delta_r\|^2
 \le4q^2p.
\]

This is an averaged-density conclusion **after discarding the hidden secret**.
It does not bound the average of individual trace distances, or the joint
output retaining or subsequently revealing `r`. Such claims can still have
square-root dependence on `p`. A circuit continuation is covered only if all
its queries are counted and its operations do not otherwise access `r`.

Conditioning on public context, the selected opening set, or opened tapes is
valid only after proving that the residual hidden tapes remain independent of
the reference experiment with the asserted per-input support probability.
Multiple candidate patch inputs for a single leaf, correlated/reused tapes,
overlapping proof namespaces, or removal of both an old and a new secret input
can require a separate multiplicity or conditioning bound. An entropy number
alone does not discharge any of these requirements.

## Reproducible local check

From `formal/crypto`, using the existing cached dependencies:

```sh
lake env lean -DwarningAsError=true -o /tmp/SmallWoodV8Smz9HiddenPatch.olean HegemonCrypto/SmallWoodV8Smz9HiddenPatch.lean
```

The complete strict check passed on 2026-09-07. Axiom audits of the full-raw
operational endpoint, mean-distance endpoint, source-support inclusion,
little-endian index identity and 512-bit fiber count report only `propext`,
`Classical.choice` and `Quot.sound`. The source framing was checked against
`smallwood_engine.rs:11607` (raw leaf words), `:4237` (canonical raw oracle
serialization), and the source layout summarized in `hidden-leaf-qrom-step.md`.
This is a local proof artifact, not a complete Fiat--Shamir/QROM privacy
theorem for serialized SMZ9 proofs, a refinement of Rust randomness or SHA-512,
or production authorization.
