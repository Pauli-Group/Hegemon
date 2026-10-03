# First honest-leaf QROM transition

## Result and exact scope

There is a concrete reduction from honest SMZ9 leaf hashing to independently
randomized leaf digests **with a persistent, coherently accessible programmed
oracle**. It uses the published adaptive-reprogramming theorem, not the
target-first simulator's entropy argument. In the finite ideal-QROM and
independent-uniform-tape model specified below, its distinguishing bound is

`delta_leaf <= min(1, R * sqrt(Q + R) / 2^256 + R * (Q + R) / 2^513)`,

where `R = T*N`, `N = 2^23`, `T` bounds all proof attempts reaching the leaf
batch, and `Q` counts every other query to the same raw oracle, honest or
adversarial. The `R` extra queries are essential: the reduction reads each
leaf answer after its reprogramming instruction. Failed or unpublished proof
attempts are not excluded from the accounting.

This closes a mathematical reduction for the first hybrid, subject to its
listed model/refinement obligations. The published quantum distance theorem
is not Lean-certified here. Nothing here removes hidden leaf programs, proves
complete SMZ9 privacy, provides a concrete SHA-512 reduction, changes a carrier,
or enables production authority.

## External theorem used

Grilo, Hovelmanns, Hulsing and Majenz's adaptive-reprogramming theorem takes a
classically supplied, adaptively selected distribution `p_r` on `(X,side)`.
The game samples that pair, independently samples uniform `Y`, updates its
shadow oracle at `X`, and returns `(X,side)`. The distinguisher queries either
the unchanged or updated oracle coherently. For
`pmax_r = E[max_x p_r,X(x)]` and `qhat_r` queries before instruction `r`, its
advantage is at most
`sum_r(sqrt(qhat_r*pmax_r) + qhat_r*pmax_r/2)`.
The PDF's own application obtains an answer by querying the current oracle
after the instruction. See [Theorem 1, Eq. (2), printed p. 7; Figure 2, p. 6;
the reduction below Figure 5, p. 10](https://arxiv.org/pdf/2010.15103v2).
The [HTML rendering](https://arxiv.org/html/2010.15103) labels that same
theorem 2.1. We use its general bound, not a guessed trace-distance premise.

## Finite quantum experiment

Fix a finite input space containing the 1,407-byte leaf inputs and all inputs
available to the chosen bounded experiment. For example, bound the query
register's byte length by a fixed `L`, with a length-tagged basis. Choose a
uniform function `H : Input -> {0,1}^512` once. A query is the complex-linear
extension of

`|x,z,w> -> |x,z XOR H(x),w>`.

The workspace includes the adversary's retained quantum memory. Between
queries it may apply arbitrary finite quantum operations; randomness and
measurements can be represented by their ordinary channels or dilations.
Setup advice must be independent of the sampled oracle unless all oracle
calls preparing that advice are included in the query count. Honest witness,
mask or statement preparation may depend on previous oracle calls; those
calls must likewise be charged. The reduction never measures the adversary's
private quantum memory merely to define the input distribution.

Proof requests are classical. An invocation is atomic with respect to external
queries for the runtime rescheduling described below. Between invocations,
and after receiving each proof, the adversary retains coherent access to the
current oracle. All later verifier and adversary queries see the same current
oracle, not a fresh oracle and not an oracle with its leaf overlay discarded.

For every leaf event, its salt, position and field-evaluation payload are
already fixed classical data. Write `C` for all these bytes, and `E(C,r)` for
the full framed input with tape `r`.

The two games differ only at the following leaf procedure:

```text
HonestLeaf(C):
    r <- uniform 64 bytes
    x := E(C,r)
    y := current H(x)
    return (r,y)

RandomizedLeaf(C):
    r <- uniform 64 bytes
    x := E(C,r)
    y <- uniform 512-bit digest, independently of x and prior state
    current H := current H with x mapped to y
    return (r,y)
```

Both games execute all subsequent Merkle, DECS, PIOP and proof-encoding work
from those actual returned tapes and digests. Both preserve failure outcomes.
The second game retains its updated oracle indefinitely. This definition does
not replace a leaf digest while leaving `H(x)` inconsistent with it.

## Exact source-shaped input law

The relevant source is `circuits/transaction/src/smallwood_engine.rs`:

- SMZ9's tape width is 64 bytes: `43,1572–1575,4933–4935`.
- Committed evaluations, DECS mask polynomials and mask evaluations are fixed
  before tape allocation: `11020–11096`.
- The SMZ9 indexed leaf batch is at `11133–11155`. Each leaf makes one raw
  SHA-512 call, at counter zero: `11742–11748,4538,4281–4284,4221–4234`.
- Raw leaf words are constructed at `11624–11640`. Words `0…3` are salt,
  word `4` is index, words `5…12` are tape, word `13` is 140, words `14…153`
  are committed evaluations, word `154` is 5, and words `155…159` are mask
  evaluations. The framing adds the 53-byte profile and 42-byte leaf role.
- Tape words are decoded and re-encoded little-endian without field
  reduction: `12877–12885,4247–4251`. Values at or above the field modulus
  remain distinct.

The resulting pre-padding input has exactly
`8 + 53 + 8 + 42 + 8 + 160*8 + 8 = 1407` bytes. Its index occupies bytes
`151…158`, and its tape occupies bytes `159…222`, zero-based. The input has
the form `leading[159] || tape[64] || trailing[1184]`. Reading that middle
slice is an explicit left inverse for every fixed pair of outer slices.

Define `p_C` by sampling a uniform element of `(Fin 256)^64`, inserting it
into those positions, and returning the resulting input and its tape as
side information. Every input in the image has probability exactly `2^-512`;
every other input has probability zero. Thus `pmax_r = 2^-512`, even when
`C` was selected using the earlier oracle interaction. This is a pointwise
bound for **every** fixed payload, not an entropy assumption about an
arbitrary quantum-conditioned distribution.

`SmallWoodV8Smz9HiddenLeafQrom.lean` constructs this byte-array law, proves
the projection/injection, exact tape cardinality, exact point probabilities
and maximum mass. It also constructs the complete finite coherent query as
an invertible complex-linear basis permutation, proves squared Hilbert-norm
preservation, and proves that changing one oracle point leaves query
amplitudes at all other input coordinates unchanged. Those are genuine
bounded results; no distinguishing probability or desired distance inequality
is a field of a record or an axiom in that module.

## Rescheduling the actual batch

Runtime obtains all tapes before hashing any leaf. The imported helper at
`smallwood_poseidon2_v8_rng_refinement.rs:202–248` copies each source byte
unchanged and partitions fixed-width tapes in order. With the current
4,096-tape batch size, there are 2,048 successful fill callbacks of 262,144
bytes each: 536,870,912 tape bytes total. There is no rejection, deduplication
or content-dependent retry. A callback is not necessarily an OS syscall.

Under the ideal independent-byte model, the same experiment can defer each
tape draw until its leaf event: its unused independent factor has not affected
an earlier oracle query or returned value. The pure leaf computations can be
serialized in index order. Their complete inputs are deterministically
distinct within one proof because the eight-byte index is retained, even if
two tapes coincide. Hence different leaf reads/updates do not affect one
another's returned values. The indexed output vector and retained tapes have
the same law as the batch implementation. This is a semantic product-coin and
independent-operation reordering; it does not claim current Rayon/TLS replay
instrumentation implements the reduction.

In particular, do **not** condition on a full private runtime state already
containing the current tape and then claim that tape is fresh. The exact game
rescheduling precedes application of the sampling theorem. Concurrency,
memory leakage, timing or RNG failures revealing unsampled tapes would require
their own model. Ideal bytes omit RNG failure; a concrete replacement must
bound the full joint randomness/error experiment, not merely condition on
successful calls and presume uniformity.

## Reduction and quantum-state preservation

The reduction runs the entire adversary and honest experiment. At each leaf,
it sends the classical description of `p_C` to the published `Reprogram`
interface, receives `x` and the tape, then makes **one ordinary basis-state
query** to `O_b(x)` and uses that returned digest. All other oracle calls are
forwarded without alteration.

If `b=0`, the accessed oracle is unchanged: inlining these steps gives
`HonestLeaf`. If `b=1`, the answer is the newly sampled independent digest:
inlining gives `RandomizedLeaf`. No prescribed target occurs in `p_C`; the
independent digest is sampled after the input. The adversary's existing quantum
registers are retained by the reduction, and the current oracle is available
throughout the continuation. Thus the final bit distributions are precisely
the two adaptive-reprogramming experiments for this reduction, and the cited
bound applies. Keeping the programmed table is essential to this equality.

The application is information-theoretic in the finite QROM. It is not a
claim that the distinguisher receives the entire classical oracle table or
its original pre-update copy. Such free oracle-correlated advice is a concrete
obstruction: with that copy and the selected point, one new query can detect
an independent replacement with probability `1 - 2^-512`, despite zero
*charged* preparatory queries. Our game excludes that uncharged advice.

## Query accounting and concrete ceilings

Let `qhat_r` count all ordinary queries before leaf instruction `r`, including
earlier leaf-answer reads and honest preprocessing. Then

`delta_leaf <= sum_(r=1)^R (sqrt(qhat_r)/2^256 + qhat_r/2^513)`.

For one uninterrupted batch with `Q_pre` preceding queries, the precise counts
are `qhat_(j+1) = Q_pre + j`, for `0 <= j < N`. Later queries remain allowed;
the conservative total-query ceiling `qhat_r <= Q+R` yields the opening bound.
Here `Q` includes all other actual SHA-512 oracle calls, including setup,
non-leaf honest hashes, sampler/XOF counters, inter-proof interaction and later
verification. SHA-512 compression blocks are not separate random-oracle calls.
There is no twenty-opening substitute for the `N = 8,388,608` leaf events.

For the displayed conservative bound, allocating the **entire** `2^-128`
budget to this one transition gives the following arithmetic screen:

| Other oracle-query bound `Q` | Bound at `T=1` | Largest integer `T` passing displayed bound | Bound at `T=2^74` |
| --- | --- | --- | --- |
| `2^64` | approximately `2^-201` | `5,810,359,557,114,882,582`, approximately `2^62.3333331513` | approximately `2^-110.5` |
| `2^128` | approximately `2^-169` | `2,199,023,255,551 = 2^41 - 1` | approximately `2^-95` |

These are ceilings for this conservative formula, not attacks above them or
protocol-approved history limits. In particular a `2^74` history ceiling does
not satisfy a 128-bit allocation once the honest leaf queries are charged.
The first row is dominated by `R` at its ceiling: treating `Q+R` as just `Q`
would be invalid. Any other privacy term requires reducing this allocation.

There is also an operational constraint on this **inclusive** `Q`: each full
proof uses `N-1` internal Merkle-node hashes alone, so `Q >= T*(N-1)` for full
proof invocations, before every other non-leaf cost. At `Q=2^64`, at most
`2,199,023,517,696` full invocations fit even this lower bound. Therefore the
first row's much larger algebraic threshold is not jointly realizable under
that fixed inclusive query budget. It must not be advertised as a feasible
history allowance. In a direct raw-oracle accounting, use
`Q(T)=Q_adversary+Q_other_honest(T)` with the actual charged honest costs.
The independent-domain reduction below gives a different, explicit meaning
to a leaf-oracle budget; it does not silently erase these costs.

The integer thresholds were checked without floating-point comparisons. Set
`R=T*2^23`, `q=Q+R`, `A=2^385-R*q`. The displayed bound is at most `2^-128`
exactly when `A >= 0` and `R^2*q*2^514 <= A^2`. Each reported `T` passes and
its immediate successor fails; the rounded bit counts are only explanatory.

## Optional independent-domain reduction and its exact cost

The whole finite raw-input space can instead be partitioned into the leaf
domain `L` and its complement `C`. Take `L` to include the exact framed leaf
inputs; membership and the sum-type encoding are fixed, oracle-independent
byte computations. Literal SMZ9 role framing separates each audited honest
non-leaf role from `L`, as proved in the preceding honest-hybrid module. No
hash-output collision assumption is used for this input partition.

There is an explicit table bijection

`(L + C -> Digest) <-> (L -> Digest) * (C -> Digest)`.

It restricts a table to its two domains; its inverse dispatches on the domain
tag. Uniformity transports through that bijection, and the two restrictions'
joint point probabilities are products. The new Lean module proves both
facts. Thus a reduction may privately sample the complement table once and
evaluate it locally. It samples that table at game initialization, before
preparing any oracle-correlated state, and simulates all subsequent preparation;
it never resamples the complement underneath an existing correlated state.
This is an information-theoretic finite-table simulation,
not an efficient implementation or a claim that actual SHA-512 queries cost
no time or hardware resources.

For any external query in superposition across both domains, select a fixed
dummy input in `L`, and perform the following coherent construction:

1. Reversibly route a leaf input to itself and a complement input to the dummy.
2. Query the current leaf oracle into an auxiliary response initially zero.
3. On the leaf branch, XOR that auxiliary into the user's answer; on the
   complement branch, XOR the privately known complement-table answer.
4. Repeat the leaf query to erase the auxiliary, then undo the routing.

This costs **two** leaf-oracle queries. The update table cannot change between
the compute and uncompute halves of a single query. The exact basis result is
`(x,z,0,w) -> (x,z XOR H(x),0,w)`. The new module constructs the three
bijections, their composition and complex-linear extension, proves this
clean-auxiliary identity, and proves norm preservation. It also proves that the
inverse query equals the same query for the concrete 512-bit register
`Fin 512 -> ZMod 2`. The full complex-linear clean-subspace equality includes
arbitrary superpositions and entanglement with the retained workspace. It is
not an assumed controlled-query primitive.

Let `Q_full` count **all** non-batch calls that need this general simulation:
adversarial queries, oracle-dependent preparation, verification of disclosed
leaves, and any other call not proved to belong to the complement. Let `R`
again count batch leaf reads. Audited complement-only honest calls can be
answered from the independent private table without a leaf-oracle query.
The reduction consequently has at most `2*Q_full+R` leaf-oracle queries and
`R` leaf reprogramming instructions. The same input-law reduction gives

`delta_leaf <= min(1, R*sqrt(2*Q_full+R)/2^256`
`                       + R*(2*Q_full+R)/2^513)`.

This budget is not subject to `Q_full >= T*(N-1)`, because the independent
complement-table simulation has now been supplied explicitly. It still
counts all honest batch leaf reads and all non-batch leaf access, and it
provides no runtime-efficiency guarantee. Source callers may be excluded only
after their actual byte-domain membership is established.

For `Q_full=2^64`, this formula is approximately `2^-200.5` at `T=1`; its
pure 128-bit-term arithmetic ceiling is
`T=5,810,358,824,107,408,150`, approximately `2^62.3333329693`.
For `Q_full=2^128`, it is approximately `2^-168.5` at `T=1`; the corresponding
ceiling is `T=1,554,944,255,987`, approximately `2^40.5`.
Each ceiling was checked by the same exact integer predicate with
`q=2*Q_full+R`. These allocate the entire budget to this transition alone.

## Collisions and obligations not discharged

Within each proof, indices guarantee distinct inputs. Across proofs, repeated
indices do not: the randomized game uses persistent **last-write-wins** table
updates, which the adaptive-reprogramming game permits. Fresh digests remain
independent draws, but an older colliding opening can cease to match the
current oracle. That possibility is included in the two games, not discarded.
If a later proof insists on an append-only collision-free history, a separate
union bound is at most `binom(T,2)*N/2^512` using only the fresh tapes and fixed
per-proof indices. We claim no extra salt entropy. Digest collisions are allowed
and do not require a separate bad-event term for this first transition.

The twenty selected tapes are disclosed in the proof and later rehashed
(`11230–11236,2902–2908,11350–11357`). The persistent overlay makes those
queries consistent; deleting it is not covered here. The final hidden-leaf
removal, full witness-independent simulation, concrete hash/RNG assumptions,
Rust/byte/parallel-schedule refinement, and complete composed history budget
remain necessary. Production and source-capability gates remain unchanged.

## Verification

Direct checking uses the existing cache without producing a shared build:

```sh
cd formal/crypto
lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9HiddenLeafQrom.lean
```

The complete new module passes direct Lean checking. Its ten-endpoint axiom
audit reports only `propext`, `Classical.choice` and `Quot.sound`; there are no
`sorry`, `admit`, custom axioms or `native_decide` declarations. The published
adaptive-reprogramming theorem remains an explicitly external lemma, not a
Lean theorem declared by this work. No runtime execution, proof creation,
shared import/inventory edit, Git mutation or production change is included.

Coordinator integration subsequently imports this module and audits its scoped
roots in the complete 2,754-job, 145-root formal-crypto gate. That gate passes
with the unchanged wire/program artifacts. The exact arithmetic is reproducible
with `python3 -B scripts/smz9_hidden_leaf_qrom_screen.py --self-test` and the
same script without arguments. Its three tests check all four integer ceilings
and their successors, as well as the inclusive-query feasibility distinction.
