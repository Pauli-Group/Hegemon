# Binius E384 complete-ZK closure audit

This directory records a fail-closed complete-zero-knowledge construction seam for the single-copy mixed B128/E384 BaseFold candidate. It is not a proof artifact, a complete simulator, a production authorization, or a measured proof-size result.

## Current verdict

The transform is mathematically implementable only if the authenticated BaseFold backend exports the exact verifier observation map and exact relation-preserving witness/mask generators. The current backend has not yet supplied that combined object, so the whole-proof claim remains false.

For fixed transcript challenges, let `O` map the original committed oracle to every distinct raw leaf, folded value, and terminal functional serialized in the proof. Let `G_w` span all same-statement witness deltas and `G_r` map uniform independent E384 masks into the relation kernel. Define

    W = O G_w
    R = O G_r.

Perfect fixed-transcript linear hiding holds exactly when

    rank(R) = rank([R | W]).

`complete_zk.rs` checks this identity over the exact local E384 field, constructs the mask translation on success, and emits a verifier-computable left-nullspace distinguisher on failure. A query count such as `n_dummy_wires=q` does not imply this rank identity.

The concurrently landed backend now exposes `raw_opening_observations_for_queries(d,r,g,&query_indices)`, including transcript-derived distinct queries, per-round sorted/deduplicated leaf unions, canonical Merkle frontiers, and terminal leaves. That is the required `O` inventory seam, but it does not export `G_w`, `G_r`, or a relation-mask kernel. It therefore cannot satisfy the rank gate yet.

## Appended-dummy protocol no-go

The live M4 approach appends random B128 dummy wires to each witness oracle and carries a separate full random mask `omega`. Under the joint `[pi, omega]` group mapping, the current mixed PCS serializer writes the round-zero `pi` and `omega` B128 codeword values as two distinct `values[group].coefficients()[0]` fields, followed by the 64-byte index tape and Merkle frontier. It does not affine-combine those fields before serialization. The exact scalar Gao--Mateer encoder has a systematic zero leaf: codeword leaf zero equals message coordinate zero. Every appended tail-dummy coefficient at that leaf is zero. Opening leaf zero therefore reveals the active coordinate exactly; the separately opened `omega` value and leaf tape do not mask it. The adapter has not yet refined the conditional group-zero=`pi`, group-one=`omega` mapping, so that integration gate remains false.

For a generic valid transparent relation, two messages differing only in active coordinate zero have the same public claim. Conditioned on opening leaf zero, their views have exact statistical distance one. The current sampler chooses `q` distinct pair indices from `L=2^(d+r-1)` and opens both siblings, so the leaf-zero event has exact probability `q/L`, equivalently `2q/2^(d+r)`. The whole-view statistical distance is therefore at least `q/L`. With replacement the miss probability would be `((L-1)/L)^q`. Because the admitted pair-population logarithm is at most 25, even one draw bounds this generic hiding mechanism by at most 25 statistical bits, not 128.

The source-bound proof covers every one of the current backend's 120 admitted `(d,r)` pairs: initialization maps leaf zero to `bit_reverse(0)=0`; only transform block zero can touch leaf zero; and `gao_mateer_twiddle(layer,0)=0`, so every transform preserves that coefficient vector. The retained exact-encoder screen additionally enumerates all 56 three-pair schedules for two eight-symbol layouts. All 56 schedules leak in both layouts. With four active plus three appended dummy coordinates, all 56 masks have full dummy-column rank three; with five active plus three dummies, only 35 do and the minimum mask rank is two. The first query pairs `[0,1,2]` open leaves `[0,1,2,3,4,5]`; the executable left-null combination `[1,0,0,0,0,0]` exposes active functional `[1,0,...]`.

This is a protocol-level counterexample for the generic hiding PCS and disproves `dummy_count=query_count` as a rank theorem. It is not yet the exact Hegemon-relation `G_w` audit: the compiler still must export which same-statement transaction witness deltas reach every committed oracle.

## Source-faithful repair baseline: Diamond Construction 4.1

The selected BaseFold ZK repair baseline is Benjamin Diamond's *Zero-Knowledge Polynomial Commitment in Binary Fields*, ePrint 2025/1015, Construction 4.1. This is the only reviewed construction in scope here with a perfect-IOP-ZK theorem for Binary BaseFold. It is not a theorem for Hegemon's transaction PIOP, ring switching, Fiat--Shamir/QROM composition, or the current mixed B128-message/E384-challenge prototype.

For an `ell`-variable polynomial, inverse-rate log `R`, fold arity log `theta` dividing `ell`, and `gamma` FRI repetitions, the construction requires all of the following together:

- run BaseFold setup on `ell+1`, doubling the coefficient/code dimension;
- append exactly `kappa = gamma * 2^theta` fresh random high coefficients and open `kappa` points per oracle;
- commit a fresh fully random blind polynomial;
- sample a combination challenge and use the virtual oracle `f^(0)=alpha*f+f'`;
- interleave the sumcheck and FRI on that virtual oracle;
- send a final degree-one pair `(c0,c1)`, rather than one constant; and
- apply the BCS salted-opening transform to every committed leaf.

The current `mixed_basefold_pcs` implements none of the first six items and its index tape is not refined to the cited BCS grammar. Its appended-dummy/equal-mask channel therefore cannot inherit Diamond's theorem. In particular, syntactic padding is not free Diamond capacity: setup on `ell+1` is mandatory unless the actual relation polynomial is rigorously lowered to a smaller `ell`.

`diamond_construction_4_1_geometry` encodes those exact requirements. For a fixed unchanged non-ZK tree schedule with depths `d_i`, field width `B`, SHA-512 node width `H=64`, and per-opened-leaf salt/tape width `S`, `diamond_construction_4_1_wire_delta` computes the serializer-derived increment

    H
    + 2*B
    + kappa*B
    + sum_i(MP(d_i+1,gamma,H)-MP(d_i,gamma,H))
    + MP(d_0+1,gamma,H)
    + (T+1)*gamma*S.

Here `MP(d,g,H)=((d-c)*g+2^c)*H` and `c=min(ceil(log2 g),d)`. The paper's classical `2*lambda` BCS salt is 32 bytes at `lambda=128`; Hegemon's strict QROM ledger reserves 64 bytes, without claiming that this supplies the missing QROM theorem. For E384, `B=48`. If the fold optimizer changes the schedule, the delta shortcut is invalid and every tree must be priced absolutely. Exact production `ell/R/theta/gamma`, tree depths, serializer bytes, and measured total are not frozen, so no Diamond proof size is promoted.

### Exploratory vanishing-mask alternative (not authority)

An exploratory alternative is a vanishing-codeword mask on a commitment domain disjoint from the relation domain:

    P_masked(X) = P(X) + Z_H(X) R(X).

`Z_H` vanishes at every relation point, so relation values are unchanged. Give every independently encoded group its own `R_g` with `m` independent B128 coefficients and `deg R_g < m`, where `m` is the per-group maximum number of distinct opened B128 coordinates in the exact proof view—not the nominal query count. If `u_l` is the maximum sorted/deduplicated opened-leaf union at layer `l` and `t` is terminal width, then

    m = u_0 + 3 * sum_{l>0}(u_l) + 3*t,

and `g` groups require `g*m` independent coefficients in total. Both siblings selected by each pair query are in `u_l`; all three lanes of later E384 values and the terminal are charged. At any `k <= m` distinct initial commitment queries `x_i`, the per-group mask matrix is the first `k` rows of `diag(Z_H(x_i))*Vandermonde(x_i,0..m)`, which has row rank `k` because the domains are disjoint and the points are distinct.

Zero PCS-wire overhead is valid only if source/refinement proves that the relation domain `H` is strictly smaller than the existing per-group power-of-two capacity by at least `m` points and that those tail positions may be randomized without changing the MLE/reduction or public-padding compression. Apparently unused or verifier-known zero slots do not qualify. If the committed relation is defined on all `N` existing points, `deg Z_H=N`, so every `m>0` makes `deg(Z_H R_g)>=N` and forces dimension growth. No relation-free tail or spare degree is established for the live M4 compiler: its exact relation-domain cardinality, opening inventory, and production geometry are not exported, so `m`, the spare-symbol count, and the live wire delta all remain null. `plan_vanishing_mask_capacity` rejects a smaller claimed `H` unless the caller supplies the explicit relation-free-tail refinement gate.

`plan_conservative_vanishing_mask_basefold` computes the smallest power-of-two dimension fixed point under the all-transcript paired-query bound. It recomputes `m(d',r,g,q)` at every candidate `d'`, because each added fold layer itself adds opened E384 coordinates, and selects the first

    2^d' >= |H| + m(d',r,g,q).

It keeps inverse-rate log `r` and query count `q` unchanged. A growth of `delta=d'-d` adds `delta` fold layers and `delta` SHA-512 roots, so `64*delta` root bytes are a source-exact lower bound; mask coefficients add zero direct payload bytes. The exact opened-value, tape, frontier, and total wire deltas remain null because new roots rotate the transcript-derived schedule. This API covers the current equal-dimension mixed PCS grammar. It has no cited whole-BaseFold simulator theorem, its polynomial-basis/relation-kernel lowering is unproved, and it is not the selected implementation authority. The qualifying mixed-depth M4 adapter still must export its per-oracle geometries and exact view rank before even a smallest exploratory geometry can be claimed.

The historical outer patch with two B128 dummy values is concretely false in E384: weights `[1,Y]` span rank two over B128, while translation `Y^2` raises the augmented rank to three. The marginal and its translation have disjoint support, hence statistical distance one. The selected repair uses two full-E384 dummy multiplication rows. Its local endpoint translation loss is conservatively bounded by

    (n + d + 1) / 2^384,

where `n` is the outer equality-basis dimension and `d` is the Hamming distance between the two consecutive dummy-row indices. This local bound is not a whole-proof QROM composition.

Every opened grouped leaf binds its oracle group, fold layer, exact index, all three B128 lanes per E384 value, and one independent 64-byte tape. The tape is a SHA-512 ROM/QROM programming input; it is not accepted as a substitute for the full-E384 algebraic mask. Exceptional Fiat--Shamir challenges are selected by a fixed first-accepted schedule with at most sixteen public transcript counters and no serialized nonce. Any witness-dependent retry is rejected.

## Exact overhead equation

Production geometry is not frozen, so no total byte estimate is promoted. Once the serializer supplies exact counts, incremental complete-ZK overhead is

    framing
    + 64 * (new_roots + new_authentication_nodes + opened_grouped_leaf_tapes)
    + 48 * (opened_mask_E384_values + explicit_masked_E384_claims + terminal_E384_values)
    + 32 * widened_endpoint_values.

There are exactly three widened outer endpoint values `(A,B,C)`, so that final term is 96 bytes. The two full-E384 dummy multiplication rows contain six committed E384 values; commitments add only roots, while any revealed dummy lanes must be included in `opened_mask_E384_values`. Transcript-derived challenges and canonical sampler counters add zero proof bytes.

## Gates still false

- The exact `O`, `G_w`, and `G_r` matrices and compiler-bound same-statement rank are not integrated.
- The current appended-dummy initial codeword is generically distinguishable.
- Diamond Construction 4.1 is not implemented: no `ell+1` setup, `kappa` high padding, blind commitment, virtual-oracle interleaving, or cited BCS opening grammar exists in the current mixed backend.
- The exploratory disjoint-domain vanishing mask is not authority, is not implemented, has no live relation-basis refinement, has unknown mask degree, and has no established spare capacity.
- No concrete implementation of the witness-free whole-proof simulator exists.
- Nonlinear multiplication-mask consistency is not proved.
- The adaptive SHA-512 commitment/transcript programming loss in the QROM is not composed.
- Exact serializer/verifier/refinement and frozen `n/rate/q/terminal/auth-path` geometry are absent.
- No proof artifact was built or measured under this transform.

Accordingly, `complete_zk`, `strict_pq128`, `proof_size_measured`, `frontend_integrated`, and `production_authorized` all remain false.

See `EXECPLAN.md` for exact commands and acceptance conditions.

`direct_rustc.py` validates this module against the exact current B128/E384 implementation without importing the separately owned in-flight authenticated BaseFold/PCS modules. It does not copy or substitute field arithmetic.

An earlier source revision passed the isolated 32-test Rust harness, and the backend owner later reported 47 integrated tests passing before the newest B128 paired-query, Diamond, and repair-inventory changes. The current digests are formatted and source-checked only: the hard disk stop forbids a new `rustc` artifact until free space reaches 28 GiB. The dependency-free Python certificate suite passes all 18 tests; its valid negative checker deliberately exits 2. No current-digest Rust pass is claimed; status remains `complete_zk=false` and `production_authorized=false`.
