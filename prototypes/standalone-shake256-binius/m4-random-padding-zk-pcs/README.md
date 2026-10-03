# Random-padding compact PCS audit

Status: source-only mathematical and byte audit. The strict frontier remains
empty. This directory does not implement a PCS, FRI prover, production parser,
complete simulator, or security reduction.

This experiment tests whether the unused high coefficients of one n15 B128
message can carry the randomness needed to hide every committed-codeword view.
The proposed shape is a low-rate univariate Reed--Solomon code, four B128
symbols plus a profile-bound salt in each strict 64-byte SHAKE256-512 Merkle
leaf, and two domain-separated E256 algebraic branches sharing exactly one
immutable root. Fiat--Shamir also uses a 64-byte SHAKE256-512 digest. The prior
56-byte SHAKE256-448 rows are retained only as non-strict negative controls.
No production-size codeword is allocated.

## The exact linear-algebra result

Write the message as `m = [x || r]`, where `x` is the active M4 prefix and `r`
is a fresh uniform B128 padding tail. For one fixed collection of opened query
groups, terminal claims, and fold/FRI linear functionals, split its B128-linear
observation matrix as

    Y = W_active x + W_pad r.

For fixed `W`, `Y` is uniform over the affine coset
`W_active*x + image(W_pad)`. Therefore:

- it is independent of `x` exactly when
  `rank([W_pad | W_active]) = rank(W_pad)`; and
- it is uniform on the whole observation space when
  `rank(W_pad) = number_of_observations`.

`random_padding_pcs.py` computes both ranks exactly over the pinned GHASH B128
field. `observation_union_matrix` refuses to audit point openings in isolation:
it appends both B128 coordinate rows of every E256 terminal and fold/FRI
functional before the single rank check. The tests exhaust every padding value
over GF(16), showing identical full-uniform distributions for two witnesses
when the tail block is full rank, disjoint witness cosets when it is deficient,
and a rank-deficient but witness-independent subspace as the weaker boundary.

For ordinary monomial RS evaluations at fixed points `alpha_i`, the first `t`
padding columns are

    diag(alpha_i^active) * [1, alpha_i, ..., alpha_i^(t-1)].

Their determinant is

    product_i(alpha_i^active) * product_{i<j}(alpha_j + alpha_i)

in characteristic two. Distinct nonzero points therefore give full row rank
when at least `t` random high coefficients exist. The B128 implementation
checks that determinant precondition and independently Gaussian-eliminates a
small real-B128 instance.

### Zero is a hard failure

At `alpha=0`, every positive monomial vanishes. An opening reveals the constant
coefficient without any high-tail mask. The test
`test_zero_domain_point_leaks_the_constant_coefficient` exhaustively exhibits
this leak. The candidate therefore uses the explicit additive affine coset

    (1 << 127) + span(1, X, ..., X^(log_domain-1)),

which is nonzero and distinct for every screened domain. A zero-containing
linear evaluation subspace is rejected.

### Fixed-matrix rank is not adaptive ZK

The lemma requires the row schedule to be fixed independently of `r`. A Merkle
root and Fiat--Shamir schedule are functions of the random padding and salts,
so a complete BCS/ROM proof is still required. The executable adaptive negative
selects one of two tail coordinates using the first tail bit. Every realized
one-row matrix has rank one, yet the observation equals the witness with
probability `3/4`. This proves that checking rank after a padding-dependent
selection is unsound.

Freshness is also mandatory. If two proofs reuse `r`, subtracting matching
linear views cancels the entire pad and exposes the view of the witness
difference. The key-reuse regression checks this identity exactly.

## Exact wire screen

The wire model uses conventional univariate RS expansion: an n15 coefficient
message at rate `1/d` has `2^15*d` B128 codeword symbols. This is not the older
TensorSwitch screen's `d^2` oracle and must not be compared as the same PCS.
Each strict leaf contains four 16-byte symbols and a profile-bound salt. One
64-byte SHAKE256-512 root is serialized; every authentication node is also 64
bytes, canonical query indices cost zero bytes, and the exact worst-case binary
multiproof frontier is charged. The 32-byte salt is the compact candidate
charge and is explicitly unproved for PQ128.

Each E256 branch is charged the existing optimistic first-level floor of
`5*q + 2` E256 values. The model then charges two terms not included in `5*q`:
the local characteristic-two two-branch n15 floor is 1,920 bytes and the fused
ring switch is 128 bytes. They are separately visible in every report row and
also conservatively count as 128 additional possibly witness-dependent B128
coordinate observations.

Two query-budget families remain separate. The full-budget rows assign the
existing optimistic 264-bit leading term to each branch, giving `q=87` at rate
`1/16` and `q=66` at rate `1/32`. This intentionally overprices two independent
branches. The conditional product rows assign 132 classical query bits to each
independent branch: `q=44` and `q=33`, respectively. Their union has `2q`
leaves, so the rate-`1/32` conditional row opens exactly the same 66 worst-case
leaves as the shared full-budget row. It is the proper size analogue only if a
future parallel-RBR theorem proves that the two 132-bit errors multiply under
one commitment. `half_budget_product_theorem_proved` remains false. All query
counts and field-message floors are model inputs, not a FRI/proximity theorem.

| strict rate / schedules / bits per branch | raw bytes | raw headroom | tree storage | conservative B128 views | tail headroom at sensitivity A=26,000 |
|---|---:|---:|---:|---:|---:|
| 1/16, shared, 264 | 96,800 | 27,268 | 20,971,456 | 2,224 | 4,544 |
| 1/16, independent worst union, 264 | 152,320 | -28,252 | 20,971,456 | 2,572 | 4,196 |
| 1/16, independent worst union, conditional 132 | 83,712 | 40,356 | 20,971,456 | 1,368 | 5,400 |
| 1/32, shared, 264 | 80,192 | 43,876 | 41,942,976 | 1,720 | 5,048 |
| 1/32, independent worst union, 264 | 128,512 | -4,444 | 41,942,976 | 1,984 | 4,784 |
| 1/32, independent worst union, conditional 132 | 69,632 | 54,436 | 41,942,976 | 1,060 | 5,708 |

The old 56-byte rate-`1/32` rows are `116,952` bytes for two full independent
budgets and `63,320` bytes for the conditional half budgets. They are emitted
only under `non_strict_shake448_negative_controls`; neither is a strict-profile
result. Widening the conditional tree to 64-byte nodes costs exactly
`(1 root + 788 frontier nodes)*8 = 6,312` bytes, producing 69,632. Widening the
full independent tree costs `(1+1,444)*8 = 11,560` bytes, producing 128,512.

### Salt profiles are theorem-scoped

The 32-byte salt is not security evidence. The direct classical BCS Merkle
privacy calculation at the rate-`1/32` tree size `n=2^18` needs
`lambda >= 592` for a 128-bit statistical bound, hence a `2*lambda = 1,184`-bit
or 148-byte salt. The model therefore emits two separate strict rate-`1/32`
rows with 148-byte salts:

| strict SHAKE256-512 / 148-byte salt | raw bytes | raw headroom | tree storage |
|---|---:|---:|---:|
| independent 264-bit budget per branch | 143,824 | -19,756 | 72,351,680 |
| independent conditional 132-bit budget per branch | 77,288 | 46,780 | 72,351,680 |

These are theorem-scope diagnostics, not promotions. The BCS result is in a
classical explicitly programmable random-oracle model, not the QROM. Moreover,
its one parameter must describe both salt length and oracle output: the
148-byte salt corresponds to `lambda=592`, while the strict digest is 512 bits.
Thus even the larger-salt row has
`direct_bcs_common_lambda_parameter_match=false`, QROM applicability false,
and `salt_profile_promotable=false`. A different source-bound lazy QROM
simulator could justify another salt length, but no such simulator exists here.

The conservative view count charges all opened B128 symbols and two B128
coordinates for every possibly witness-dependent E256 message. Under the
non-authoritative `26,000`-active-symbol sensitivity input, the n15 tail has
6,768 symbols. The source-bound static geometry counter only narrows the active
prefix to `23,594..32,668`, hence the possible tail is `100..9,174` symbols.
No profile above has enough rank capacity for that entire interval; at the
static upper endpoint, even the conditional row is short by 960 B128 rows.
Compilation must select the actual point before this construction survives the
rank-capacity gate.

The double-full-budget independent rate-`1/32` row requires the real
compiled active prefix to be at most 30,784 symbols. The conditional half-budget
row relaxes that capacity-only ceiling to 31,708. Capacity is necessary, not
sufficient: the actual union matrix is not available and its rank is
deliberately `null` in the report.

Both strict rate-`1/32` independent rows are only lower-bound architecture
screens. The double-full-budget row is 4,444 bytes over the raw cap. The
conditional half-budget row has 54,436 bytes, but none of that is usable as a security result
until the missing parallel-RBR product theorem exists. Headroom must still pay
for every omitted later FRI round, PIOP relation message, parser field,
abort/rejection encoding, and security repair. Shared schedules and two
domain-separated labels likewise cannot be used to multiply soundness errors
without a theorem for one shared commitment.

## Commitment and transcript seam

`salted_leaf_hash` is authoritative and length-frames a profile-bound salt,
leaf index, and exactly four canonical little-endian B128 symbols into a
64-byte SHAKE256-512 digest. `merkle_node_hash` uses a separate strict domain
and binds level, node index, and both 64-byte children.
`branch_transcript_digest` returns the full 64-byte SHAKE256-512 Fiat--Shamir
digest; the E256 challenge is mapped from its first 32 bytes. The two branches
absorb the same strict root and public context under distinct labels.

The separate `salted_leaf_hash_nonstrict_shake448` and
`merkle_node_hash_nonstrict_shake448` functions are negative controls with
different domains. No strict report row calls them. Domain separation does not
prove branch independence, especially with one shared commitment.

## Gates that remain false

The report keeps every production authority bit false. In particular, it does
not prove that the prospective M4 PIOP ignores or soundly constrains the random
tail, freeze the compiled active-symbol count, export the full observation
union, freeze the actual terminal/FRI matrix, prove FRI proximity or extraction,
prove adaptive BCS zero knowledge, prove a global simulator, prove salted-Merkle
hiding or binding in the QROM, instantiate SHAKE256-512 as the required
commitment oracle, prove either salt profile sufficient, prove two-E256 parallel
soundness, compose PQ128/QROM loss, or bind a canonical parser/verifier to the
maximum M4 relation. One root plus two labels is not an independence theorem.

The source inventory is limited to the available static facts: 83 Keccak-f
calls, 3,187,200 Boolean BitAnd constraints, 671 private u64 words, and 336
packed B128 transport symbols. The Rust source itself warns that its active
trace length is not emitted until compilation. No Pay1x2 count is substituted.

## Disk-safe validation

From the repository root:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/random_padding_pcs.py \
      --check --report

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/test_random_padding_pcs.py

The first command prints `RANDOM_PADDING_PCS_CHECK_PASS`; the second currently
runs 26 tests. Neither command allocates the modeled codeword or invokes Cargo.
