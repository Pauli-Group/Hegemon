# Exact fail-closed odd-field PQ/QROM composition

This ExecPlan is a living record for the isolated strict-composition package.
It follows `.agent/PLANS.md`; all implementation stays under
`.agent/hardening/strict-odd-field-composition/` and does not edit shared docs.

## Purpose

Produce a canonical, dependency-free security ledger that answers whether the
current odd-field R1CS plus HVZK-WHIR/ProveKit candidate can support a complete
zero-knowledge, strictly-more-than-128-bit post-quantum/QROM claim under
conventional hashes. Missing theorem terms must remain JSON `null`, equality at
`2^-128` must reject, and source drift must fail the checker.

## Progress

- [x] Read the repository instructions and relevant design/method/plan context.
- [x] Pin the strict-QROM, HVZK wire, odd-field compiler, CFW IOR, Plonky3, and
      immutable ProveKit/WHIR source evidence.
- [x] Recompute all decisions with exact `Fraction` arithmetic.
- [x] Bind the final mixed and split R1CS geometry and equal-half CFW embedding.
- [x] Separate the theorem-only concrete-hash lane from the explicit
      conventional-hash-as-QRO assumption lane.
- [x] Inventory all 15 security-bearing semantic roles and their key/source
      width and min-entropy evidence boundary.
- [x] Enumerate every required PCS, IOP, RBR, HVZK, FS, hash, grinding, RNG,
      union, parser, consensus, and refinement term.
- [x] Retain missing advantages as `null`, never zero.
- [x] Generate canonical `ledger.json`, checker, and mutation tests.
- [x] Add the direct GHCM21 SmallWood QROM-reprogramming sensitivity while
      keeping complete ZK, CMS/RBR soundness, and concrete-hash instantiation
      separate and fail closed.
- [x] Correct the direct GHCM route for heterogeneous leaf/chain entropy and
      parameterize widened-tape wire deltas at `q_D=23/48/55`.
- [x] Run the dependency-free checker and 32-test suite.

## Discoveries

- The final mixed relation has 20,457,227 constraints and 19,311,555
  nonconstant variables. Construction 11.4 needs equal halves of length
  `ell=2^25`, hence a `2^26` carrier. A previous shorthand treating 25 or 26
  as a WHIR polynomial variable count was invalid; the actual WHIR count is
  still unset.
- Section 11 has 105 encoded oracles and an exact `105*zeta` statistical-HVZK
  union, but `zeta` is missing. The 26 repeated sumcheck coordinates are not
  the full RBR vector; the full vector has 29 coordinates.
- The paper's initial RBR numerator requires an unprinted `L_out>=d` premise or
  a `d+1` repair. The current theorem cannot authorize the relation.
- The printed endpoint state tests one coefficient rather than evaluation at
  one: `s=X^2-X` is an honest-completeness counterexample. The endpoint state
  must be `pow(1)`, and the main matrix form needs an explicit alpha-indexed
  row-MLE typing repair.
- Goldilocks degree 5 is a real local TwoAdic binomial extension and retains
  field-arithmetic headroom at the full-carrier sensitivity screen. This does
  not rescue the protocol: Theorem 11.3 communication has at least 33,555,190
  E320 field elements, or 10,737,660,800 bits in the local 40-byte coefficient
  representation, leaving fewer than 93 bits in the direct BCS term at
  lambda 512.
- The current ProveKit source disables witness hiding and restricts
  conventional Merkle/transcript hashes to 256-bit digests. It is both
  incomplete-ZK and strict-width disqualified.
- Even under an explicit ideal-QRO instantiation counterfactual, current
  semantic secret-prefix screens contain exact `2^-127` and `2^-126` terms.
- GHCM21 Proposition 2 gives a conditionally viable direct SmallWood ZK
  reprogramming screen without literal BCS.  Widening only the leaf tapes is a
  heterogeneous calculation: `2*N` leaf programs at 576 bits contribute
  `3/2^172` over the `2^64`-proof history, while eight 512-bit chain programs
  contribute `3/2^158`.  Their exact sum is
  `3*(1+2^-14)/2^158` (about `2^-156.414949`).  The old approximately
  `2^-170.415` figure assumes all `2*N+8` programs have 576-bit entropy and is
  retained only as a homogeneous sensitivity.
- That route is not currently applicable to the whole implementation.  The
  first Fiat--Shamir program has only the current 256-bit global salt unless
  root entropy is separately proved, the `2*N+8` hybrid and side-information
  conditions are unproved, and GHCM supplies no soundness or extraction.  A
  64-byte salt adds 32 proof bytes but is revealed after its first use; later
  chain programs still need proved fresh conditional 512-bit prior digests or
  independent salts.  Widened-tape deltas are 184/384/440 bytes at provisional
  `q_D=23/48/55`, or 216/416/472 bytes including that one-time salt delta.

## Decisions

- Use strict advantage `< 2^-128`; never use a rounded decimal or `>=128`
  display as admission.
- Keep theorem big-O statements and local policy constants in separate JSON
  fields. A local coefficient cannot authorize a theorem claim.
- Use the CFW full-carrier coefficient `2^26` only as a conservative local
  field sensitivity. The actual algebraic theorem coefficient remains null.
- Interpret BCS Lemma 7.5 `p(x)` as total IOP proof length in bits. Apply the
  exact Theorem 11.3 communication floor and 320-bit E320 representation:
  lambda 648 still fails, and 656 first passes this floor alone. Exact `p(x)`
  and required lambda remain null because codeword/randomness lengths are not
  selected.
- Do not treat 14 proof-wire role types, 15 semantic roles, 83 relation hash
  invocations, 105 Section 11 encodings, or a one-polynomial PCS example as
  interchangeable counts.
- Do not select CapacityBound or the local `f64`/dominant-term Johnson screen.
- Keep winner, production profile, proof bytes, full composition, and every
  uninstantiated advantage null or false.
- Treat GHCM21 as a ZK-hybrid lemma only.  CMS19 soundness remains specific to
  its BCS construction; the custom vector-leaf SmallWood transform needs a new
  BCS/CMS equivalence plus exact RBR premises.  Concrete SHA-512/SHAKE QRO
  instantiation advantages stay named and null.

## Validation

The retained commands are:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  .agent/hardening/strict-odd-field-composition/check_composition.py

PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s .agent/hardening/strict-odd-field-composition -p 'test_*.py' -v

git diff --check -- .agent/hardening/strict-odd-field-composition
```

Expected outcomes are `STRICT_ODD_FIELD_COMPOSITION_CHECK_PASS`, 32 passing
tests, and no diff whitespace errors.

## Result

The artifact is an exact negative certificate. The theorem-only concrete-hash
lane is unbounded because applicable exact deployed-hash reductions are
missing. The explicit hash-as-QRO lane is also rejected by known semantic and
BCS terms before all remaining null terms are composed. E320 is the only local
field option with arithmetic headroom, but no architecture winner exists and
production remains fail-closed.
