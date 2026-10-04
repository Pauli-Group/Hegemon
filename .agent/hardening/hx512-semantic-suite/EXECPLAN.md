# Freeze the HX512 semantic-suite source candidate without activation

This ExecPlan follows `.agent/PLANS.md` and owns only this directory.  It does
not authorize Cargo, proof generation, production edits, or release claims.

## Purpose

Freeze the smallest fresh 64-byte conventional-hash semantic schedule that
can survive the known 384/448 multi-user screen, compare it with a distinct
SHA-512/SHAKE256-512 control, and expose rather than conceal every remaining
PQ/QROM and complete-ZK blocker.

## Progress

- [x] Pin the exact HX448C02 83-call source schedule and odd-field macro basis.
- [x] Allocate fresh statement, relation, action, network, suite, backend,
  proof-profile, and domain-set identities.
- [x] Widen every semantic digest, stablecoin authority, manifest root, state
  snapshot, private secret, and public identifier to 64 bytes where required.
- [x] Adopt the frozen specialized all-W64 HGMA authority schedule and reject
  the larger generic HX512 authority framing.
- [x] Freeze exact statement/witness/row/source grammars, call counts,
  compression/permutation counts, R1CS projection, KATs, mutations, and pins.
- [x] Source-pin the inactive native V2 module/checker/tests; freeze verifier
  context as `manifest_root64 || parent_height:u64le`, keep the snapshot in
  the statement, and preserve zero as a valid canonical policy version.
- [x] Retain separate theorem-only and conditional nonzero hash-as-QRO ledgers,
  including the independent BCS lambda blocker.
- [x] Run the dependency-free checker and tests; retain canonical JSON.
- [ ] Compile an expanded relation, close formal/native refinement, instantiate
  the proof-system security theorem, generate and measure a proof, and pass
  lifecycle/release gates.  These steps are outside this source-only plan.

## Decision log

- The 56-byte/448-bit route is disqualified: the conservative two-input,
  `2^32`-proof epoch prefix hybrid is `2^-126`.
- The manifest authority uses the frozen parameter personalizations because
  they bind identity role, root role, profile, width, cap, and level while
  saving six BLAKE2b compressions versus the discarded generic frame.
- Core and authority use separate registries, jointly fixed by domain-set
  identity.  No parser accepts the discarded authority encoding.
- The BLAKE candidate wins this source-cost screen, not production admission.
- The first suite draft carried an unsupported 14,616-row authority estimate.
  The final emitted six-group compiler ledger is exactly 11,592 rows
  (`186+1088+512+5696+1934+2176`).  No missing predicate justified the former
  3,045-row excess, while red-team review did identify exactly 21 required
  high-bit-zero rows for three byte-encoded booleans.  The existing 64-row
  absent-`retired_at` constraint is separate and was not double counted.
- Native V2 source review disqualified the compiler's earlier
  `snapshot64 || height` context projection.  The exact public-authority codec
  carries `manifest_root64 || parent_height:u64le`; statement `state_root`
  remains the derived snapshot.  The recomputed manifest-root equality was
  already present as 512 rows in the 5,696-row group, so this semantic repair
  adds zero rows.  Native V2 accepts every canonical `u32` policy version,
  including zero, so no policy-version nonzero predicate is permitted.
- The two 64-byte authorization masters are opening-specific `current` and
  `next` values.  Accumulator initialization selects next and zeros current;
  approval maps slot 0 to current and slot 1 to next and requires equality;
  value-lock/final use current and zero next; single-key zeros both.  The
  selected-policy mux therefore widens by 512 rows and approval continuity
  adds 512 rows.  The exact correction is +1,024 rows, with no padding or
  additional hash calls.

## Acceptance

`hx512_suite.py --check` must reproduce all four JSON artifacts byte-for-byte;
all dependency-free tests must pass; source pins must match; selected BLAKE
counts must be 90 calls / 213 compressions / 29,510,157 rows; control counts
must be 37 SHA-512 compressions / 183 SHAKE permutations / 36,868,145 rows;
production must remain false and proof bytes null.
