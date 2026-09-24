# ExecPlan: source-bound full-M4 binding vector PCS audit

## Objective

Audit the missing hiding/binding transparent vector-opening PCS in the
`86,752`-byte mixed-field geometry. The remaining raw PCS plus algebraic-ZK
budget is `37,316` bytes. The result must be source-only, executable on a
small toy instance, and fail closed until a theorem-backed construction and
QROM ledger exist.

## Invariants

- Committed symbols are B128; algebraic challenges are the real cubic E384
  field, not a product ring.
- SHAKE256-512 is used for Fiat--Shamir; Merkle nodes are SHAKE256-448
  (56 bytes) and are priced independently.
- Full-M4 source anchors are revision
  `3f96163049f680b2909f6545690bd929f1b48c44`, 853 public bytes, 114 public
  words, 671 private u64 words, and 83 Keccak-f calls.
- The Keccak chi inventory is exactly
  `83 * (24*5*5*64) = 3,187,200` BitAnd constraints. Python probes only
  representative BitAnd/shift/public transport behavior and never allocate
  or build the circuit.
- An E384 OTP/mask is three independent B128 coordinates. The relation-
  independent candidate commits one joint `[pi || omega]` leaf and charges
  both shares' three-coordinate query rows.
- No trusted setup, pairings, aggregation, Cargo build, network, or full
  oracle allocation is allowed under the disk/resource gate.

## Construction boundary

The former one-lane affine kernel toy is a negative control only. Full M4 has
quadratic BitAnd constraints, so affine translation does not preserve the
relation. The replacement seam is

    pi' = (1-gamma)pi + gamma omega
    sigma = <omega,T>
    alpha = <pi',T>

The toy proves one linear claim with a canonical parser and SHAKE256-448
Merkle frontier. The production model prices 113 optimistic wide claims,
two E384 messages per fold variable, all terminal E384 values, and one sigma
per alpha. It separately records the unresolved nonlinear cross terms rather
than treating them as zero bytes.

Padding-aware terminal accounting reports the active prefix and zero suffix.
No terminal-target/rank-3 elision is deducted because full random omega masks
the inactive suffix unless an additional zero-tail theorem is supplied.

## Source artifacts

- `binding_vector_pcs.py`: fields, transcript, source inventory, M4 probes,
  joint-mask toy, exact wire searches, and GhashSq256b comparison.
- `test_binding_vector_pcs.py`: 19 parser, arithmetic, relation-probe,
  wire-region tamper, geometry, and fail-closed tests.
- `README.md`: assumptions, formulas, exact results, and claim ceiling.

## Validation contract

From the repository root:

    python3 -m py_compile .agent/hardening/binius-pq128-proof-size/binding-vector-pcs/binding_vector_pcs.py
    python3 .agent/hardening/binius-pq128-proof-size/binding-vector-pcs/binding_vector_pcs.py --toy-check --report
    python3 -m unittest discover -s .agent/hardening/binius-pq128-proof-size/binding-vector-pcs -p 'test_*.py'

Expected results:

- `q=68`, with the stated component query term at least 264 classical bits;
- exact private transport packing `ceil(671/2)=336` B128 symbols;
- n15 optimistic joint mask row: fold 5, rate 13, q 44, frontier 768,
  vector 178,296, alpha/sigma 110,112, raw 288,408, envelope 288,420,
  joint oracle 24 GiB;
- n16 optimistic joint mask row: fold 5, rate 12, q 47, frontier 816,
  vector 190,200, alpha/sigma 208,416, raw 398,616, envelope 398,628,
  joint oracle 24 GiB;
- GhashSq256b two-repetition arithmetic screen: 136 bits per repetition,
  272 raw product bits, 136 conservative composed bits;
- separate 5,644-target hash ledger: 211.5375 classical / 136.8708 generic
  QROM bits for 448-bit Merkle nodes and 243.5375 / 158.2042 for 512-bit
  Fiat--Shamir;
- 20 passing tests and `strict_admitted=false`.

The explicit masked BitAnd expansion has three cross-term products per gate:
`3 * 3,187,200 * 48 = 458,956,800` E384-priced bytes before any full
relation proof. Even the unsound hypothetical all-terminal-elision screen
remains over budget (`72,472` bytes for n15), so terminal-target cuts cannot
rescue this declared model.

## Status

Completed source-only implementation and audit. The exact no-go applies to
the declared optimistic `[pi || omega]` wire model under the stated
three-coordinate E384 mask, full-M4 relation-claim, 28 GiB oracle, and
37,316-byte budget assumptions. Strict admission remains blocked by the
uncompiled active trace dimension, nonlinear BitAnd masking compiler,
complete simulator, verifier refinement, and composed QROM evidence.
