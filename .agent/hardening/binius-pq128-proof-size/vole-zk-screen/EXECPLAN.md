# Screen transparent VOLE proof sizes for full M4

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds. It is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

The goal is to determine, without a heavy build, whether a transparent
VOLE-in-the-head or MPC-in-the-head zero-knowledge proof can carry the complete
83-permutation M4 action relation in fewer than 124,068 bytes. A developer can
run one Python command to see every proof component, the best Keccak checkpoint
spacing, and the strict security admission gates. The screen must reject the
invalid shortcut that treats one 64-bit bitwise AND as one field
multiplication.

## Progress

- [x] (2026-08-21 18:25Z) Pinned the M4 geometry and exact public/private byte
  transport from current source.
- [x] (2026-08-21 18:50Z) Read the primary VOLE-in-the-head, QuickSilver,
  FAEST-v2, PoMFRIT, and Picnic sources and official implementation pages.
- [x] (2026-08-21 19:10Z) Implemented the generic gate screens, high-degree
  Keccak checkpoint search, transparent forest accounting, and conservative
  QROM numeric screen in `vole_zk_screen.py`.
- [x] (2026-08-21 19:18Z) Implemented the proposed fail-closed transport header
  parser and negative tests in `wire_layout.py` and `test_wire_layout.py`.
- [x] (2026-08-21 19:27Z) Ran all nine lightweight tests, documented the no-go,
  and captured source hashes. No Cargo build, prover, or ledger mutation ran.

## Surprises & Discoveries

- Observation: The stated roughly 50,000 word-ANDs are exactly 49,800 Keccak
  lane operations, but each is 64 Boolean multiplications.
  Evidence: `83 * 24 * 25 = 49,800` and `49,800 * 64 = 3,187,200`, matching the
  M4 geometry assertion.

- Observation: A real primary-source Keccak optimization exists. Four forward
  rounds have degree 16 and two inverse rounds have degree 9, so one committed
  state per six-round interval reduces per-permutation nonlinear data from
  4,800 to 800 bytes.
  Evidence: the independent one-permutation model gives 14,690 bytes against
  the PoMFRIT implementation's reported 14.9 KB.

- Observation: The strict transparent forest misses the cap before Keccak is
  priced.
  Evidence: 32 small VOLEs times the frozen 5,368 private bytes is 171,776
  bytes, already larger than 124,068.

- Observation: The best full-M4 checkpoint span is 12 rounds, not the paper's
  six-round point, because the proof-size objective tolerates a degree-243
  response to halve checkpoint states.
  Evidence: exhaustive spans 1 through 24 produce 1,632,012 bytes at span 12
  for the lambda-384 forest.

## Decision Log

- Decision: Count every lane bit as a distinct multiplication for the generic
  binary protocol, and retain the word-level count only as a labeled invalid
  reward-hacking control.
  Rationale: QuickSilver's binary protocol is over a field; component-wise
  multiplication of 64 bits is a product ring, not one field multiplication.
  Date/Author: 2026-08-21 / Codex.

- Decision: Use a per-tree GGM forest opening for the strict screen instead of
  crediting FAEST v2's one-tree compressor.
  Rationale: no official lambda-384 parameter set or implementation exists, so
  extrapolating its compressed opening would make an unsupported size claim.
  Date/Author: 2026-08-21 / Codex.

- Decision: Price SHAKE256-512 outputs, a complete embedded public transport,
  and the PoMFRIT four-lambda simulator randomizer.
  Rationale: the requested artifact is a standalone complete-ZK action proof,
  not a signature-size analogy with omitted transport or simulation bytes.
  Date/Author: 2026-08-21 / Codex.

- Decision: Keep every frontier and strict capability gate false.
  Rationale: the numeric screen is not an exact M4 refinement, complete-ZK
  theorem, QROM theorem, production parser, or independently reviewed prover.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The source-only tool now gives a reproducible no-go rather than an intuitive
estimate. Generic binary VOLE-in-the-head is 6,374,400 bytes at the primary
paper's 16-bit-per-AND point. The real degree-checkpoint architecture cuts that
substantially, but the best strict forest remains 1,632,012 bytes. The useful
next research boundary is therefore not another small parameter tweak: beating
the cap requires a different proven witness commitment/VOLE generator or a
succinct delegation layer. This directory intentionally does not implement
either expansion.

## Context and Orientation

The scalar relation lives in
`circuits/standalone-full-shake256-relation-prototype/src/lib.rs`. The binary M4
realization lives in
`prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs`,
and its geometry-only executable contract is the adjacent `src/main.rs`. M4
uses 671 private 64-bit words and 114 public words. Its 83 Keccak-f calls each
have 24 rounds, and each round's chi layer has 25 lane-word ANDs, with 64 bits
per lane.

VOLE means vector oblivious linear evaluation, a correlation that gives the
prover homomorphic witness commitments and gives the verifier a hidden MAC
key. VOLE-in-the-head replaces an online designated verifier with hash-based
all-but-one vector commitments, making the proof public and transparent.
QuickSilver evaluates low-degree constraints over those commitments. A
checkpoint is a committed internal Keccak state used to stop polynomial degree
from growing across all 24 rounds.

The screen is isolated under
`.agent/hardening/binius-pq128-proof-size/vole-zk-screen/`. It has no third-party
Python dependencies and writes no persistent output.

## Plan of Work

First, pin the local relation scale and serialization. The public bytes are the
853-byte canonical statement, three zero padding bytes, and the 56-byte derived
intent. The private byte stream uses big-endian semantic integers and verbatim
opaque arrays, then loads every eight-byte chunk as a little-endian M4 word.

Second, encode the primary-source communication models. The generic screen
multiplies valid Boolean AND count by reported bits per gate. The optimized
screen splits each checkpoint interval into forward degree-2 rounds and inverse
degree-3 rounds, chooses the minimum maximum degree, and prices correction
vectors, consistency, witness derandomization, QuickSilver coefficients, GGM
openings, transcript values, public transport, and parser bytes.

Third, fail closed on security. Report a conservative numeric QROM estimate,
but require separate Boolean gates for exact relation refinement, complete ZK,
an exact QROM theorem, and a production parser. No combination of numeric
parameters may turn those evidence gates on.

Finally, test the formulas against official FAEST sizes and the implemented
PoMFRIT Keccak point, run all checkpoint spans, rehash the owner-controlled
source files, and report the result without promoting a frontier row.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, inspect the result with:

    cd .agent/hardening/binius-pq128-proof-size/vole-zk-screen
    python3 -m unittest -v test_vole_zk_screen.py test_wire_layout.py
    python3 vole_zk_screen.py --profile strict384 --compact
    python3 vole_zk_screen.py --profile faest256 --compact

The test command must finish with:

    Ran 9 tests
    OK

The strict JSON must contain `total: 1632012`,
`conservative_numeric_bits: 170`, `below_cap: false`, and
`frontier_admitted: false`. The FAEST-256-shaped JSON must contain
`total: 1031576`, `conservative_numeric_bits: 120`, and
`numeric_pq128_pass: false`.

## Validation and Acceptance

Acceptance requires all nine tests to pass. The tests must reproduce 49,800
word-ANDs, 3,187,200 Boolean ANDs, official FAEST-v2 signature sizes of 4,506
and 20,696 bytes, a degree-16 4+2 Keccak split, and the 14,690-byte independent
one-permutation calibration. Parser tests must accept one exact envelope and
reject truncation, trailing bytes, and nonzero reserved bytes. Both complete
M4 profiles must remain above the cap and unadmitted.

No Cargo command, Rust prover, network download, or shared design document edit
is part of validation. The disk gate remains respected.

## Idempotence and Recovery

All commands are read-only except Python's optional `__pycache__`, which can be
removed safely after validation. Re-running the model produces identical JSON.
If owner-controlled M4 sources change, update `SOURCE_PIN.md` only after
re-reading the changed constants and serialization functions; do not blindly
replace hashes while retaining stale facts.

## Artifacts and Notes

The important measured transcript is:

    test_degree_16_keccak_checkpoint_matches_primary_construction ... ok
    test_official_faest_v2_rows_reproduce_spec_sizes ... ok
    test_one_permutation_calibrates_to_pomfrit_14900_byte_result ... ok
    test_strict_screen_never_promotes ... ok
    Ran 9 tests in 0.002s
    OK

`README.md` contains the claim boundaries and primary source URLs.
`SOURCE_PIN.md` contains the local source hashes and exact anchors.

## Interfaces and Dependencies

`vole_zk_screen.py` exports `M4Relation`, `VoleProfile`,
`best_keccak_degree_split`, `checkpoint_estimate`,
`best_checkpoint_estimate`, `paper_linear_screens`, and
`faest_v2_signature_bytes`. They use only the Python standard library.

`wire_layout.py` exports `Header.encode`, `parse_header`, and
`section_slices`. Its 200-byte header uses little-endian fixed-width integers,
a 64-byte relation digest, fixed M4 geometry, explicit VOLE parameters, eleven
section lengths, and zero reserved bytes. It parses transport only; a future
cryptographic verifier must validate the actual proof sections.

Revision note (2026-08-21): Created after completing the bounded source-only
screen so the rationale, commands, evidence, and non-promotion boundary remain
recoverable without conversation history.
