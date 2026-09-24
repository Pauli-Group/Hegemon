# HX448C02 odd-field Boolean/R1CS screen

This is a living ExecPlan. It follows `.agent/PLANS.md` and records only the
isolated source-only screen in this directory. The repository-wide production
plan remains authoritative for release work.

## Purpose and outcome

Compile the frozen diagnostic `HX448C02` scalar/M4 transaction schedule into a
deterministic macro-R1CS over one explicit odd prime field. The artifact must
make every Boolean lowering rule, public/private byte grammar, relation family,
hash call, row count, variable count, nonzero count, and digest reproducible
without Cargo or a proof build. It must also make the known host-only
stablecoin boundary impossible to mistake for a compiled consensus predicate.

The screen is successful when a clean Python process can reconstruct the
canonical manifests byte-for-byte, verify primitive R1CS rows and transaction
surface positive/negative witnesses, and report exact `(m,n,l)` and nonzero
counts for both frozen hash profiles. Success is not production authorization:
the whole-manifest commitment, selected-entry membership, and authenticated
consensus root/height are not fixed-width witnesses in `HX448C02`.

## Constraints

- Disk admission is closed. Do not invoke Cargo, rustc, Lake, a build, a proof,
  a dependency installer, or create a large expanded matrix artifact.
- Preserve all shared edits. Only this directory may be changed by this task.
- The scalar and M4 sources are inputs. Source hashes and structural anchors
  are checked; the compiler does not claim either file is a production
  authority.
- The local Plonky3 checkout may be inspected read-only. It is a PCS source
  reference, not an R1CS adapter or a pinned Hegemon verifier.

## Progress

- [x] Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`,
  `.agent/PLANS.md`, and the repository living production ExecPlan.
- [x] Inspect the live scalar and M4 schedules, public/private layouts, hash
  registry, twenty local relation families, seven hash-link families, nine
  consensus-seam families, four host-only predicates, sixteen masks, and five
  authorization modes.
- [x] Inspect the local Hiding-WHIR adapter. It exposes a multilinear PCS over
  caller-selected two-adic fields, DFT, MMCS, challenger, and CSPRNG; it does
  not provide an R1CS compiler or select this field/profile.
- [x] Implement the deterministic compiler/checker and dependency-free tests.
- [x] Emit and verify the canonical relation and certificate artifacts.
- [x] Record final hashes, counts, test commands, and the no-go verdict.

## Design

`compiler.py` is dependency-free and has three commands:

1. `emit` reads and checks the live sources, constructs a compact macro-R1CS
   program, and writes canonical sorted/minified JSON followed by one LF.
2. `check` reconstructs those bytes in memory, compares them with the retained
   files, validates row schemas over the chosen field, runs conventional-hash
   known-answer tests, and exercises every activity mask/mode plus stablecoin
   and host-boundary mutation cases.
3. `summary` prints only retained digests and exact geometry.

The field is Goldilocks, `p = 0xffffffff00000001`, used only because it is an
explicit odd prime with a conventional 8-byte representation and is compatible
with Boolean equations containing the coefficient `2`. This screen does not
infer a Plonky3 PCS instantiation. A field element is exactly eight little-
endian bytes and is rejected if its integer is at least `p`. Public statement
and witness transports are bit-decomposed, so arbitrary 64-bit words never
undergo lossy reduction.

The R1CS convention is `(A z) * (B z) = (C z)` with
`z = (1, public[0..l], auxiliary)`. `n` counts all nonconstant variables and
`l` counts public variables. Each sparse term is a `(column, canonical field
element)` pair, columns are strictly increasing, zero coefficients are absent,
and rows are serialized in construction order. The retained artifact is a
macro program, not an expanded multi-million-row file; every macro pins its
closed-form expansion counts and selected rows can be expanded by the checker.

The 869-byte statement contributes 6,952 public bits. The 50-word consensus
state seam contributes 3,200 public bits. Thus `l = 10,152`. The private
transport is exactly 1,209 words / 9,672 bytes / 77,376 bits. The internal
109-word M4 projection aliases the 869 statement bytes plus 24 fixed zero pad
bits; it is never parsed as a field element.

Boolean primitives are exact over every odd field:

- bitness: `x * (x - 1) = 0`;
- AND: `x * y = z`;
- XOR: `(2x) * y = x + y - z`;
- equality/wiring: `(x - y) * 1 = 0`;
- conditional equality: `s * (x - y) = 0`;
- select: `s * (a - b) = z - b`.

The hash macros expand RFC 7693 BLAKE2b-448 as Boolean ARX with exact byte
counters and final masks, FIPS 202 SHAKE256-448, and the separately tagged
SHA3-512/truncate-448 control. Keccak rotations and permutations are aliases;
XOR, Chi, and Iota use only the pinned Boolean rows. Authorization mode arms
are selected before hashing.

## Validation and acceptance

Run, with bytecode disabled:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py emit
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/test_compiler.py
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py summary

Acceptance requires all commands to pass, canonical files to be unchanged by a
second `emit`, source hashes to match the certificate, all 15 nonempty masks to
have at least one accepted authorization mode, the all-empty mask to fail, all
five modes to have a positive case, every listed mutation to fail at the
correct layer, and all production/security authority flags to remain false.

## Decisions

- 2026-08-22: Use raw public bits rather than 159 public u64 field elements.
  Goldilocks cannot canonically encode every u64 word; reduction would create
  statement aliases.
- 2026-08-22: Retain both mixed and split-control profiles in the screen. Exact
  R1CS size is compared only after relation coverage is identical.
- 2026-08-22: Encode the flat-manifest and consensus-authentication predicates
  as explicit host-boundary blockers, not invented fixed-size constraints. The
  live flat vector has no consensus cap or membership path in the relation.
- 2026-08-22: Do not claim the inspected Plonky3 checkout as a field, IOP,
  challenger, MMCS, or release pin. Its Hiding-WHIR adapter is only a source
  reference for the later PCS composition step.
- 2026-08-22: Alias parser-synthesized statement padding, fixed constants,
  rotations, permutations, and frame source bits instead of allocating copy
  witnesses. This preserves the exact 10,152-bit public grammar and removes
  redundant R1CS copy rows from the retained macro schedule.
- 2026-08-22: Keep the four host-only predicates as a decisive negative
  baseline. The smallest source-compatible successor currently identified by
  the separate closure screen is a cap-16/depth-4 canonical manifest with
  exact 183-byte rows, strict `(asset_id,policy_version)` ordering, a private
  BLAKE2b-448 membership path and 56-byte root, compiled 61-byte
  policy-identity BLAKE2b-384, and verifier-authenticated parent root/height.
  None of that successor closure is marked compiled in this artifact.

## Surprises and discoveries

- `HX448C02` appends a typed 50-word consensus seam to the public relation, but
  the 869-byte statement itself does not carry the expected root/height
  authority separately from that seam.
- The scalar and M4 sources are still untracked/shared working files and can
  change during this campaign. `emit` therefore fails on structural drift and
  pins the exact bytes it consumed.
- Three stablecoin authorities are 48 bytes while transaction digests are 56
  bytes. This compatibility seam is retained exactly and is not advertised as
  a positive composed PQ128 margin.

## Final results

The retained source-only screen passes. It compiles exactly 6,952 statement
bits plus 3,200 state-seam bits as `l=10,152`, and exactly 1,209 private words
as 77,376 private transport bits. All twenty local families, seven hash-link
families, and nine state-seam families have nonzero macro-R1CS rows. The test
matrix covers all 80 `(mask,mode)` pairs: 33 accept and 47 reject; mask zero
rejects in every mode, every nonempty mask has an accepting mode, and every
mode has a positive case. Sixteen relation-visible counterfeit mutations
reject. Four host-only counterfeits remain indistinguishable to this R1CS and
therefore disqualify it as a full production relation.

Exact retained macro geometry over Goldilocks is:

- BLAKE2b-448 mixed: `m=20,457,227`, `n=19,311,555`, `l=10,152`,
  19,224,027 derived auxiliaries, and 94,551,238 matrix nonzeros.
- SHA3-512 split control: `m=23,727,052`, `n=23,613,572`, `l=10,152`,
  23,526,044 derived auxiliaries, and 112,255,042 matrix nonzeros.

Both candidate Section-11 embeddings have `ell=33,554,432` and a
`67,108,864`-row square shape. For mixed, public/witness/row padding is
33,544,279 / 14,253,029 / 32,398,608 and embedded nonzeros are 123,057,296.
For split control, public/witness/row padding is 33,544,279 / 9,951,012 /
33,430,800 and embedded nonzeros are 132,157,066. These are candidate mapping
counts, not a theorem binding, proof build, proof-byte measurement, or PCS
profile.

Verification on 2026-08-22:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py emit
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/test_compiler.py
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py summary

`check` passed; all 15 tests passed. The manifest is 102,003 canonical bytes,
its SHAKE256-512 identity is
`81f88eb0afd355bbd50d90d0760b65e341b4b490a29af3d5e0a8acf1721e42792bd547fd62559263f1c70edf365fb482fde2f88117c3ae98b2360934a3c75254`,
and its source-set SHA-512 is
`968bfcf34da1caf9fed1c81581a225dffb0e7ba160c5ed1cda5900dfe59f3286e877f7646da91089050c788338f29a40db65b73dc5ccbf95280ff0173ee2575a`.
Retained file SHA-512 values are:

- `compiler.py`: `62bd836c41fac8691e2ff97414c33d3bb955ae2b5cb833721e811e3e52b43c1793676a98178007fc3727bad825545cd8075d06b44c467d4d54b6a3cdf70226b5`
- `test_compiler.py`: `e5e4eb4a5b2b3ff8f54160d5f498e7908b4166f14e867eeff5710c0b958643a4f0961718792a7efe8bdfeba7524d77fe04bb08c5dfc1a9c2ccdf0aa6e98e0069`
- `relation_manifest.json`: `dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e`
- `certificate.json`: `f6b2cdc6944a55c013d5d89644579ac8e10cb20cac7e74e5887b8230c735e3b8d4adea09a130fe35e8eb0327ba99ec8ac27e119b764c3995a15d2b16375e4bfd`

The frozen scalar source SHA-512 is
`905ffb7e3b8b2f28ba4600ef498acddba8d9125a859adb1cb10c97a0ec4ebd993858e88b91eda6465d49f05172a31a49057203457abf04717cf9efbe7fd195d9`;
the frozen M4 source SHA-512 is
`0cd45615489f2f84bfc803e7d94f0c7309c24a2ef37c8df4fdde0c651d0a81ba63502fe4fdfe41f7e6e3f68477797a951a878da42540a2d2b4e4f1eca624179c`.
Every production, relation-identity, complete-ZK, composed-QROM, PCS-selection,
and verifier-refinement flag remains false. Verdict:
`SOURCE_ONLY_SCREEN_COMPLETE_ROUTE_DISQUALIFIED_BY_HOST_BOUNDARY_AND_UNPROVED_REFINEMENT_SECURITY`.
