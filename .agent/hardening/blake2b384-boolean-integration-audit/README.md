# RFC 7693 BLAKE2b Boolean integration audit

This is retained source-only evidence. It is not a proof artifact, a compiled
relation, a complete-zero-knowledge certificate, a PQ/QROM certificate, or
production authorization.

## Verdict

`circuits/transaction/src/smallwood_blake2b384.rs` is a real bit-level RFC 7693
ARX trace, not a call to the repository's host digest. Its parameter word,
little-endian message words, 128-bit byte counter, final-block mask, twelve
sigma rounds, additions with carry, XOR, NOT, rotations, and output truncation
match an independent Python implementation and `hashlib.blake2b` on 32 retained
unkeyed/keyed/personalized cases. The source-only checker also independently
reproduces the constant-folded scalar gate inventory.

The integration is not a production relation. The dormant 48-byte V5 adapter
constructs native reference digests and separately validates each Boolean
trace, but it does not lower all source, digest-reduction, and cross-call
equalities into one committed proof graph. The `HX448C02` scalar diagnostic
reuses the same generic core at the 56-byte output width. The frozen M4 source
does not call this Rust trace object: it independently lowers RFC 7693 as
64-bit `iadd`, `bxor`, and `rotr` operations. That scalar-to-M4 relationship is
therefore parity evidence, not shared executable authority.

The legacy SmallWood frontend still returns
`smallwood_blake2b384_boolean_relation_is_compiled() == false`. The HX scalar
candidate still sets both aggregate-relation-compiled and production authority
to false. Those gates are correct and are pinned by the mutation suite.

## Repairs in this audit

The gadget now derives one canonical block-descriptor schedule and uses the
same descriptor values for compression counters/final flags and retained
metadata. `verify_constraints()` rejects mutated counter, final, absorbed-byte,
or offset metadata. A central `verify_input_bindings()` API checks every key and
message source bit; both the dormant V5 adapter and the HX scalar caller use it
instead of relying on hand-written caller loops. Gate and row accounting now
includes external key/message bindings as well as output bindings. Rust tests
add wrong-key/message/length rejection, every constraint-family mutation, and
block-metadata mutation cases.

The dormant V5 schedule remains prohibitively large: 77 calls and 164
compressions produce 16,322,454 internal scalar constraints, projected as
255,100 per-call packed-64 rows. The newly explicit source equalities add
120,520 constraints / 1,906 rows; output equalities add 29,568 / 462 rows; the
per-call combined equality projection is 2,368 rows. These are source/compiler
counts, not proof bytes or an actual SmallWood row measurement after global
packing and DCE.

## Source-only checks

From the repository root:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/blake2b384-boolean-integration-audit/check.py
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/blake2b384-boolean-integration-audit/test_check.py

The first command must emit `"status": "pass"`; the second must reject ten
source mutations covering IV, counter-high, final flag, a host-digest shortcut,
caller input binding, compiled/authority flags, the M4 output-length parameter,
and the M4 final mask.

No Cargo, rustc, Lake, proof generation, dependency installation, or heavy
build was run for this audit because the repository disk gate was closed. The
new Rust tests are retained but remain unexecuted until that gate opens.

## Blockers

- No aggregate source/digest/non-hash equality graph is compiled for either
  the dormant V5 adapter or `HX448C02`.
- The actual M4 lowering is an independent implementation and has not been
  compiled or differentially executed under the closed disk gate.
- BLAKE2b-384 has no positive generic quantum-collision composition margin
  beyond 128 bits, so the dormant 48-byte profile cannot satisfy the composed
  strict target.
- Complete zero knowledge, deployed transcript/QROM composition, verifier
  refinement, fresh identity, measured proof bytes, and lifecycle artifacts
  remain absent. Production must remain fail closed.
