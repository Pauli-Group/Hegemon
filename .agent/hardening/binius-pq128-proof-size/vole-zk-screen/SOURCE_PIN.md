# Source pin

Captured 2026-08-21. Re-run `shasum -a 256` before relying on these values;
the workspace files are untracked research artifacts and may still be edited
by their owner.

| role | path | SHA-256 |
|---|---|---|
| scalar full relation | `circuits/standalone-full-shake256-relation-prototype/src/lib.rs` | `e251d0d6ade5948cb603de8d50d7a2f655d87dfb15378b327efce7297a74c3f2` |
| sealed public transport | `circuits/standalone-full-shake256-relation-prototype/src/composed_envelope.rs` | `b3173460a5e1bcbfcf364ba35b9a69da0881e697e8e16667eacf4b4669fc749e` |
| M4 relation | `prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs` | `67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91` |
| M4 geometry contract | `prototypes/standalone-shake256-binius/m4-full-production-prototype/src/main.rs` | `d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c` |
| realization map | `prototypes/standalone-shake256-binius/m4-full-production-prototype/REALIZATION_MAP.md` | `84c9d2ef603288978433da6d96431cc47d4a0f900e15ef92241409259f282b84` |

Frozen logical upstream revision declared by the M4 crate:
`3f96163049f680b2909f6545690bd929f1b48c44`.

Anchors used by the model:

- M4 `src/lib.rs`: `PUBLIC_WORDS`, `PRIVATE_WORDS`, `serialize_private_witness`,
  `pack_private_words`, and `public_words_from_binding`;
- M4 `src/main.rs`: 83-permutation geometry and
  `KECCAK_ANDS_PER_PERMUTATION = 24 * 5 * 5 * 64`;
- scalar `src/lib.rs`: `CANONICAL_STATEMENT_BYTES = 853`,
  `M4_DERIVED_INTENT_WORDS = 7`, and
  `M4_FIXED_KECCAK_PERMUTATIONS = 83`.

Primary formula anchors used by `vole_zk_screen.py`:

- Baum et al., VOLE-in-the-Head, Table 1 (PDF page 4): 16 F2 elements per
  Boolean AND for VOLEitH and 42 for Limbo at soundness at most 2^-128 for the
  2^20-gate comparison circuit.
- FAEST v2 specification, section 3.1 (PDF pages 12--13):
  `tau*(ell+3*lambda+B) + Topen*lambda + nleafcom*lambda*tau + lambda + 128 + 32`
  bits. The tests reproduce the 4,506-byte and 20,696-byte official rows.
- PoMFRIT, section 1.2 and section 7 (PDF pages 1--2 and 10--11): one
  SHAKE256 Keccak checkpoint vector falls from 4,800 to 800 bytes by committing
  every sixth state and using a degree-16 constraint; Table 2 reports 14.9 KB.
- PoMFRIT, Appendix B.2 (PDF pages 17--18): Assert uses `d-1` mask VOLEs and
  sends `d` extension-field elements; circuit evaluation communicates
  `ell+t` base-field elements plus `d` extension-field elements.
- PoMFRIT, Appendix B.3 (PDF pages 18--19): `comrand` plus `rand` adds
  `4*lambda` proof bits for the stated complete-ZK simulation split.
