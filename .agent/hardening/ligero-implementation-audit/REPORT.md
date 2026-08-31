# Original Ligero implementation-readiness audit

## Frozen verdict

**Disqualified as an implementation-ready backup.**  The pinned executable is
not the exact protocol proved in the 2022 Ligero paper.  It implements the
AHIV17 construction as adapted to R1CS in Aurora Appendix B, adds libiop's LDT
reducer/direct LDT, and then applies a custom, “slightly modified” BCS layer
with a final proof of work.  No refinement identifies that round graph with
Ligero 2022 Section 4.7.  Accordingly, neither Lemma 4.15's explicit
perfect-view simulator nor Section 5.2's protocol-specific round-by-round
soundness (RBR) analysis applies to the executable.

This is not merely an absence of paperwork.  The source hardcodes the
zero-knowledge encoding-independence parameter to three while explicitly
admitting that the solved query bound is not forwarded because larger
independence has a bug.  The BCS transcript is not the CMS Section 8.2 chain,
does not bind the statement or Hegemon context before the first challenge, and
has no conventional-hash serializer.  Its reported “argument size” is an
in-memory payload count, not proof bytes.

Every authority gate is false.  Proof bytes, proof bounds, composed advantage,
composed security bits, relation geometry, retained artifact path, and all
release authority are null.

## Claim boundary and relation input

No build, clone, proof generation, dependency installation, or production edit
was performed.  The source audit used the local pinned libiop tree at
`/private/tmp/aurora-libiop-audit-a2ed/libiop-a2ed2ec2f3e85f29b6035951553b02cb737c817a`.
The selected 6,152-line protocol/BCS/test surface is SHA-512 pinned file by file
in `ledger.json`.

The HX512 relation itself is not frozen.  Red-team review invalidated the
count-only compiler and a semantic repair changed the provisional geometry.
Only this interface is retained:

| Stable item | Value |
| --- | ---: |
| statement | 1,141 bytes |
| verifier context | 72 bytes |
| context grammar | `manifest_root[64] || parent_height:u64le` |
| public interface | 9,704 bits, LSB-first |
| private transport | 88,000 bits / 11,000 bytes |

The field, `m`, `n`, nonzero count, relation digest, and certificate digest are
null.  No provisional geometry is used for a proof-size or parameter claim.

## Exact primary protocol pin

The primary construction is
[Ligero ePrint 2022/1608, archive version 20221118:030830](https://eprint.iacr.org/archive/2022/1608/20221118:030830/),
SHA-512
`04ddcdfc4f95ba68c3149e0d8efab8f3818eb8b5966b15f3f3917a21ff7d22e91c06bd2bad9406c5bc169091b437eb8005aa5cd63b98f297d6cb6de36428d054`.
It is the extended CCS 2017 paper with tighter analysis, an updated
implementation discussion, and formal proofs.

The theorem-bearing protocol is exactly Section 4.7's arithmetic-circuit
ZKIPCP.  It uses randomized encodings `U_w`, `U_x`, `U_y`, and `U_z`,
per-repetition blinding codewords, two verifier-challenge stages, and a final
set `Q` of queried positions.

- Lemma 4.15 gives an explicit honest-verifier perfect simulator under
  `k > ell + t`.
- Theorem 4.7 claims perfect completeness, the printed soundness bound under
  `e < (n-k)/4`, and an identical-view simulator for every adversarial
  verifier.
- Section 5.2 gives a state-function/RBR split for this protocol: the first
  challenge contributes `(d+2)/|F|^sigma`, and the third contributes
  `(1-e/n)^t + 2*((e+2*k)/n)^t`.

These are real protocol-level zero-knowledge and RBR results.  They are not
generic properties of codewords named “Ligero.”

The optimized Section 5.3 choice `e=k, n=3k` does not meet Theorem 4.7's
printed `e<(n-k)/4` premise.  It uses the later `e<d/2` proximity result and
Appendix C's joint-test analysis.  The paper does not restate a
protocol-specific RBR state function for that refined bound.  Therefore the
optimized profile is ineligible for CMS until that RBR proof is supplied; an
ordinary soundness substitution is insufficient.

## What libiop actually implements

The pinned source is
[scipr-lab/libiop at `a2ed2ec2f3e85f29b6035951553b02cb737c817a`](https://github.com/scipr-lab/libiop/tree/a2ed2ec2f3e85f29b6035951553b02cb737c817a),
dated 2021-05-13 and MIT licensed.  The latest tagged release recorded in this
audit is v0.2.0 (2020-08-13).  README lines 11 and 85-92 identify its Ligero as
AHIV17 and state that the implemented R1CS extension is the one in
[Aurora ePrint 2018/828 Appendix B](https://eprint.iacr.org/2018/828.pdf).
README line 17 calls the library an academic proof of concept that is not ready
for production.

The closest specification is Aurora Appendix B.3, “Interleaved ZKIPCP for
R1CS,” followed by Appendix B.4's generic lift from an encoded IPCP to a regular
IPCP.  Appendix B.3 explicitly defines `b` as the query bound required for zero
knowledge.  libiop's hardcoded value three and acknowledged failure to forward
the solved query bound therefore break the most direct mapping even to that
older specification.

| Surface | Exact executable behavior | Why 2022 inheritance fails |
| --- | --- | --- |
| relation frontend | Builds `(1, primary, auxiliary)`, computes `Az`, `Bz`, `Cz`, and commits interleaved R1CS rows (`encoded/ligero/ligero.tcc:218-333`) | Section 4.7 proves an arithmetic-circuit wire layout and different oracle/check structure |
| low-degree layer | Composes the R1CS protocol with an LDT reducer and direct LDT (`ligero_iop.tcc:303-355`) | Adds verifier states and four error sources absent from Section 5.2's state function |
| proof rounds | Witness/masks, R1CS responses, then LDT proof (`ligero_iop.tcc:359-373`) | Not the exact two-challenge/final-query schedule proved in 2022 |
| zero-knowledge | Random masks exist, but independence is hardcoded to 3 (`encoded/ligero/ligero.tcc:44-49`) | No simulator/refinement for the actual opened view |
| Fiat-Shamir | Custom root/message absorption plus custom final PoW | Neither the Ligero Section 5.2 transcript nor CMS Section 8.2 modified BCS |

The top-level parameter code lists four separately allocated soundness errors:
direct-LDT query error, LDT-reducer interactive error, encoded-protocol
interactive error, and encoded-protocol query error
(`ligero_iop.tcc:30-71`).  Component error budgeting is not a whole-protocol
RBR state function.

### Complete-ZK blocker

`ligero_iop.tcc:61-67` says the solved query bound is not passed to encoded
Ligero because sampling sufficiently high-wise-independent polynomials has a
bug; it says this does not affect the *reported argument size*.
`encoded/ligero/ligero.tcc:44-49` then sets
`encoding_independence_ = 3`.  Query count is solved elsewhere and is not fixed
to three.  Thus `make_zk=true` demonstrates an intended masking mode, not a
complete-ZK theorem for the executable.  The audit does not assert a concrete
witness-recovery attack; it records the narrower, source-proved conclusion
that complete view independence and the 2022 simulator are unestablished.

## CMS modified BCS and QROM composition

[CMS ePrint 2019/834](https://eprint.iacr.org/2019/834.pdf) Section 8.2 uses
the exact chain

```text
m_j       = H(sigma_(j-1), encode_unique(j))
sigma_j   = H(m_j, rt_j)
m_(k+1)   = H(sigma_k, encode_unique(k+1)).
```

CMS Remark 8.2 says its chain differs from BCS16; the older chain needs a
stronger RBR variant.  Theorem 8.6 requires whole-IOP RBR and gives only the
asymptotic QROM soundness shape
`O(T^2*epsilon + T^3/2^lambda)` for an external attacker making at most
`T-O(q log ell)` oracle queries.

libiop's `bcs_common.tcc:551-595` instead absorbs each round root in sequence,
absorbs a hash of a concatenated field-message vector, and squeezes the next
messages.  `bcs_common.hpp:137` still has a TODO to make initial state depend on
the primary input.  There is no unique encoded round number, final `sigma`
proof element, or Hegemon network/version/relation/statement/action domain.

Consequently neither CMS route is open:

- the exact CMS modified chain is absent; and
- the stronger RBR needed for a different/original-style chain is absent.

At the paper level only, there is a conditional route: an implementation that
uses the exact Section 4.7 round graph and parameters satisfying every printed
Theorem 4.7/Lemma 4.15 premise has both perfect HVZK and the Section 5.2 RBR
state-function analysis.  Those are the right abstract premises to invoke CMS
Theorem 8.6 with CMS's modified chain and privacy-preserving salted
commitments.  This observation establishes no executable composition and no
number: exact syntactic checks, `p(x)`, query conversion, arity, constants, and
concrete SHAKE mapping still have to be instantiated.  It also excludes the
Section 5.3 optimized profile until its refined RBR proof exists.

The exact base-game arity, augmented-query conversion, IOP proof length,
random-oracle output, theorem constants, grinding/retry terms, and lifetime
union are all null.  A claim that “BCS is post-quantum” in the README does not
instantiate these premises.

For zero knowledge, [BCS ePrint 2016/116](https://eprint.iacr.org/2016/116.pdf)
Lemma 7.5 adds

```text
z' = z + p(x) * 2^(-lambda/4 + 2),
```

where `p(x)` is total IOP proof length in bits.  libiop does not determine the
canonical `p(x)` or a qualifying `lambda`, so this term cannot be evaluated.
Its BLAKE2b implementation is capped by RFC 7693's 64-byte output and therefore
cannot simply be dialed to an arbitrarily wide BCS zero-knowledge parameter.

## Proof bytes, serializer, and parser

There are no executable proof bytes to report.
`bcs_transformation_transcript::size_in_bytes()` at
`bcs_common.tcc:12-73` is the instrumentation expression

```text
field_bytes * (prover-message elements + query-response elements)
+ Merkle-root digest bytes
+ auxiliary/salt digest bytes
+ PoW digest bytes.
```

It is not the length of a byte serialization:

- `bcs_common.hpp:44-62` says query positions are carried in the transcript but
  deliberately omitted from the reported size.
- `bcs/README.md:23-25` says a standardized final-transcript serializer is a
  major missing feature.
- The only implemented serializer is ad hoc comma-separated text for a
  multiplicative field with an algebraic hash.  It is marked non-ZK, omits the
  PoW value, and omits membership-proof randomness salts
  (`bcs_common.tcc:93-205,309-357`).
- Serialization and deserialization for a binary field or non-algebraic hash
  print “not implemented” and return unchanged streams
  (`bcs_common.tcc:360-378`).  This includes the GF64/BLAKE2b Ligero test path.
- The only serializer round-trip test uses non-ZK `alt_bn128_Fr` and Poseidon
  (`tests/snark/test_serialization.cpp:38-95`).

The verifier consumes an already-populated C++ transcript object.  It indexes
root/query/response/proof vectors before enforcing exact container shapes
(`bcs_verifier.tcc:35-105`).  Merkle verification dereferences randomness and
auxiliary iterators before verifying their exact lengths
(`merkle_tree.tcc:338-482`).  This is not a canonical, bounded, fail-closed byte
parser and cannot be exposed to consensus input.

Therefore `proof_bytes`, its lower bound, and its upper bound are null.  No
paper communication expression or `size_in_bytes()` printout may replace a
serialized, independently parsed, retained proof.

## Conventional hash and consensus framing

The pinned code offers libsodium BLAKE2b, which is conventional, alongside
Poseidon.  It offers neither SHA-512 nor SHAKE.  More importantly, its BLAKE2b
input mapping is not canonical:

- `blake2b.tcc:138-152` hashes `sizeof(FieldT)` native object memory and carries
  a TODO about Montgomery/canonical representation.
- `blake2b.tcc:163-180` writes digest bytes directly into a field object and
  keys the hash with native `size_t` bytes.
- `blake2b.tcc:232-249` appends a native `size_t` squeeze index.
- `blake2b.cpp:50-73` derives a native `size_t` query position and reduces it
  modulo a power-of-two domain.
- `blake2b.tcc:11-18` initializes the chain with space bytes and explicitly
  leaves personalization as a TODO.

Those choices are platform/representation dependent and do not bind Hegemon's
parser, statement, action, network, version, domains, relation, or ciphertext
surface.  Replacing the function name with SHA-512 or SHAKE would not repair
the missing grammar or CMS chain.

## Dependency and maintenance inventory

The direct libiop stack is C++14, libsodium, libff, libfqfft, and Boost.
The checked-in build surface unconditionally includes `ate-pairing`/`xbyak`
and builds `zm`; libiop also compiles Poseidon and includes alt_bn128/Edwards
test and benchmark targets.  A selectively configured BLAKE2b protocol may not
execute ECC, but the repository/build dependency closure violates Hegemon's
self-contained Rust/no-ECC/no-Poseidon production boundary.

Other available sources do not close the gap:

| Source | Pin/license | Bounded verdict |
| --- | --- | --- |
| [ligeroinc/ligero-prover](https://github.com/ligeroinc/ligero-prover/tree/a40868f6045ddf27a488f65498a9f17832c1cda0) | `a40868f...`, v1.7.0, Apache-2.0, active 2026-08-04 | Maintained, but uses a BN254 field, SHA-256 staging, protobuf/gzip, incompletely enforced metadata, and no exact 2022/QROM/Hegemon refinement or self-contained Rust verifier |
| [NP-Eng/ligero](https://github.com/NP-Eng/ligero/tree/472e7e1af85f9db0bcb44557112ff9d549490ad6) | `472e7e1...`, MIT OR Apache-2.0, last observed 2024-10-28 | Rust demo referencing the 2022 paper, but README explicitly says non-ZK/not production; parameter and Fiat-Shamir TODOs remain and there is no wire |
| [ligeroinc/NFLlib](https://github.com/ligeroinc/NFLlib/tree/4b0bfcca68e999546020538771d0fcc42017a209) | `4b0bfcca...`, GPL-3.0, 2021-04-21 | NTT/field library used by the paper's reported implementation, not a published protocol implementation |

The 2022 paper reports NFLlib, a 30-bit prime field, and SHA-256 experiments,
but does not pin public protocol source.  Those measurements are not an
implementation source or Hegemon proof artifact.

## Self-contained Rust implementation map

The least theorem-risk route is a clean-room implementation of the exact 2022
Section 4.7 protocol.  The frozen R1CS verifier must first be compiled into the
paper's arithmetic-circuit relation, with a checked refinement from the
Hegemon assignment and public/context bytes to circuit wires.  Directly porting
Aurora Appendix B's R1CS adapter repeats the missing whole-protocol simulator
and RBR problem and is not a backup when Aurora's RBR gate has failed.

| Module | Required responsibility | Admission evidence |
| --- | --- | --- |
| `field.rs` | canonical fixed-endian field arithmetic and rejection sampling | independent KATs; reject noncanonical elements |
| `relation.rs` | stream frozen sparse R1CS; exact public/private/context grammar and source digests | frozen manifest/certificate plus mutation corpus |
| `circuit_adapter.rs` | compile R1CS satisfaction to Section 4.7 arithmetic-circuit wires | executable equivalence certificate and no host predicates |
| `parameters.rs` | fixed theorem-safe `n,m,ell,k,t,e,sigma` with exact rational checks | every printed premise true; optimized profile disabled absent RBR |
| `reed_solomon.rs` | deterministic RS encoding/domains | independent vectors and boundary tests |
| `iop.rs` | exact four-oracle, blinding, challenge, query, and verification schedule | paper-step transcript vectors |
| `simulator.rs` | Lemma 4.15 simulator and malicious-verifier view wrapper | distribution/refinement tests for every query schedule |
| `merkle.rs` | salted hiding commitments and canonical fixed-shape multiproofs | strict-count parser/mutations and hiding/binding ledger |
| `transcript.rs` | exact CMS modified chain and Hegemon domain binding with SHAKE | transcript KATs, unique round encodings, no ambiguous concatenation |
| `wire.rs` | one self-contained fixed-endian bounded proof | exact consume, derived counts, trailing-byte rejection |
| `prover.rs` / `verifier.rs` | explicit CSPRNG, zeroization, fail-closed fixed profile | same-artifact proof/verify/mutation/restart tests |
| `security.rs` | PCS/IOP/RBR/BCS/CMS/hash/grinding/RNG/retry/union ledger | concrete composed advantage strictly below `2^-128` |
| `refinement/` | Lean/Rust relation, bytes, transcript, sampler, and acceptance equivalence | formal gate plus native mutation corpus |

The permitted dependency target is the smallest audited Rust surface for
`sha2`, `sha3`, `rand_core`, and `zeroize`; everything else should be local.
C++, libsodium, libff/libfqfft, Boost, protobuf, gzip, ark-ec, ECC, pairings,
and Poseidon are excluded.  Target LoC is deliberately null: the only exact LoC
receipt is the 6,152-line pinned reference surface, and it implements the wrong
protocol.

## Exact missing-piece order

1. Freeze the repaired executable HX512 relation and its source/refinement
   certificate.  Until then, field and geometry remain null.
2. Choose and freeze the theorem-safe Section 4.7 parameter profile.  Do not
   use the Section 5.3 optimized profile until its whole-protocol RBR state
   function is proved.
3. Implement and refine the R1CS-to-arithmetic-circuit adapter.
4. Implement the exact IOP and explicit simulator; validate opened-view
   independence for the actual query bound.
5. Prove whole-protocol RBR for the exact implemented round graph.
6. Implement salted commitments, CMS's exact modified chain, SHAKE framing,
   and the canonical bounded wire.
7. Instantiate every PCS/IOP/Fiat-Shamir/QROM/hash/grinding/RNG/retry/union
   term and the BCS `p(x)` zero-knowledge loss.
8. Generate a retained full-relation proof, count the canonical bytes, and
   independently verify mutations, fresh processes, restart, reorg, and fresh
   node lifecycle.
9. Complete Rust/Lean refinement and release manifest.  Production remains
   disabled until all gates pass together.

## Reproduction

No heavy build is required:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/ligero-implementation-audit/ligero_implementation_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/ligero-implementation-audit/check_audit.py --require-local-source --require-local-pdfs
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/ligero-implementation-audit -p 'test_*.py' -v
```

The generated ledger is canonical JSON.  Its checker rejects any attempted
promotion of theorem inheritance, complete ZK, CMS/QROM applicability,
relation geometry, proof bytes, security bits, or authority.
