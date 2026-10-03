# Post-quantum architecture challenger screen

**Status:** bounded source-only tournament; fail closed.  **Winner:** `null`.
**Production authorized:** `false`.

This report adversarially screens transparent, no-ECC, no-pairing, no-RSA
proof routes against the current M4 + one-level Ligerito research route.  It
does not promote a weak profile, a component benchmark, or an approximate
paper number into a Hegemon proof measurement.

The one concrete route that is nominally plausibly smaller is the newly implemented
`Dachshundv2 -> LaBRADOS -> LNP-Lite -> LaBRADOR` Pack in LaZer.  Its paper
reports proofs of **around 110 KB with zero knowledge** across the implemented
case studies.  That headline is nominally below the replacement Ligerito/E384
screen's exact fixed maximum-frontier grammars of `136,048` bytes at
`q=64/source-128` and `208,400` bytes at `q=132/source-264`.  The comparison is
not same-relation or same-security: LaZer's number is approximate and passes
the statement separately, while both Ligerito numbers are non-ZK opening-core
serializer results, not production-proof measurements or lower bounds.
Variable authentication multiproofs could also change the Ligerito wire.

LaZer is therefore a **bounded size challenger, not a winner**.  It fails the exact
relation, canonical parser, retained artifact, and composed-QROM gates.  It
also fails the numerical security gate unchanged: LNP-Lite's stated
knowledge-soundness error contains `5 / 2^128` before the other terms, already
only about `125.68` bits, and Appendix C makes the Fiat--Shamir argument only
heuristic in the classical ROM with a further multiplicative random-oracle
query loss.  The official LaBRADOR source additionally chains transcript state
through a 16-byte SHAKE128 state.  The best-fitting published multi-round
measure-and-reprogram theorem cannot manufacture the missing quantum
interactive PoK premise, and its concrete query loss makes the current base
errors and 128-bit challenge range categorically insufficient.  No such
profile can establish Hegemon's strict `>128`-bit post-quantum/QROM target.

HVZK-WHIR is the stronger theorem-level complete-ZK topology.  Its proved
straightline extractor is weaker than the knowledge premise in the available
QROM compiler, however, and Plonky3 implements only its hiding PCS rather than
the paper's R1CS reduction.  It therefore supplies neither a second winner nor
a valid proof-byte comparison.

## Scope and admission boundary

The governing repository documents and ExecPlan were read before this screen:
`AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`, `.agent/PLANS.md`, and
`.agent/SMALLWOOD_SHAKE256_PRODUCTION_EXECPLAN.md`.  No dependency was
imported, no Cargo/Lake/proof build was run, and no proof was generated.  The
disk gate was closed at roughly 17 GiB free, below the 28 GiB heavy-build
threshold.

The current M4 figures are not a frozen production relation.  They are
source-static, pre-DCE hash ledgers:

| diagnostic source | native-word AND | linear | BMUL | minimum scalar Boolean ANDs |
| --- | ---: | ---: | ---: | ---: |
| mixed BLAKE2b-448/SHAKE | 79,128 | 265,963 | 452 | 5,064,192 |
| split SHA3-512/SHAKE | 90,600 | 327,437 | 444 | 5,798,400 |

The last column is the exact expansion `64 * native-word AND`; it still omits
the exact full non-hash 2-input/2-output relation, compiler padding, and any ZK
wrapper.  It is a workload floor, not a constraint-system mapping.

The retained Ligerito comparators are also screens, not proof baselines:

| retained screen | exact bytes | authority boundary |
| --- | ---: | --- |
| executable E384, q64/source-128, 2-MiB oracle | 136,048 | fixed maximum-frontier serializer; 15/15 tests and source checker pass; non-ZK, optimistic source equation only |
| executable E384, q132/source-264, 2-MiB oracle | 208,400 | fixed maximum-frontier serializer; 15/15 tests and source checker pass; non-ZK, source-only conservative convention |
| n16, q38, 64-GiB encoded oracle | 144,496 | non-ZK model; no exact full relation, parser, or composition |
| n16, q61, 512-MiB encoded oracle | 168,688 | non-ZK model; same omissions |
| rate 1/16, E256 x2, salted first level | 117,088 | architecture budget; leaves only 6,980 bytes for all later rounds, ZK, and framing |
| rate 1/32, E256 x2, salted first level | 99,328 | architecture budget; leaves only 24,740 bytes for all later rounds, ZK, and framing |

The replacement E384 implementation and exact ledger are retained under
`.agent/hardening/ligerito-e384-core`; independent execution is recorded in the
root ExecPlan.  The old source-structure hiding floor raises the two modeled
n16 rows to at least `148,336` and `174,736` bytes respectively, but neither
number is a complete-ZK estimate.  For the replacement fixed grammars, the
VEIL audit's direct-structure floor would instead yield `142,384` and
`221,264` bytes before the dominant missing relation/simulator wrapper.  None
of these is an architecture lower bound.

## Nominal size challenger: succinct LaZer Pack

### Pinned primary and official sources

- Paper: Biasioli et al., [A Toolkit for Succinct Lattice-Based Zero
  Knowledge Proofs](https://eprint.iacr.org/2026/1289), ePrint 2026/1289,
  received 19 June 2026.
- Official implementation: [lazer-crypto/lazer](https://github.com/lazer-crypto/lazer).
  The current official README directs reproduction of this paper to commit
  [`59a52f74ca39584edf77b4b8b7437dbd48f9ad94`](https://github.com/lazer-crypto/lazer/tree/59a52f74ca39584edf77b4b8b7437dbd48f9ad94).
  That paper reproduction pin, not a moving branch, is the audit anchor.
- The pinned tree records its official `labrados` submodule at
  [`3f95485139ffaa65fe572da809b90772901372e5`](https://github.com/lazer-crypto/labrador/tree/3f95485139ffaa65fe572da809b90772901372e5).

No source was built.  The official LaZer README requires Linux x86-64,
AVX-512/AES, GCC, SageMath, Python/CFFI, and recursive submodules; those are
outside this bounded source-only screen and the closed disk gate.

### Relation language and assumptions

The Pack is not an R1CS/Boolean-circuit backend.  Its native relation is over
cyclotomic rings `R = Z[X]/(X^d + 1)` and `Rq`, principally degree `d=256` in
the proof system; the case studies use degree 512 objects translated into the
degree-256 proof ring.  LaBRADOR proves knowledge of short polynomial witness
vectors satisfying global/individual norm bounds and full-ring or
constant-term dot-product quadratic constraints.  Dachshundv2 adds binary
constraints, exact or approximate norm constraints, and arbitrary quadratics
between witness vectors, aggregating the latter with polynomial challenges.

Security relies on concrete M-SIS binding and M-LWE/Extended-M-LWE hiding,
plus rejection sampling, projection bounds, challenge-space properties, and
the ROM.  The implemented parameter derivation also uses a normal-distribution
heuristic for projection rows in Appendix D.  This is a very different
arithmetization and assumption surface from M4 + Ligerito.

### Zero knowledge: real generic claim, absent Hegemon refinement

This is not mere witness obfuscation.  Section 3.5 gives a simulator for the
composed interactive Pack: pre-LNP-Lite LaBRADOS messages are simulated as
commitments to zero using hiding outer commitments; LNP-Lite's last message is
simulated; and the remaining LaBRADOS/LaBRADOR transcript is computed from the
simulated output.  The implementation exposes a `zk` flag selecting the
LNP-Lite layer.  Under its lattice assumptions, this is substantive
protocol-level ZK evidence.

It is not yet Hegemon-complete ZK.  There is no compiled Hegemon observation
surface, no simulator for Hegemon's exact parser/statement/abort/retry paths,
no leakage/refinement result for the native implementation, and no retained
mutation/restart artifact.  Appendix C asserts that non-interactive ZK follows
from HVZK, but gives only a heuristic classical-ROM soundness composition.

### The “quantum-safe” lineage does not close Fiat--Shamir

The foundational Bootle--Lyubashevsky--Nguyen--Seiler paper,
[A Non-PCP Approach to Succinct Quantum-Safe Zero-Knowledge](https://iacr.org/archive/crypto2020/12171046/12171046.pdf)
(CRYPTO 2020), does **not** prove a QROM NIZK.  Its introduction says exactly
that the interactive schemes are Fiat--Shamir transformed but that security is
proved in the ROM rather than the QROM.  Definition 2.5 quantifies over a PPT
malicious prover and an expected-polynomial-time extractor; Theorem 3.3 builds
a classical transcript tree using heavy-row extraction and rewinding.  Its
“potentially post-quantum” conclusion comes from lattice assumptions, not a
non-interactive QROM knowledge-soundness theorem.

The descendant stack does not repair that boundary:

- the original LaBRADOR theorem is for the interactive protocol;
- the later [complete non-interactive LaBRADOR analysis](https://eprint.iacr.org/2024/311)
  defines Fiat--Shamir in the classical ROM, quantifies classical PPT provers,
  and rewinds/reprograms a classical random-oracle table;
- Dachshundv2 is a relation frontend, LaBRADOS supplies ordinary Ajtai outer
  commitments and predicate-special-sound compression, and LNP-Lite supplies
  interactive ZK; and
- the 2026 Pack paper's Appendix C (PDF pages 27--28) deliberately says the
  non-interactive composition “should follow” and is considered secure only
  heuristically.

No cited layer proves a collapsing commitment, a
quantum-computationally-unique response relation, a quantum interactive PoK,
or an exact quantum extractor for the parameter-dependent Pack transcript.
Those properties therefore cannot be inherited merely because the underlying
binding and hiding assumptions are lattice based.

### Security failure under the Hegemon gate

The relevant paper terms are explicit:

- LaBRADOS: `2^-128 + q^-lambda + q^(-d/2) + 2/|C|`;
- LNP-Lite Theorem 2 in Section 3.3 (PDF page 10):
  `5 * 2^-128 + q^-lambda + q^(-d/2) + 2/|C|`, where Appendix B.2 shows that
  the coefficient five is one subprotocol term plus a union bound over four
  projection failures; and
- Fiat--Shamir then incurs a multiplicative loss based on the adversary's
  number of random-oracle queries.

Thus `5 * 2^-128` alone is larger than `2^-128`; it has
`128 - log2(5) ~= 125.68` bits.  Adding the remaining positive terms and the
ROM query loss can only reduce security.  There is no PCS/IOP/Fiat--Shamir/hash/
grinding/union ledger proving `>128` bits in the QROM.

The official pinned LaBRADOR
[`proofsystem.c`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.c#L88-L93)
makes the concrete hash boundary worse.  Its `update_hash_polz` function uses
`shake128` to update a **16-byte** transcript state; challenge samplers retain
that same 16-byte state.  SHAKE is an allowed conventional hash family, but the
retained challenge range is at most `2^128`; it cannot make any strict
`>128`-bit error claim, and [Grover search](https://arxiv.org/abs/quant-ph/9605043)
puts generic preimage search on a 128-bit target at only a 64-bit work-factor
ceiling.  The paper's separate proof-friendly
lattice hash is explicitly presented as a candidate without cryptanalysis and
is forbidden as Hegemon validity authority.

### Published QROM transforms: topology is not a certificate

[Measure-and-Reprogram 2.0](https://eprint.iacr.org/2020/282.pdf), Corollary
13, is the closest generic theorem for a constant-round `(2n+1)`-message
public-coin protocol under its duplicate-free, round-indexed hash schedule.  If
`q_H` is the quantum random-oracle query count, its exact reduction is

```text
P_int >= n! / (2*q_H + n + 1)^(2*n) * P_FS - epsilon,
sum(epsilon) = n! / |C|.
```

Equivalently, the resulting Fiat--Shamir error is bounded by

```text
P_FS <= ((2*q_H+n+1)^(2*n) / n!) * P_int
      + (2*q_H+n+1)^(2*n) / |C|.
```

At Hegemon's global low-advantage budget `q_H=2^64`, even the unrealistically
favorable `n=1` multiplier is `(2^65+2)^2 > 2^130`.  A bare `2^-lambda` term
therefore needs integer `lambda >= 259`; the Pack's coefficient-five term
needs `lambda >= 261`.  Combining the Pack's `2/|C|` with Corollary 13's
`1/|C|` needs `log2(|C|) >= 260`, before margin for every other positive term.
The Pack's `125.68`-bit base term and 128-bit concrete transcript fail this
screen before the actual, larger and parameter-dependent challenge-round
count is known.

Corollary 15 does not create quantum knowledge soundness: it transfers
soundness or knowledge extraction only when the interactive protocol already
has the corresponding quantum soundness or quantum-PoK property.  Plain
measure-and-reprogram soundness does not require unique responses, collapsing,
or oblivious commitments, so their absence is not being used as a spurious
premise here.  They become relevant to the alternative extraction routes:

- [DFMS19](https://www.iacr.org/archive/crypto2019/116940247/116940247.pdf)
  derives quantum PoK from special soundness only with a
  quantum-computationally-unique/collapsing response relation.  Ordinary Ajtai
  commitment binding and the Pack's classical predicate-special-sound
  argument do not establish that premise.
- [Unruh's QROM Fiat--Shamir analysis](https://eprint.iacr.org/2017/398.pdf)
  gives QROM ZK for a three-message Sigma protocol under completeness, HVZK,
  and unpredictable commitments.  The Pack has no exact collision-entropy
  proof for its first message and no QROM simulator for its multi-round
  abort/retry behavior.
- [Unruh's transform](https://eprint.iacr.org/2014/587.pdf) covers three-move
  Sigma protocols by repeating commitments, committing to the response for
  every challenge, and opening selected responses; its later extension is a
  specialized five-round binary-challenge case.  The Pack has
  parameter-dependent rounds and large challenge spaces, so this is not a
  source-applicable transform and no finite proof-byte price follows.
- [Katsumata's semi-generic lattice compiler](https://eprint.iacr.org/2021/927.pdf)
  requires a covered linear-response form and adds an extractable
  linear-homomorphic commitment.  Its reported `2.6x` Bootle-five-round and
  `51.8x` extended-Unruh examples are different protocols, not valid Pack size
  factors.
- [Rotem--Tessaro](https://eprint.iacr.org/2024/1724.pdf) commits to a full
  multi-round transcript tree and opens a selected path, under a generalized
  special-soundness premise and exact tree degrees.  Neither premise nor the
  resulting tree geometry is proved for the Pack.

For sensitivity only, if one incorrectly treated the Pack as `n=1` and also
assumed independent direct-product repetition of its full `5*2^-128` error,
three approximately 110-KB copies would be the first count that could clear
the best-case 130-bit loss: nominally about 330 KB.  This is **not** an admitted
floor or construction: no direct-product theorem is supplied, the true Pack
has more challenge rounds, and 110 KB is not an exact serialized measurement.

### No supported strict-security parameterization

The paper reproduction pin does not expose a reviewed 192- or 256-bit Pack
profile.  Its LaBRADOS submodule is pinned to
[`3f95485139ffaa65fe572da809b90772901372e5`](https://github.com/lazer-crypto/lazer/tree/59a52f74ca39584edf77b4b8b7437dbd48f9ad94/src),
where the source fixes
[`PS_CHALBITS` to 128](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.h#L10-L14),
stores every statement transcript in
[`uint8_t h[16]`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.h#L37-L49),
and gives every sampler that same 16-byte type.  The implementation then calls
[`shake128` and copies only 16 bytes back](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.c#L88-L93)
throughout the transcript and challenge samplers.

The Pack parameter generator's complete public input is
[`(statement, zk, iwtbits)`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/pack.c#L27-L46).
It returns a round-dependent `pibits` estimate, but accepts no security level,
QROM query budget, transcript primitive, or transcript width.  Changing the
macro, every `h[16]` ABI, the XOF, projection failure targets, challenge
spaces, lattice hardness parameters, and round optimizer would therefore be a
new protocol/profile implementation requiring a fresh proof and review, not a
supported configuration switch.

Merely widening the untransmitted Fiat--Shamir state would not yield a sound
byte delta.  Clearing the base errors and QROM reduction also changes
commitments, responses, projection dimensions, challenges, and potentially
the number of Pack rounds.  Because the source has no such profile and hence no
canonical serializer/measurement for one, its strict-profile proof bytes
remain `unknown`;
the approximate 110-KB headline cannot be carried over.

### Proof-byte and parser boundary

The paper says proof size remains approximately constant across its PRG,
compression, membership, and blind-signature cases because the final
LaBRADOR round dominates: around `100 KB` without ZK and around `110 KB` with
ZK.  The extra approximately `10 KB` is attributed to LNP-Lite commitments and
post-LNP-Lite LaBRADOS rounds.

The estimate therefore includes those protocol commitments/messages, and the
paper/security code uses the 128-bit failure targets and `PS_CHALBITS=128`
audited above.  Those are not strict-QROM parameters or exact serialized byte
measurements.  The official pinned
[`benchmark_expansion.py`](https://github.com/lazer-crypto/lazer/blob/59a52f74ca39584edf77b4b8b7437dbd48f9ad94/python/succinct_zkp/benchmark_expansion.py#L51-L88)
reports prover/verifier time, not proof length.  It calls
`statement = PS.output_statement()`, then `proof = PS.pack_prove()`, and passes
the statement separately to `pack_verify`; the other official case-study
benchmarks follow the same Pack API.  No bounded canonical transaction
frame, version/domain grammar, reject-trailing-bytes parser, or byte-for-byte
wallet-to-consensus artifact is reported.  It is therefore unknown whether
the paper number charges every statement/parameter/framing byte relevant to a
self-contained Hegemon transaction.

### Deployment portability is a separate blocker

The official [LaZer README](https://github.com/lazer-crypto/lazer/tree/59a52f74ca39584edf77b4b8b7437dbd48f9ad94)
requires Linux amd64/x86-64, kernel 4.18 or newer, AVX-512 and AES instruction
extensions, GCC 13.2 or newer, SageMath 10.2 or newer, Python/CFFI, and
recursive submodules; it records testing only on Ubuntu 20.04 and RHEL 8.10.
The pinned [LaBRADOR repository](https://github.com/lazer-crypto/labrador/tree/3f95485139ffaa65fe572da809b90772901372e5)
also warns that it is research-purpose code without the security review,
testing, or validation required for production deployment.

Those are benchmark-implementation constraints, not a proof that the
mathematical protocol is intrinsically x86-only.  Hegemon nevertheless needs a
portable, constant-time verifier for every release target, byte-identical
cross-platform parsing and negative vectors, memory/resource caps, and a
native-verifier/refinement proof.  No such rewrite exists.  Its cost and proof
bytes cannot be counted as implemented, and the benchmark code cannot be
linked into consensus as-is.

### Why no sound same-relation projection exists yet

At minimum, the mixed candidate contains 5,064,192 scalar Boolean AND
equations and the split candidate 5,798,400, before full non-hash logic.  A
naive claim that each degree-256 ring element carries 256 independent Boolean
constraints is unsound: ring multiplication is convolutional, Dachshundv2
aggregates quadratics with challenges, norm/no-wrap constraints depend on the
chosen modulus and witness grouping, and the current M4 linear/BMUL counts are
not a frozen full relation.  No primary theorem or official compiler maps M4's
native-word gates to the Pack's short-vector/norm/quadratic relation while
preserving extraction and ZK.

Consequently the only honest numeric statement is:

```text
mixed Boolean-core floor = 79,128 * 64 = 5,064,192 AND equations
split Boolean-core floor = 90,600 * 64 = 5,798,400 AND equations
LaZer same-relation proof bytes = unknown
LaZer same-relation prover memory/time = unknown
```

This keeps LaZer alive as a challenger but disqualifies it as a winner.

## Other challenger results

### STIR

[STIR](https://eprint.iacr.org/2024/390) is an IOPP/PCS component, not a full
ZK argument.  The retained source-only Hegemon screen pins the authors'
[reference source at commit
51064ebd45667dae3b499539f4476ba6d8527610](https://github.com/WizardOfMenlo/stir/tree/51064ebd45667dae3b499539f4476ba6d8527610).
For the specific two-branch B128/E256 transport it prices, the smallest strict
canonical transcript is 403,392 bytes, and even deleting every authentication
node leaves a 128,456-byte floor.  Those are local transport-model results,
not a universal STIR lower bound.  STIR's published multiplicative-domain
theorem does not instantiate over the proposed characteristic-two additive
domain, and neither the paper nor source supplies complete ZK, the mixed-field
extraction theorem, or a composed QROM certificate.  **Eliminated at theorem,
ZK, and size gates for the retained seam.**

### WHIR and HVZK-WHIR

Base [WHIR](https://eprint.iacr.org/2024/1586) is an efficient non-ZK
IOPP/PCS.  At 128-bit target security its paper reports 56--87 KiB arguments at
rate `1/16` for degrees `2^18` through `2^28`; those are PCS/IOPP arguments,
not full relation proofs.  The official [worldfnd/whir](https://github.com/worldfnd/whir)
README calls the implementation an academic prototype, defaults to 100-bit
security/conjectured list soundness, and warns that it is not production-ready.

Chiesa--Fenzi--Weissenberg's [Zero-Knowledge IOPPs for Constrained
Interleaved Codes](https://eprint.iacr.org/2026/391) is the strongest retained
complete-ZK theorem topology.  Definition 3.7 (PDF page 27) gives a
witness-propagating round-by-round knowledge notion; Theorem 4.5 (pages
32--34) composes its error vectors and HVZK; Theorem 10.2 (pages 62--65) gives
the complete HVZK constrained-code IOPP; and Theorem 11.3 (page 66 onward)
gives the R1CS-to-constrained-code IOR.  Remark 4.3 (page 32) says that, when
the target is a trivial relation and the IOR is an IOP, its HVZK definition
coincides with standard IOP HVZK.  The advertised `1 + o(1)` is IOP oracle
communication overhead, not a serialized R1CS proof-size theorem.

The straightline claim does not automatically meet the knowledge premise of
the QROM compiler.  The definition comes from the authors' earlier
[State-Restoration Knowledge Soundness for IOPs](https://eprint.iacr.org/2025/753).
Its Section 2.8 and Figure 1 (PDF pages 19--22) explicitly call the new notion
a weakening of the prior/CMS round-by-round-knowledge definition and say that
the arbitrary-code protocols are not known to satisfy the prior definition
without an efficient error-tolerant decoder.  Appendix C, Theorem C.1 proves
only prior/CMS knowledge implies the new variant, not the converse.  Appendix
B, Theorem B.4 instead derives classical straightline state-restoration
knowledge from the relaxed variant.  Consequently the 2026/391 extractor does
**not** establish clause 2 of [CMS19 Theorem
8.6](https://eprint.iacr.org/2019/834.pdf), a QROM argument of knowledge, for
the composed construction as published.

That distinction is not itself fatal to consensus validity.  Consensus needs
QROM soundness and zero knowledge; it does not intrinsically require an
extractable argument of knowledge.  The relaxed definition implies
round-by-round soundness.  Therefore CMS19 Theorem 8.6 clause 1 can
potentially compile the final public-coin IOP to QROM soundness, and standard
IOP HVZK can feed clause 3 for statistical zero knowledge, provided Hegemon
uses CMS's modified BCS hash chain and supplies the exact scalar base-error,
hash, query, grinding, and union accounting.  This is a potentially sufficient
abstract NIZK route, distinct from the missing clause-2 AoK.  The paper does
not instantiate that concrete composition or prove a stronger CMS-style
extractor for the full R1CS/HVZK construction.

The R1CS reduction also does not directly accept the retained M4 relation.
Theorem 11.3 works over a finite field and its complete-ZK conclusion requires
`char(F) != 2`; M4's `B128` relation has characteristic two.  A self-contained
route is possible in principle by compiling bits into an odd-characteristic
R1CS, constraining bitness, using multiplication constraints for AND, and
encoding XOR as `x + y - 2xy`.  It needs no validity sidecar: the Section 11
IOR and Section 10 IOPP can reside in the same BCS proof.  But it is a new
semantics-preserving compiler.  The retained `79,128`/`90,600` native-word
AND counts map only to `5,064,192`/`5,798,400` scalar AND equations; they omit
the now-nonlinear XORs, bitness, wiring, exact 83-call schedule integration,
and full non-hash relation.  A characteristic-two instantiation would retain
cheap XOR but would not satisfy the paper's complete-ZK premise.  No sound
same-relation constraint count follows from the current ledger.

The official implementation is narrower still.  Plonky3 main was pinned for
this screen at
[`3c84c158c0939345a3becba60a387643935593d2`](https://github.com/Plonky3/Plonky3/tree/3c84c158c0939345a3becba60a387643935593d2).
Its completed [implementation tracker](https://github.com/Plonky3/Plonky3/issues/1590)
and merged [HVZK-WHIR PCS pull request](https://github.com/Plonky3/Plonky3/pull/1767)
explicitly leave the paper's Section 11 R1CS reduction out of scope: Plonky3
is AIR-only.  The merged component is a generic `HidingWhirPcs`, not a full
R1CS SNARK.  Its MMCS and challenger are generic; its serde proof is not a
bounded canonical consensus grammar; no conventional SHA-512/SHAKE strict-
QROM profile, exact Hegemon statement binding, or native-verifier refinement
is supplied.  The pinned README also warns that malformed proofs can panic
and downstream consumers should catch the panic, which is a fail-closed
parser/verifier blocker.

The pull request reports only a weak component benchmark: KoalaBear,
100-bit target security, `k=4`, and PCS inputs `2^16`/`2^18`, with
`1.29x`/`1.19x` proving-time overhead, `3.28x`/`3.04x` proof-size overhead,
and approximately 120 KB fixed mask-opening overhead.  It publishes no exact
absolute proof bytes.  These are PCS-only results, so the 120-KB figure is
neither a full-proof measurement nor a lower bound and must not be converted
into paper-PCS transaction bytes.  It nevertheless makes a sub-136,048-byte
strict full-Hegemon proof implausible for this implementation absent a
materially different measured profile.

**Retain HVZK-WHIR as the top theorem-level complete-ZK challenger, but not as
a winner.  Exact odd-field Hegemon R1CS size, strict composed-QROM parameters,
canonical proof bytes, prover resources, parser, and refinement are all
unknown.**

### Brakedown

[Brakedown](https://eprint.iacr.org/2021/1043) combines a linear-time code PCS
with Spartan, but the implemented inner argument is not zero knowledge.
The primary [Scorpius repair paper](https://eprint.iacr.org/2024/1164)
confirms that obtaining ZK requires an outer recursive ZK SNARK.  That violates
this screen's self-contained/no-sidecar requirement unless a complete outer
route, parser, bytes, and QROM composition are supplied; none is implemented
for this relation.  **Eliminated at complete-ZK and same-relation gates.**

### Orion / Scorpius

The original [Orion](https://eprint.iacr.org/2022/1010) soundness analysis is
broken.  The [Scorpius repair](https://eprint.iacr.org/2024/1164) notes that
Orion's `t=1568` yields only about 14 bits for the relevant linear-combination
check and that `t=9635` would have been required for 128 bits; it sets
`t=4795` for a separate distance bound in the repaired construction.  The
repair still needs an outer complete knowledge-sound ZK CP-SNARK.  No strict
same-relation implementation or byte artifact is retained.  **Eliminated at
soundness, outer-ZK, and measurement gates.**

### Ligero, Longfellow, BooLigero, and Ligero++

The full [Ligero](https://eprint.iacr.org/2022/1608) paper gives a public-coin
ZK argument from collision-resistant hashes and a non-interactive version via
Fiat--Shamir in the classical ROM.  Its published security is not a composed
concrete QROM `>128` result for Hegemon, and no exact Hegemon relation/parser/
bytes exist.

Google's official [Longfellow ZK specification](https://google.github.io/longfellow-zk/spec/draft-google-cfrg-libzk-01.html)
is the strongest implementation/parser evidence in this family: it specifies
full circuit ZK, public-input binding, field/proof serialization, and a
canonical proof structure.  Its opinionated profile, however, uses SHA-256 for
both Fiat--Shamir and Merkle commitments.  The
[BHT collision algorithm](https://arxiv.org/abs/quant-ph/9705002) puts SHA-256
at only about 85 bits of generic quantum collision resistance, so the profile
cannot meet a strict PQ128 binding gate.  It also has no compiled Hegemon
relation or measured same-relation artifact.  **Eliminated at hash/QROM and
same-relation gates.**

[BooLigero](https://eprint.iacr.org/2021/121) provides perfect HVZK for its
interactive protocol and classical-ROM Fiat--Shamir.  For `w=64`, its exact
Test-And construction has `w0=8`, `w1=8` and adds
`3*N*w1 + 3*(w1+1)*kappa = 24N + 3456` hidden `GF(2^64)` elements at
`kappa=128`:

| core | hidden elements | raw unencoded bytes |
| --- | ---: | ---: |
| mixed, N=79,128 | 1,902,528 | 15,220,224 |
| split, N=90,600 | 2,177,856 | 17,422,848 |

This is a prover/oracle resource floor, not a proof-byte floor, because the
elements are code-encoded and selectively opened.  The protocol additionally
uses two committed oracles, and the paper reports a SciPy parameter optimizer
rather than a production proof/parser artifact.  **Not ruled out by proof
bytes alone, but eliminated at implementation, same-relation, and QROM gates.**

[Ligero++](https://doi.org/10.1145/3372297.3417893) is a transparent
sublinear ZK IOP; the primary publication reports an implementation and
benchmarks.  No author-linked maintained implementation, canonical parser,
strict QROM composition, or Hegemon same-relation artifact was available in
this bounded screen.  Historical benchmark claims therefore cannot be
recomputed or compared.  **Eliminated at reproducibility, QROM, parser, and
same-relation gates.**

### VOLE-in-the-head

The primary [VOLE-in-the-head paper](https://eprint.iacr.org/2023/996) gives a
strong size warning, not a same-relation lower bound.  Its Table 1 reports an
**average** 16 bits per Boolean AND at soundness error at most `2^-128` for one
`2^20`-gate circuit.  A direct extrapolation of that published reference rate
to the raw hash core gives:

| core | scalar Boolean ANDs | 16-bit-rate projection |
| --- | ---: | ---: |
| mixed | 5,064,192 | 10,128,384 bytes |
| split | 5,798,400 | 11,596,800 bytes |

The table's rate includes protocol overhead amortized at `2^20`, so applying
it at a different circuit size is not a theorem-backed floor.  The projections
also omit every linear/BMUL/non-hash constraint, exact Boolean compiler,
statement, parser, and framing byte.  They make this route uncompetitive by
roughly two orders of magnitude, but the formal rejection is at the absent
same-relation artifact, canonical parser, and composed-QROM gates—not an
invented size lower bound.

### Lattice routes other than the Pack

- Base [LaBRADOR](https://eprint.iacr.org/2022/1341) reports approximately
  58 KB for a `2^20`-constraint R1CS at 128-bit target, but it is explicitly
  not zero knowledge.  The Pack is the concrete ZK successor and is audited
  above.
- [LatticeFold+](https://eprint.iacr.org/2025/247) and
  [Neo](https://eprint.iacr.org/2025/294) are folding schemes, not standalone
  transaction NIZKs.  The official
  [Nethermind implementation](https://github.com/NethermindEth/latticefold)
  is a proof of concept, says LatticeFold+ remains work in progress, and warns
  it is not production-ready.  A final SNARK, complete ZK, parser, and bytes
  are still required.
- [Lantern's implementation paper](https://eprint.iacr.org/2024/457) and
  [official tutorial](https://lattice-zk.isec.tugraz.at/) report compact proofs
  for native lattice statements (for example about 29 KB for knowledge of an
  MLWE secret), not a generic full Boolean Hegemon transaction relation.

None supplies a smaller implemented self-contained complete-ZK Hegemon proof.

### Flock

The retained [Flock](https://eprint.iacr.org/2026/1329) route is not a ZK
candidate: the paper targets 100-bit soundness and succinctness, not zero
knowledge.  Its official [source](https://github.com/succinctlabs/flock)
implements R1CS over `GF(2^128)` with Ligerito and fixed hash workloads, but
does not close those gates.  The official
[Flock BLAKE3 benchmark](https://github.com/Layr-Labs/flock-challenge)
measures a largest accepted 436,107-byte proof for `2^18` BLAKE3 compression
functions.  That is a real parser/verification artifact, but it is non-ZK,
weak-profile, and not the full Hegemon relation.  **Eliminated at ZK,
strict-security, relation, and size gates.**

## Tournament ledger

| route | theorem | implementation | complete ZK | strict composed QROM >128 | conventional-hash authority | canonical Hegemon parser | same-relation measured bytes | decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LaZer Pack | classical-ROM lattice PoK + interactive protocol ZK | yes, paper pin; narrow x86-64 research target | generic claim yes; Hegemon no | **no** | conventional SHAKE, but 128-bit retained state is too narrow; candidate lattice hash forbidden | no | no; ~110 KB cross-use-case only | **nominal size challenger, disqualified** |
| STIR | IOPP/PCS | academic prototype | no | no composed result | configurable conventional hash | no | no; local seam floor 128,456 B | reject |
| WHIR | IOPP/PCS | academic prototype | base no | no full composition | SHA3/BLAKE3 source options | no | no; 56--87 KiB PCS only | reject |
| HVZK-WHIR | complete HVZK IOPP/R1CS theorem; relaxed RBR soundness | hiding PCS only; R1CS explicitly out of scope | theorem yes; exact Hegemon no | potentially CMS clause 1 + 3; no concrete ledger or clause-2 AoK | generic backend; target hash/profile absent | no | no; weak 100-bit PCS reports ~120 KB additive masking only | **top theorem challenger, disqualified** |
| Brakedown | R1CS SNARK | research | inner no | no | hash based | no | no | reject |
| Orion/Scorpius | repaired SNARK needs outer CP-SNARK | incomplete route | only with outer | no | hash based | no | no | reject |
| Ligero | public-coin ZK | paper implementation | yes | classical ROM only | collision-resistant hash | no | no | reject |
| Longfellow | circuit ZK | active official source/spec | yes | **no: SHA-256 collision ceiling** | SHA-256 | strong generic serialization, not Hegemon | no | reject |
| BooLigero | perfect HVZK | optimizer only | interactive yes | classical ROM only | generic hash | no | no | reject |
| Ligero++ | transparent ZK IOP | paper says implemented | yes | no exact composition | collision-resistant hash/ROM | no | no | reject |
| VOLE-in-head | public ZK | paper implementation | yes | no Hegemon composition | symmetric/hash | no | >10 MB direct rate projection, not a floor | reject |
| lattice folding | folding only | PoC/WIP | no final ZK | no final composition | lattice/RO | no | no final proof | reject |
| Lantern | native lattice ZK | Sage tutorial | native statements only | no Hegemon composition | lattice/RO | no | 29 KB basic MLWE only | reject |
| Flock | R1CS/PCS | yes | **no** | 100-bit target | SHA-256/FS in paper/source | benchmark parser only | 436,107 B wrong relation | reject |

## Exact decision and next falsifiable screen

`winner = null`.  No challenger satisfies all theorem, implementation,
complete-ZK, composed-QROM, conventional-hash, parser, exact-relation, and
measured-artifact gates.  The existing M4 + Ligerito route is not promoted by
default; it remains a non-ZK model with the same unresolved gates.

The first challenger deserving a future bounded implementation screen is
HVZK-WHIR, because it is the only retained topology with theorem-level
complete HVZK and a potentially sufficient CMS clause-1-soundness plus
clause-3-ZK route.  LaZer remains a nominal size lead only and must not consume
implementation budget until a source-applicable QROM theorem and widened
reviewed profile exist.  HVZK-WHIR admission would require all of the
following before any proof-size comparison:

1. freeze and independently check the exact full Hegemon 2x2 relation,
   including every non-hash, parser, mode, mask, ciphertext, balance,
   nullifier, Merkle, domain, version, and intent constraint;
2. implement and refine a Boolean-to-odd-field R1CS compiler that accounts for
   every bitness, AND, XOR, wiring, and public-input constraint and preserves
   the exact relation, including negative vectors;
3. implement the paper's Section 11 R1CS reduction and Section 10 IOPP as one
   self-contained BCS proof rather than treating the existing hiding PCS as a
   transaction proof;
4. pin a conventional SHA-512/SHAKE256-512 domain-separated profile and prove
   exact CMS clause-1 QROM soundness plus clause-3 statistical ZK strictly
   above 128 bits, including PCS/IOP/hash/query/grinding/union terms; require
   clause-2 knowledge extraction only if consensus semantics actually depend
   on extraction;
5. define a bounded canonical proof parser binding the exact Hegemon statement
   and rejecting noncanonical/trailing data;
6. implement a portable constant-time verifier, resource caps, byte-identical
   cross-target vectors, and native-verifier/refinement evidence; and
7. only then generate, mutate, restart-verify, retain, and measure one exact
   proof artifact.

Until all seven pass, the machine-readable ledger remains fail closed.
