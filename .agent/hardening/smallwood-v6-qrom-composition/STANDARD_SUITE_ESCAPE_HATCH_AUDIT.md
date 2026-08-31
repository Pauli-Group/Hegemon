# Conventional-suite escape-hatch audit

Date: 2026-08-22

Status: **valid negative; no winner; no authority**. This audit is source-only.
It does not select a hash registry, rotate a protocol identity, authorize
`composed_pq128`, or authorize production.

## Decision

No conventional standardized suite examined here currently instantiates all
15 Hegemon roles with a defensible, exact, composed security bound strictly
better than 128 post-quantum/QROM bits.

The obstacle is not output width. There are several cheap width-correct
designs. The obstacle is the missing bridge from the deployed conventional
primitive to the ideal object required by the available quantum theorem:

* HMAC-SHA-512 has a QROM theorem only when its Merkle--Damgard compression
  function is already a quantum random oracle, with asymptotic hidden
  constants. HKDF's proof is classical.
* KMAC256 has the strongest directly relevant keyed theorem found, but in the
  quantum ideal-permutation model, for a uniformly random key longer than the
  1088-bit rate. It does not instantiate fixed Keccak-f[1600], public
  TupleHash, transcripts, or commitments.
* keyed BLAKE2b has an exact classical weakly-ideal-cipher/multi-key theorem,
  but no deployed-BLAKE2b quantum-query PRF/QRO bridge.
* SHA-512, SHA-512 truncation, SHA3-512, TupleHash, ParallelHash, HMAC, HKDF,
  and KMAC are conventional standardized constructions. Standardization and
  known-answer tests are not QROM reductions.

An explicit concrete-hash-as-QRO assumption is the only bounded escape found.
The single-primitive minimum-assumption redesign uses approved SHA-512,
left-truncated to 400 bits under FIPS 180-4 section 7, with injective
fixed-shape role domains and fresh 512-bit independent secret prefixes. It is
an **implementation-ready experiment**, not a production-selectable suite:
the assumption has no reviewed finite deployed-hash loss, two stablecoin
source grammars remain undefined, and the
PCS/IOP/Fiat--Shamir/ZK/refinement composition remains open. Split
SHA3-512/SHAKE256 and BLAKE2b have smaller source-operation screens, but add
or retain equally unresolved concrete-hash assumptions.

This is a proof-status no-go, not evidence of a practical attack on SHA-512,
SHA-3, KMAC, HMAC, HKDF, or BLAKE2b.

## Evidence levels

Every conclusion below uses one of three labels:

1. **Theorem.** The cited primary source proves the stated game under its
   exact idealized or computational assumptions.
2. **Idealized assumption.** A candidate explicitly models a concrete tagged
   construction as a QRO, QIPM object, or ideal cipher. This is not a deployed
   primitive theorem.
3. **Concrete bridge.** A result connects the exact deployed primitive,
   framing, query surface, and multi-user history to the idealized theorem
   with explicit finite loss. No complete bridge was found for any candidate.

Generic Grover/collision widths and algorithmic primitive counts are screens.
They contribute no authorized composition term without the relevant theorem
and concrete bridge.

## Exact target and first admissible width

The retained gate requires both:

```text
Adv_total(Q = 2^64) < 2^-128
Pr[work-factor success at Q = 2^128] < 1/2.
```

Equality fails. For the ideal-QRO collision theorem in Grubbs--Maram--Paterson
Appendix B, Lemma 6, this audit conservatively replaces the theorem's
`alpha < 648` by 648:

```text
Pr[collision] <= 648*(Q+1)^3 / 2^n.
```

Exact integer comparison at `Q=2^128` shows that the first output width whose
single collision term is below `1/2` is 395 bits. The first byte-aligned width
is therefore **400 bits**. A 384-bit or 392-bit output fails; 400 bits passes.
At `Q=2^64`, the 400-bit term is approximately `2^-198.660`, before concrete
instantiation loss. This is only one tagged-product-oracle screen, not the
full composition.

Under the separately stated but unenforced history envelope
`U=15*2^32`, the ideal secret-prefix lemma for a 512-bit uniform master gives
the exact low-budget term

```text
2*U*Q / 2^256 = 15/2^159 ~= 2^-155.093109.
```

Thus the known idealized semantic-hash slice is bounded by

```text
648*(2^64+1)^3/2^400 + 15/2^159,
```

leaving about 27 bits above the target for that slice alone. This is not a
composition: the epoch cap is not consensus-enforced, correlated-key hybrids
are absent, and the full-SHA-512 proof-leaf hiding/selective-opening term has
no applicable quantitative theorem. Those missing terms are `null`, not zero.

FIPS 180-4 defines a general SHA-512/t IV procedure but says only
SHA-512/224 and SHA-512/256 are approved SHA-512/t algorithms. The smaller
candidate therefore does **not** invent “SHA-512/400.” It uses approved
SHA-512 and the standard's section-7 permission to select the leftmost 400
bits of a larger digest. Full SHA-512 remains the simpler named-output
alternative.

## The 15 roles and the minimum-assumption mapping

The proposed experiment maps roles as follows. It assumes all fixed secret
prefixes are sampled independently and uniformly, and moves each secret
immediately after its role domain so the ideal-QRO secret-prefix theorem
actually applies.

| Role | Required property | Experimental construction | Remaining blocker |
| --- | --- | --- | --- |
| note commitment | collision and commitment hiding | typed SHA-512-left400 over a fresh 512-bit blinding prefix | concrete QRO bridge; hiding/selective-opening composition |
| nullifier | qPRF and collision | typed SHA-512-left400 with the input's 512-bit spend master as prefix | concrete bridge; multi-user/correlated-role hybrid |
| Merkle node | collision | typed SHA-512-left400 | concrete bridge |
| spend-key expansion | qPRF/KDF | two injectively tagged SHA-512-left400 calls under one 512-bit spend master | concrete bridge; KDF composition |
| authorization policy | hiding and collision | typed SHA-512-left400 with a fresh 512-bit policy master | entropy/key-generation and concrete bridge |
| authorization accumulator | qPRF/hiding/collision | typed SHA-512-left400 under the policy master | correlated-role composition |
| authorization value lock | qPRF/hiding/collision | separately tagged SHA-512-left400 under the same policy master | correlated-role composition |
| intent | collision | typed SHA-512-left400 | concrete bridge |
| balance tag | collision | typed SHA-512-left400 | concrete bridge |
| ciphertext hash | collision | typed SHA-512-left400 | concrete bridge |
| stablecoin policy source | robust public-record collision binding | retain live 48-byte compatibility field and add fresh typed 400-bit constructor | constructor/source refinement and concrete bridge |
| stablecoin oracle source | collision if public; hiding/preimage if secret | same only after exact source grammar and secrecy classification | source grammar absent; secret case needs another 512-bit key |
| stablecoin attestation source | collision if public; hiding/preimage if secret | same only after exact source grammar and secrecy classification | source grammar absent; secret case needs another 512-bit key |
| proof Merkle leaf | collision and commitment hiding | full typed SHA-512 | adaptive/selective-opening theorem and concrete bridge |
| opened-leaf random tape | commitment hiding | full typed SHA-512 over the existing 64-byte independent tape and leaf index | complete-ZK/systematic-opening repair and concrete bridge |

The audit-only role registry binds the exact eight-byte frame profile
`HXQ400A1`, fifteen unique role IDs, sixteen unique eight-byte role tags (the
spend KDF has independent A/B tags), the property/secrecy classification, and
each source owner. Its 5,134-byte canonical JSON encoding has SHA-512 digest:

```text
c3aee170ead3ff2dffdb13dc69ef45d4554542364bf00fbb4b3c8c3041cbd68b9fe4ed388111530d55ad1ce735b605c7f5e28c97e7e3ebcbf3bd6c777db32337
```

Every entry has `concrete_bridge=false` and `instantiated=false`. The profile
and domains are experiment labels, not consensus or production identities.

The live `HX448C02` policy hash is a public RFC 7693 BLAKE2b-384 binding of an
exact 61-byte policy tuple. It does not hide a secret. The oracle and
attestation values remain public statement bytes, but public visibility does
not prove that their committed source records contain no secret material.
Current-height/manifest admission gives them provenance; it does not supply a
typed hash theorem or lift 384-bit robust collision strength. If governance
can prove that an authority is a fixed target before any adversarial choice,
a second-preimage-only treatment may retain 48 bytes, but that lifecycle proof
does not exist and is not assumed here.

## Exact wire, key, and source-operation schedule

The source baseline is diagnostic-only `HX448C02`: 869 bytes, eleven 56-byte
relation/consensus digests, and three exact live 48-byte stablecoin values.
There are three materially different 400-bit geometries:

| Geometry | Exact bytes | Seven-byte limbs | Security/compatibility meaning |
| --- | ---: | ---: | --- |
| replace all fourteen fields | 809 | 116 | migration counterfactual; drops exact live 48-byte fields |
| retain live fields; treat them fixed-target-only | 803 | 115 | smallest compatibility form, but unproved lifecycle classification |
| retain live fields and add three fresh 400-bit constructors | **953** | **137** | robust-collision experiment used below |

The 953-byte form preserves the live fields unchanged. It adds fresh
constructor outputs rather than pretending that `H(new_domain || old_hash)`
repairs an underlying collision; hashing the old 48 bytes alone would not.

For the 953-byte SHA-512-left400 relation, before hashing the three stablecoin
source records, the exact fixed frame schedule is:

| Family | Calls | Bytes/call | SHA-512 compressions/call | Total |
| --- | ---: | ---: | ---: | ---: |
| notes | 4 | 242 | 3 | 12 |
| nullifiers | 2 | 143 | 2 | 4 |
| Merkle nodes | 64 | 121 | 2 | 128 |
| spend lanes | 4 | 93 | 1 | 4 |
| policy | 1 | 415 | 4 | 4 |
| authorization lanes | 4 | 235 | 2 | 8 |
| intent | 1 | 822 | 7 | 7 |
| balance | 1 | 100 | 1 | 1 |
| ciphertexts | 2 | 2,182 | 18 | 36 |
| **subtotal** | **83** | | | **204** |

The intent frame deliberately retains the existing 14-byte header/flag
binding and omits only the 50-byte anchor plus two 50-byte nullifiers:
`953 - 150 + 19 = 822`. Omitting the header would save a block in some sponge
schedules but would weaken exact statement/mask binding.

Fresh stablecoin constructors add three calls. The public policy tuple is 61
bytes, so its one-field canonical frame is 80 bytes and costs one SHA-512
compression. If the canonical oracle and attestation source records have
lengths `B_oracle` and `B_attestation`, the exact total is:

```text
C_SHA512 = 204 + 1
         + ceil((B_oracle + 36)/128)
         + ceil((B_attestation + 36)/128).
```

Those two source widths are deliberately `null` in the checker. Inventing
them would turn opaque authorities into a paper schedule rather than an exact
constructor.

The fixed secret material is 512 bytes: four 64-byte note blindings, two
64-byte spend masters, and two 64-byte policy/auth masters. The present fixed
material is 288 bytes, so the exact witness delta is **+224 bytes**. A stable
source found to require hiding adds one independent 64-byte key per such
source.

A direct Boolean SHA-512 source schedule contains 752 modular-64 additions
and 240 AND-based `Ch`/`Maj` word operations per compression, or 992 nonlinear
word operations before compiler fusion/DCE. The 204-compression subtotal is
202,368 such source operations. This is not a proof-row or proof-byte
measurement.

## Standard-suite comparison

The following counts use the same 953-byte compatibility-preserving intent
binding and exclude all three stable source constructors. The known policy
constructor adds the operation shown above; the oracle and attestation costs
remain symbolic because their source grammars are undefined.

| Candidate | Exact source schedule | Key bytes | Theorem status | Verdict |
| --- | ---: | ---: | --- | --- |
| SHA-512-left400, raw typed secret prefix | 83 calls / 204 compressions | 512 | ideal-QRO secret-prefix and collision lemmas only | minimum-assumption experiment; no deployed bridge |
| HMAC-SHA-512 plus PRF/KDF lanes | 232 SHA-512 compressions | 512 | HMAC QROM only if compression is QRO; HKDF analysis classical | unselectable and larger |
| split SHA3-512-left400 / SHAKE256-400 | 50 + 106 = 156 Keccak-f permutations | 512 | ideal-width screens only; no prefix-keyed SHA3 theorem or concrete sponge bridge | smaller source screen; unselectable |
| KMAC256 + TupleHash256, 400/800-bit outputs | 226 Keccak-f permutations | 1,568 | keyed QIPM theorem applies only under new key/cap assumptions; public bridge absent | unselectable |
| keyed/unkeyed RFC 7693 BLAKE2b-400 | 148 compressions | 512 | exact theorem is classical weakly-ideal-cipher only | smallest source count; RFC is informational; unselectable |
| full SHA-512 additive grammar | 1,149 bytes / 165 limbs / 210 compressions | 512 | same missing concrete bridge | named-output fallback, not authority |

### HMAC-SHA-512, HKDF, and SHA-512/t

FIPS 198-1 specifies HMAC with an approved iterative hash and permits
left-truncated HMAC outputs. NIST's current MAC project still lists HMAC as an
approved general-purpose MAC while its specification is being moved to SP
800-224. RFC 5869 specifies HKDF extract-then-expand and permits skipping
extract only when the input is already a good pseudorandom key.

Hosoyamada--Iwata's HMAC/NMAC theorem assumes the Merkle--Damgard compression
function itself is a quantum random oracle. Its threshold statements contain
hidden asymptotic constants and do not instantiate real SHA-512. Zhandry's
prefix-free Merkle--Damgard theorem likewise starts from an ideal compression
oracle; Fehr's collapsing theorem requires the real compression to already be
collapsing and IV-preimage-resistant. The classical HKDF proof cannot be
relabelled QROM.

The counted 232-compression route uses already-uniform keys, charges both
HMAC key blocks in every call, and charges no cache as validity. It is a lower
bound if HKDF-Extract, extra key separation, or wider canonical context is
needed. It therefore offers no assumption advantage over the simpler typed
SHA-512 experiment.

SHA-512/t400 is not selected. Although FIPS 180-4 gives a deterministic IV
generation grammar for general `t < 512`, `t != 384`, it approves only the
224- and 256-bit variants. Standard SHA-512 plus section-7 truncation avoids
allocating an unapproved named variant and costs the same compression trace.

HMAC-SHA3-512 does not inherit the cited HMAC theorem: that result is for
NMAC/HMAC over a Merkle--Damgard compression function modeled as a QRO, while
SHA3-512 is a sponge. Treating the sponge as a compression oracle changes the
construction and theorem. The split SHA3-512/SHAKE256 source screen instead
uses 50 SHA3-512 permutations for secret roles and 106 SHAKE256 permutations
for public collision roles. Its widths pass ideal screens, but raw
secret-prefix SHA3 still lacks an applicable keyed-role theorem and both
functions lack a finite fixed-Keccak bridge.

### KMAC256, TupleHash, and ParallelHash

SP 800-185 standardizes KMAC, TupleHash, and ParallelHash. Standardization is
not the reduction. Hosoyamada Theorem 7 gives, for outer-keyed sponge with
uniform `kappa > r`, classical construction-query block budget `sigma`, and
`q_Q` quantum queries to the public ideal permutation/inverse:

```text
kappa' = min(kappa-r+(|s1| mod r), r-(|s1| mod r))

Adv_prf <= 4*sqrt(sigma^2*q_Q/2^c)
         + 3*sigma^2/2^c
         + 2*sqrt(2*sigma*q_Q^2/2^c)
         + 8*sqrt(2*(q_Q+sigma+|k*|/r)^2/2^kappa').
```

For normative KMAC256, `r=1088`, `c=512`; current 384/448/512-bit keys fail
`kappa > r`. Under the illustrative, unenforced envelope
`U=15*2^32`, `sigma<=64`, `q_Q=2^64`, a conservative multi-user hybrid puts a
1,568-bit key's KMAC term near `2^-151.549`. The arithmetic margin is real
inside the QIPM, but key generation, user/query caps, fixed Keccak-f[1600],
public TupleHash, and every proof-system term remain uninstantiated.

The exact key allocation is eight independent 196-byte masters, 1,568 bytes
total, or **+1,280 bytes** over the current 288. The 226-permutation schedule
preserves the statement header in the intent. A 1,600-bit Keccak permutation
has 600 64-bit AND operations in the source model, so this is 135,600
nonlinear word operations before compiler effects. ParallelHash adds leaf and
root work on these short frames and supplies no missing theorem or bridge.

### RFC 7693 BLAKE2b and tree modes

RFC 7693 permits a 50-byte BLAKE2b output and a key up to 64 bytes. The
Luykx--Mennink--Neves classical analysis gives, for `n=512`, total classical
primitive work `q`, `mu` independent uniform keys, and key size `kappa`:

```text
delta_B2 = C(q,2)/2^(2n)
         + 2*C(q,2)/2^n
         + q/2^(n/2)
         + mu*q/2^kappa
         + C(mu,2)/2^kappa.
```

This is a weakly-ideal-cipher, classical multi-key theorem. It is not a
quantum-query theorem about deployed BLAKE2b, and it does not extract entropy
or cover correlated role keys. RFC 7693 is an informational RFC and explicitly
does **not** define the original BLAKE2 design's optional personalization or
tree-hashing parameter fields. Importing BLAKE2bp or another tree profile
would therefore add a construction, framing, and theorem obligation. It also
cannot reduce the number of Boolean leaf compressions on these at-most-2.2-KiB
frames without adding a root. The 148-compression sequential-RFC count is
therefore a useful size screen only. At 576 nonlinear addition words per
compression it is 85,248 source operations, incomparable to Keccak or realized
proof bytes.

## Smaller physical-query caps do not preserve the claim

The checker records exact conditional caps; none is consensus-enforceable.
Quantum queries to a public hash are offline attacker work, not calls a node
can meter.

* For the ideal-QRO 384-bit collision bound, the largest passing power-of-two
  cap is `2^82` for the low-advantage gate and `2^124` for success below one
  half. A `2^124` work cap cannot honestly establish more than 128 bits of
  work; it merely stops the game early.
* For the secret-prefix `2*U*q/2^(k/2)` lemma, a 384-bit single-user key fails
  at `q=2^63` and passes at `2^62`. With `U=2^33`, the maximum passing power is
  `2^29`; with `U=15*2^32`, it is `2^27`. A 448-bit key raises those last two
  caps to `2^61` and `2^59`, still below the retained `2^64` budget.
* SHAKE256's generic secret/preimage term `q^2/2^256` equals `2^-128` at
  `q=2^64`. Reducing the game to `2^63` makes the inequality strict but changes
  the claimed adversary, not the primitive's 128-bit Grover ceiling.

A theorem may legitimately state a `(q, epsilon)` bound. It may not call a
profile “strictly more than 128-bit secure” by choosing `q < 2^128` and
relabeling that smaller adversary budget.

## LaZer Pack / LNP-Lite escape-hatch screen

The Pack paper's LNP-Lite Theorem 2 gives the interactive knowledge error

```text
kappa = 5/2^128 + (1/q_lattice)^lambda
      + 1/q_lattice^(d/2) + 2/|C|.
```

The leading term alone has
`-log2(5/2^128) = 125.678071905...` bits. Unmodified, it cannot satisfy a
strict `>128` target. For that term alone, the minimum integer denominator
exponent is 131 bits; the first byte-aligned choice is 136. The combined Pack
also carries other positive projection/challenge terms, so widening only this
constant is not sufficient.

Appendix C does not give a QROM theorem. It says the non-interactive
composition should follow and treats its Fiat--Shamir security heuristically
in the classical ROM, with a further multiplicative random-oracle-query loss.
The foundational Bootle--Lyubashevsky--Nguyen--Seiler paper explicitly proves
ROM, not QROM, security.

The official pinned LaBRADOR source fixes `PS_CHALBITS=128`, stores the
transcript in `uint8_t h[16]`, and repeatedly updates that 16-byte state with
SHAKE128. The Pack parameter API accepts statement, ZK mode, and integer
witness-type bits; it exposes no security level, transcript width, or hash
suite parameter. FIPS 202 caps SHAKE128 preimage strength at 128 classical
bits, hence only 64 bits under generic Grover search. Output widening cannot
lift that standardized cap, and the retained 128-bit state independently has
only a 64-bit generic quantum-preimage work factor.

Measure-and-Reprogram 2.0 Corollary 13 is the closest generic multi-round
QROM transform. For a `(2n+1)`-round public-coin protocol and `q_H` QRO
queries, its rearranged exact error coefficient is:

```text
M(n,q_H) = (2*q_H+n+1)^(2n) / n!

epsilon_FS <= M*epsilon_interactive
            + (2*q_H+n+1)^(2n)/|C|.
```

It preserves quantum interactive soundness/qPoK; it does not manufacture that
premise from Pack's classical extraction. Even in the unrealistically
favorable `n=1`, `q_H=2^64` case,
`M=(2^65+2)^2 > 2^130`. If the Pack leading term were changed to
`5/2^lambda`, that term alone would need **lambda >= 261**. Combining Pack's
`2/|C|` with the transform's `1/|C|` gives `3M/|C|`, requiring at least a
**260-bit challenge range**. A hypothetical exact `q_H^2` loss, smaller than
the actual best-case coefficient, would still need 259 denominator bits; the
first byte-aligned width is 264.

No bounded supported parameter widening closes this:

* changing `h[16]` and `PS_CHALBITS` is an ABI/protocol change, not a config;
* SHAKE128 cannot supply the needed capacity;
* SHAKE256 plus a 260/264-bit state would still need a concrete sponge/QROM
  bridge and a new projection/challenge/lattice analysis;
* the actual Pack round count is parameter-dependent and can only increase the
  measure-and-reprogram loss; and
* no source-applicable Unruh, DFMS, Katsumata, or transcript-tree compiler has
  all required Pack premises and an exact retained proof-byte schedule.

Accordingly, the approximate 110-KB Pack proof remains a promising size
challenger but is not a strict-QROM baseline. Parameter widening has no honest
bounded byte delta until a new protocol and proof are supplied.

## Exact composed ledger that remains open

Any selectable suite must populate every term below with a finite exact value:

```text
epsilon_total = epsilon_PCS_binding
              + epsilon_IOP_knowledge_soundness
              + epsilon_Fiat_Shamir_QROM
              + epsilon_hash_instantiation
              + epsilon_semantic_PRF_KDF
              + epsilon_collision_second_preimage
              + epsilon_commitment_hiding
              + epsilon_leaf_selective_opening
              + epsilon_grinding_retry_abort
              + epsilon_multi_user_history
              + epsilon_complete_ZK
              + epsilon_relation_compiler_refinement
              + epsilon_Rust_verifier_refinement
              < 2^-128.
```

The work-factor analogue must remain below one half at `2^128` total quantum
queries. A `null` or hidden-constant term is not zero. The current source
cannot populate hash instantiation, semantic PRF/KDF, stablecoin constructors,
commitment hiding, or Fiat--Shamir; the parent certificate additionally leaves
PCS/IOP, complete ZK, global history, and refinement open.

## Sealed source checkpoint

The parent fail-closed composition manifest was refreshed only after the
scalar/M4 parity owners declared the following sources quiescent:

| Source | Digest |
| --- | --- |
| `circuits/transaction/src/full_blake2b448_relation.rs` | SHA-512 `b029ebec35c9d001d245b843a7ae918a2578ec961f7b0bd6097eb28950644ab2c2a9d9bfc58d87db39ad225b940347eaaaf3f678c3462663d07c3b5c59f0ceab` |
| `prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/src/mixed_candidate.rs` | SHA-512 `1cf8ca5c3b5202cadc8bfe2b075a0a844f31f69ba4ebc646dde672cca94dc72c50c22c856ce3763939d0005f7c90968b5ac56385174d36cfeb99d46ad6495a14` |
| `prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/check_source.py` | SHA-512 `29aa5e390f86a3f2d8c31d7d393d24acd4b9115dcd5d324911a4f761d11a5042636c5f96f8d8fc893db4bb56885ab2385bfa864b33669f32790509c7b2fe3ce3` |
| frozen Binius source tree | SHA-512 `1aead2b02df1b30bc217ae4d0337ccf9ab7fa1e42dabcc8f0c0a91aef6059eb7fe55fef123583a9af2e2d769566618f2c5e734b2afce0b0d006c695de8cab052` |
| `prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs` | SHA-256 `0babc2344eedaa9cfefb03312a086e2b69f041579fbb7f6d21ffa338423e8780` |
| `composition.py` after pin refresh | SHA-512 `9670767b8108890e43aa0ce6a035a0507b577ab43dd27bfc9bdd629fef867c9a4c37fcf704d07aa136d2cf5a0e3bbc9430d3d29b73d25882c23b4dfa3f6c29de` |
| framed twelve-source relation manifest | SHA-512 `6458fedfcd900d548e640eaeaf6e681c0183dc62c721de43e4e623bdb2bddee3d8c66b4dce62b35931312c987b2204d8a6853261ec09bb7b8ed7aa8edacc20b9` |

The dependency-free evaluator reports `input_valid=true` and
`source_binding.binding_pass=true` at this checkpoint. These pins establish
drift detection only. They do not instantiate a random oracle, prove complete
zero knowledge, or authorize either proof backend.

## Implementation handoff (not selected)

If reviewers explicitly accept a concrete tagged-SHA-512-as-QRO assumption as
a protocol assumption, the smallest next experiment is:

1. allocate a fresh, non-production identity and a 953-byte compatibility
   grammar; retain the three live 48-byte stablecoin values and add three fresh
   50-byte constructor values;
2. define one injective, fixed-length role frame per call, with the 512-bit
   secret prefix immediately after the role domain and the 14-byte statement
   header retained in intent;
3. sample eight independent 64-byte masters (512 bytes total), bind their
   entropy/key-generation contract, and add 64 bytes for each stable source
   classified secret;
4. specify the canonical oracle and attestation source records so the two
   symbolic compression terms become integers;
5. compile and measure the exact Boolean relation only after the disk gate
   opens, then recompose PCS/IOP/FS/hash/grinding/history/ZK/refinement losses;
6. keep every wallet/node/consensus route fail-closed until an independent
   review accepts the concrete assumption and all mutations/restart artifacts.

This recommendation minimizes the number of distinct primitive assumptions,
not proof bytes. BLAKE2b remains the smallest source-count candidate and KMAC
has the strongest keyed ideal-model theorem, but neither has the necessary
public/deployed bridge.

## Reproduction

Run only the dependency-free checker:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agent/hardening/smallwood-v6-qrom-composition \
  -p 'test_escape_hatch.py' -v

PYTHONDONTWRITEBYTECODE=1 python3 \
  .agent/hardening/smallwood-v6-qrom-composition/escape_hatch.py
```

The first command must pass 14 tests. The second emits a deterministic
`valid-negative` JSON report and exits 2. Every capability is hard-coded
false.

## Primary sources

* NIST, [FIPS 180-4 Secure Hash Standard](https://csrc.nist.gov/files/pubs/fips/180-4/final/docs/fips180-4.pdf), sections 5.3.6 and 7.
* NIST, [FIPS 202 SHA-3 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), section A.1 and Table 4.
* NIST, [FIPS 198-1 HMAC](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf), and the [current official MAC status page](https://csrc.nist.gov/projects/message-authentication-codes).
* NIST, [SP 800-185 SHA-3 Derived Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).
* NIST, [SP 800-108 Revision 1 Update 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final).
* IETF, [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869.html), and Krawczyk, [Cryptographic Extraction and Key Derivation: The HKDF Scheme](https://eprint.iacr.org/2010/264.pdf).
* IETF, [RFC 7693 BLAKE2](https://www.rfc-editor.org/rfc/rfc7693.html), and Luykx--Mennink--Neves, [Security Analysis of BLAKE2's Modes of Operation](https://eprint.iacr.org/2016/827.pdf).
* Hosoyamada--Iwata, [On Tight Quantum Security of HMAC and NMAC in the QROM](https://eprint.iacr.org/2021/774.pdf).
* Hosoyamada, [Post-Quantum Security of Keyed Sponge-Based Constructions through a Modular Approach](https://eprint.iacr.org/2025/1059).
* Zhandry, [How to Record Quantum Queries, and Applications to Quantum Indifferentiability](https://eprint.iacr.org/2018/276.pdf).
* Fehr, [Classical Proofs for the Quantum Collapsing Property of Classical Hash Functions](https://eprint.iacr.org/2018/887.pdf).
* Grubbs--Maram--Paterson, [Anonymous, Robust Post-Quantum Public Key Encryption](https://eprint.iacr.org/2021/708.pdf), Appendix B.
* Biasioli et al., [A Toolkit for Succinct Lattice-Based Zero Knowledge Proofs](https://eprint.iacr.org/2026/1289.pdf), Theorem 2 and Appendix C.
* Don--Fehr--Majenz, [The Measure-and-Reprogram Technique 2.0](https://eprint.iacr.org/2020/282.pdf), Corollaries 13 and 15.
* Bootle--Lyubashevsky--Nguyen--Seiler, [A Non-PCP Approach to Succinct Quantum-Safe Zero-Knowledge](https://iacr.org/archive/crypto2020/12171046/12171046.pdf).
* Official LaBRADOR source at commit `3f95485139ffaa65fe572da809b90772901372e5`: [`proofsystem.h`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.h#L10-L49), [`proofsystem.c`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/proofsystem.c#L88-L93), and [`pack.c`](https://github.com/lazer-crypto/labrador/blob/3f95485139ffaa65fe572da809b90772901372e5/pack.c#L27-L46).

## Capability flags

```text
standard_suite_selected = false
concrete_hash_qrom_bridge = false
all_15_roles_instantiated = false
proof_system_qrom_composed = false
lazer_pack_qrom_authorized = false
composed_pq128 = false
production_authorized = false
```
