# Concrete-hash/QROM audit for the SmallWood V6 typed roles

Live-source addendum (2026-08-22): the retained `HGF6ST02` certificate below
is a historical 893-byte negative snapshot. The current diagnostic relation is
`HX448C02`, 869 bytes, with exact 48-byte live stablecoin fields. Its policy
field now has an exact public 61-byte SCALE source tuple and RFC 7693
BLAKE2b-384 constructor; oracle and attestation source grammars remain
undefined. The conventional-suite follow-up and updated geometry are in
`STANDARD_SUITE_ESCAPE_HATCH_AUDIT.md`. Nothing in this addendum authorizes
either profile.

Date: 2026-08-22

Status: **negative and fail-closed**.  This audit does not authorize a semantic
hash profile, a proof hash profile, `composed_pq128`, or production.  It uses
only primary papers, standards, and official construction specifications.  A
generic output-width or Grover/collision work-factor screen is recorded only
when a theorem explicitly places it in a security game; it is never used as a
concrete-hash reduction.

## Result

No examined conventional profile supplies a defensible, source-bound
`< 2^-128` composition for all 15 security-bearing typed roles:

* RFC 7693 keyed BLAKE2b has a useful **classical**, weakly-ideal-cipher,
  multi-key PRF theorem.  No primary result found here supplies the missing
  real-BLAKE2b quantum-query indifferentiability/QRO bridge or a keyed
  multi-user qPRF/KDF theorem.  The classical theorem cannot be relabelled
  quantum.
* KMAC256 has a directly relevant post-quantum PRF theorem in the **quantum
  ideal permutation model**, with classical construction queries and quantum
  access to the public permutation.  The theorem requires a uniformly random
  key longer than the 1088-bit SHAKE256/cSHAKE256 rate.  Hegemon's current
  384- and 448-bit secret inputs fail that assumption.  The theorem is
  single-user and does not instantiate the real Keccak-f[1600] permutation.
* HMAC has a QROM theorem when its Merkle--Damgard compression function is a
  quantum random oracle.  That theorem does not instantiate HMAC-SHA3-512,
  whose hash is a sponge, and it has hidden asymptotic constants.  Composing it
  through the best full-sponge quantum-indifferentiability theorem found here
  is already vacuous at `q = 2^64`.
* A secret-prefix ideal random oracle has a sharp single-key qPRF bound, but
  Hegemon's 384-bit prefix gives `2^-127` at `q = 2^64`, already failing the
  strict target.  The 448-bit prefix passes only the single-key screen; the
  conservative epoch multi-user hybrid gives `2^-126` for two inputs across
  `2^32` proofs and therefore also fails.  The actual derived-key dependency
  violates the theorem's independent-uniform-key premise in any event.

This is a proof-status no-go, not evidence of a practical attack on BLAKE2b,
SHA-3, KMAC, or HMAC.

## Exact scope: 15 security-bearing roles

The checker inventory has a nearby sixteenth entry,
`semantic.authorization_dummy`, but it has no security property and is fixed
shape non-authoritative padding.  It is excluded.  The audited roles are:

| # | Exact role ID | Required property | Current strict verdict |
|---:|---|---|---|
| 1 | `semantic.note_commitment` | collision binding; preimage/commitment hiding | **NO**: no commitment composition or concrete QROM hash bridge; the proposed 384-bit secret leg is below target under the ideal-QRO theorem. |
| 2 | `semantic.nullifier` | collision binding; PRF/key derivation | **NO**: actual key derivation/correlation is unproved; 448-bit multi-user secret-prefix bound fails the epoch screen. |
| 3 | `semantic.merkle_node` | collision binding | **NO**: current SHAKE256-448 route has no exact concrete Keccak/QRO bridge. |
| 4 | `semantic.spend_key_xof` | preimage hiding; PRF/KDF; RO-XOF | **NO**: 384-bit key fails the ideal-QRO strict bound; no extractor or two-lane 896-bit expansion theorem. |
| 5 | `semantic.authorization_policy` | collision binding; preimage hiding | **NO**: no uniform-key partition, entropy contract, commitment theorem, or concrete bridge. |
| 6 | `semantic.authorization_accumulator` | collision binding; preimage hiding; PRF/KDF | **NO**: proposed `policy_root` is checked only for nonzero/consistency, not uniform entropy; keyed-theorem premise fails. |
| 7 | `semantic.authorization_value_lock` | collision binding; preimage hiding; PRF/KDF | **NO**: same entropy, correlation, and QROM blockers as the accumulator. |
| 8 | `semantic.intent` | collision binding | **NO**: SHAKE256-448 width is not a concrete QROM reduction. |
| 9 | `semantic.balance_tag` | collision binding | **NO**: same. |
| 10 | `semantic.ciphertext_hash` | collision binding | **NO**: same. |
| 11 | `statement.stablecoin_policy_hash` | robust collision binding | **NO**: live `HX448C02` has an exact public 61-byte source tuple and RFC 7693 BLAKE2b-384 constructor, but its 384-bit output has no strict composed margin or concrete-QROM bridge. |
| 12 | `statement.stablecoin_oracle_commitment` | collision binding; hiding if source is secret | **NO**: the live field is exactly 48 bytes, but the canonical source grammar and secrecy classification are absent. |
| 13 | `statement.stablecoin_attestation_commitment` | collision binding; hiding if source is secret | **NO**: same. |
| 14 | `proof.merkle_leaf` | collision binding; commitment-hiding preimage | **NO**: current role is SHA-512; no adaptive/selective-opening hiding composition or concrete QROM instantiation. |
| 15 | `proof.opened_leaf_random_tape` | commitment-hiding preimage | **NO**: current role is SHA-512; the hash cannot repair the independent complete-ZK/systematic-opening blocker. |

The mixed-candidate statement that there are 15 physical BLAKE calls is a
different count: 4 note calls, 2 nullifier calls, 4 spend-key lanes, 1 policy
call, and 4 authorization-mux calls.  That physical schedule covers only six
secret semantic role families; it does not cover the four public semantic
roles, the three separately classified stablecoin fields, or the two proof
roles above.

## Primary theorem ledger

### 1. RFC 7693 keyed BLAKE2b

RFC 7693 permits BLAKE2b digest lengths from 1 through 64 bytes and keys from
0 through 64 bytes.  Thus a 56-byte digest and Hegemon's 48- and 56-byte inputs
are syntactically permitted.  The RFC describes the keyed mode as a MAC but
its security-considerations section makes no independent security assertion.
The registered identifiers listed by the RFC cover 160, 256, 384, and 512
bits, not a separately named BLAKE2b-448 algorithm.

The controlling analysis is Luykx--Mennink--Neves, *Security Analysis of
BLAKE2's Modes of Operation*.  For state size `n`, key length `kappa`, `mu`
independent uniform keys, and total **classical** primitive complexity `q`:

**Theorem 1, compression indifferentiability in the weakly ideal-cipher
model**

```text
Indiff_F(q) <= C(q,2)/2^(2n) + C(q,2)/2^n + q/2^(n/2).
```

**Corollary 1, sequential BLAKE2 hashing-mode indifferentiability**

```text
Indiff_H(q) <= C(q,2)/2^(2n) + 2*C(q,2)/2^n + q/2^(n/2).
```

The composed simulator makes `O(q^3)` random-oracle queries.  Here `q` counts
block-cipher evaluations induced by construction and primitive queries, not
only top-level hash invocations.

**Lemma 3, ideal-hash keyed-prefix multi-key PRF**

For `KH_k(PB,m) = H(PB, k || 0^(2n-kappa) || m)`:

```text
Adv_PRF(KH) <= mu*q/2^kappa + C(mu,2)/2^kappa.
```

**Corollary 3, keyed BLAKE2 multi-key PRF**

```text
delta_B2(q,mu,kappa,n)
  = C(q,2)/2^(2n)
  + 2*C(q,2)/2^n
  + q/2^(n/2)
  + mu*q/2^kappa
  + C(mu,2)/2^kappa.
```

For BLAKE2b, `n = 512`.  Truncating both experiments to 448 bits cannot
increase distinguishing advantage, but that is a data-processing inference,
not a separately numbered theorem in the paper.

These results do not discharge the Hegemon gate:

* the model is classical and the primitive is a weakly ideal 1024-bit cipher,
  not real BLAKE2b under a standard concrete assumption;
* the keys must be independent, uniform, and of one fixed length;
* `mu` counts actual keys, not role IDs or calls; correlated/derived keys and
  two tagged lanes under one key do not acquire independence;
* the PRF result is expansion from an already uniform secret, not an entropy
  extractor for `policy_root`, a password, or correlated input material; and
* no occurrence of a quantum adversary appears in the proof.

An elementary **classical** PRF-to-MAC reduction would add `v/2^448` for `v`
fresh verification guesses, with their evaluations charged to `q`.  This is
not a QROM theorem.  Likewise, two injectively tagged calls can classically
expand a uniform key to two 448-bit strings, but Corollary 3 does not establish
KDF extraction.

The original BLAKE2 design paper calls keyed BLAKE2 a MAC/PRF and suggests it
inside PBKDF2, but its inherited-indifferentiability assertion is not a usable
replacement: the later BLAKE2-specific analysis explains why BLAKE's analysis
does not simply carry over.  BLAKE2X is only an expected-security design and is
neither RFC 7693 BLAKE2b nor Hegemon's two-tagged-call construction.

#### Closest quantum results do not bridge BLAKE2b

* Zhandry's *How to Record Quantum Queries* proves quantum
  indifferentiability for a simple domain extender and prefix-free
  Merkle--Damgard when the compression function is already an ideal random
  oracle.  Appendix-D losses are asymptotic, with hidden constants.  It does
  not prove BLAKE2's weakly-ideal-cipher compression step quantumly or cover
  the concrete BLAKE2 parameter-block/HAIFA mode.
* Fehr's *Classical Proofs for the Quantum Collapsing Property*, Theorem 1,
  gives an `L`-block Merkle--Damgard collapsing bound

  ```text
  gamma(q) = L*epsilon(q + L(L+1)/2) + sqrt(2*beta(q+L))
  ```

  when the compression function is already `epsilon`-collapsing and
  `beta`-IV-preimage-resistant; Section 4.4 treats HAIFA.  This is collapsing,
  not QRO indifferentiability, qPRF/KDF, or multi-user security, and the real
  BLAKE2 compression premise is uninstantiated.
* Proposed Zcash ZIP 2005 conditionally treats BLAKE2b/HAIFA as collapsing by
  assuming its compression function is collapsing or modelling it as a random
  oracle, then carries an asymptotic protocol `O(q^3/N)` term.  It does not
  prove that assumption, give exact constants, or supply keyed multi-user
  qPRF/KDF security.

Therefore the exact BLAKE2 classical theorem is useful evidence but contributes
**zero authorized advantage** to the current QROM composition.

### 2. Generic secret-prefix random oracle

Two primary QROM lemmas give the same decisive key-length term.

Xagawa--Yamakawa, Lemma 2.1, lets
`H : {0,1}^ell x X -> Y` and `H' : X -> Y` be independent random oracles and
lets `s` be independent uniform.  For an unbounded adversary making at most
`q_H` quantum queries to `H`:

```text
|Pr[A^(H,H(s,.))=1] - Pr[A^(H,H')=1]|
  <= 2*q_H*2^(-ell/2).
```

Grubbs--Maram--Paterson, Appendix B, Lemma 3, states the corresponding
single-key qPRF bound for `F_k(x)=H(k,x)`:

```text
Adv_qPRF <= 2*q/sqrt(|K|).
```

Their Lemma 6 gives the ideal-QRO collision bound

```text
Pr[collision] <= alpha*(q+1)^3/|Y|,    alpha < 648.
```

All three are **ideal-QRO** results.  They do not instantiate BLAKE2b,
SHA3-512, SHAKE256, or SHA-512.

At Hegemon's low-advantage query cap `q = 2^64`:

| Independent prefix entropy | Single-key bound | Strict target |
|---:|---:|---|
| 384 bits | `2 * 2^64 * 2^-192 = 2^-127` | fails |
| 448 bits | `2 * 2^64 * 2^-224 = 2^-159` | passes this term only |

The cited lemmas are single-key.  A conservative `U`-user hybrid, derived here
only by the triangle inequality, is

```text
delta_prefix_multi <= 2*U*q*2^(-ell/2).
```

This is not presented as a published multi-user theorem.  For the nullifier
epoch cap `U <= 2 * 2^32 = 2^33`, a 448-bit independent prefix gives

```text
2 * 2^33 * 2^64 * 2^-224 = 2^-126,
```

which fails.  The minimum byte-aligned independent prefix for this term alone
is 456 bits (`2^-130`).  If the union is conservatively expanded to
`U < 15*2^32 < 2^36`, 448 bits gives a bound greater than `2^-124` (the exact
`U=15*2^32` exponent is about `-123.093`), and the minimum byte-aligned prefix
for this term alone is 464 bits.  A 512-bit prefix gives `2^-158` under the
`U=2^33` screen.

Even those larger-key screens are inapplicable unless the key is sampled
independently and uniformly.  A nullifier prefix derived by the same hash/KDF
must first charge that derivation and its correlation; padding a 448-bit value
to a longer representation manufactures no entropy.

For a 448-bit ideal random-oracle output and `q=2^64`, the collision lemma has
a large numerical screen (`alpha*(q+1)^3/2^448`, with `alpha<648`).  It still
contributes zero to the concrete ledger because no bounded primitive-to-QRO
bridge is available.

### 3. SHA3-512, SHAKE256, and the concrete sponge bridge

FIPS 202 defines the normative parameters:

| Function | Keccak-f state | Rate `r` | Capacity `c` | `min(r,c)` |
|---|---:|---:|---:|---:|
| SHAKE256 | 1600 | 1088 | 512 | 512 |
| SHA3-512 | 1600 | 576 | 1024 | 576 |

Alagic--Carolan--Majenz--Tokat, *The Sponge is Quantum
Indifferentiable*, Theorem 7.22, provides an efficient simulator for a random
permutation sponge.  For `q` quantum queries, each of block length at most
`l`, its exact stated asymptotic shape is

```text
Adv_indiff = O(
    l^2 * sqrt(q^9 * 2^(-min(r,c)))
  + l^3 * fourth_root(q^5 * 2^(-min(r,c)))
).
```

The hidden constant prevents exact-integer composition.  More decisively, at
`q = 2^64` the first term is at least:

* `l^2` for SHA3-512 (`min(r,c)=576`); and
* `2^32*l^2` for SHAKE256 (`min(r,c)=512`).

Thus this theorem is already vacuous for both candidates at the required query
cap.  In fact, even ignoring the hidden constant and taking `l=1`, making the
first term strictly less than `2^-128` would require

```text
min(r,c) > 9*64 + 256 = 832.
```

No 1600-bit sponge can have `min(r,c)>800`.  This is a no-go for using this
particular theorem as Hegemon's concrete bridge at `q=2^64`; it is not an
attack on Keccak.

The same paper's Theorem 6.11 and Corollary 6.12 give one-squeeze random-
permutation preimage/collision probability `O(q^5*n*2^-min(r,c))`.  At
`q=2^64` and `n=1600<2^11`, the parameter exponents screen to `-181` for
SHAKE256 and `-245` for SHA3-512.  They cannot be entered into the exact
ledger: constants are hidden, the theorem's preimage target is a uniform
full-rate output rather than Hegemon's role-specific 448-bit truncation, and it
does not establish the PRF/KDF, Fiat--Shamir, or commitment-hiding games.

Consequently, split SHA3-512-truncated-448 is not authorized merely because
its generic width is wider than SHAKE256-448.  It still needs a concrete
Keccak/sponge QROM bridge with exact constants and role-specific composition.

### 4. KMAC256

NIST SP 800-185 defines

```text
KMAC256(K,X,L,S)
  = cSHAKE256(bytepad(encode_string(K),136)
              || X || right_encode(L),
              L, "KMAC", S),
```

and KMACXOF256 uses `right_encode(0)`.  NIST SP 800-108r1 recognizes KMAC as a
PRF-based KDF.  These are standardization facts, not quantum reductions.

Hosoyamada, *Post-Quantum Security of Keyed Sponge-Based Constructions through
a Modular Approach*, Theorem 7, is the primary quantum theorem.  For an
outer-keyed sponge with a uniformly random `kappa`-bit key, `kappa > r`, total
effective blocks `sigma` over **classical construction queries**, and at most
`q_Q` quantum queries to the public ideal permutation and its inverse, define

```text
kappa' = min(kappa-r+(|s1| mod r), r-(|s1| mod r)).
```

Then

```text
Adv_OKS^prf
 <= 4*sqrt(sigma^2*q_Q/2^c)
  + 3*sigma^2/2^c
  + 2*sqrt(2*sigma*q_Q^2/2^c)
  + 8*sqrt(2*(q_Q+sigma+|k*|/r)^2/2^kappa').
```

This is a Q1-style post-quantum PRF result in the quantum ideal permutation
model: construction queries are classical; primitive queries are quantum.  It
is single-user, assumes an independent uniform key, and does not prove
security of the fixed Keccak-f[1600] permutation.

Normative KMAC256 has `r=1088`, `c=512`.  The paper's sentence reporting
`r=1048` is arithmetically inconsistent with its stated 1600-bit state and
512-bit capacity.  It is best read as a typo or an effective offset, not a new
KMAC parameter.  From the SP 800-185 encoding, for byte-aligned keys with
`256 <= kappa < 65536`, the customization prefix consumes whole rate blocks
and the pre-key offset is exactly 40 bits:

```text
|s1| mod r = 40,
kappa' = min(kappa-1048, 1048).
```

Therefore every current 384-, 448-, or 512-bit Hegemon key fails the theorem's
`kappa > 1088` premise before any advantage is calculated.  Expanding or
padding those keys does not satisfy the independent-uniform-key assumption.

For orientation only, not profile selection, suppose all of the following
unenforced caps were adopted: `U=15*2^32`, `sigma<=64` per user,
`q_Q=2^64`, and `|k*|/r<=4`.  A conservative triangle-inequality hybrid over
the paper's single-user theorem gives approximately:

| Uniform KMAC key | `kappa'` | `log2(U * bound)` | Meaning |
|---:|---:|---:|---|
| 1512 bits | 464 | `-128.593` | first byte-aligned crossing for this KMAC term only; less than one bit of composition margin |
| 1536 bits | 488 | `-140.592` | about 12.6 bits of term-only margin |
| 1568 bits | 520 | `-151.549` | near the capacity-term floor |

For 1536 bits, simple powers-of-two upper bounds per user are: first term
`<2^-216`, second `<2^-498`, third `<2^-187`, and fourth `<2^-175`; their sum
is `<2^-174`, and multiplying by `U<2^36` yields `<2^-138`.  This conservative
multi-user multiplication is this audit's triangle-inequality derivation, not a
theorem in the paper.  At `q_Q=2^128`, the same 1536-bit illustrative envelope
is only about `2^-76.592` after that hybrid.

The calculation is not production authority because `U`, `sigma`, key
generation, independence, and key lifetime are not consensus-bound; the
Keccak permutation is still idealized; and the other PCS/IOP/Fiat--Shamir/hash
terms remain unset.  It does show that “KMAC256 with a 512-bit key” is not the
repair justified by this theorem.

### 5. HMAC-SHA3-512

NIST's HMAC specification permits approved hash functions, and NIST publishes
SHA3 HMAC examples; the draft SP 800-224 work explicitly adds SHA-3 block-size
handling.  Approval and test vectors are not a QROM theorem.

Hosoyamada--Iwata, *On Tight Quantum Security of HMAC and NMAC in the QROM*,
Theorem 1 (informal), assumes a Merkle--Damgard hash whose `m`-to-`n`
compression function is a quantum random oracle, with `m>=n`, and maximum
message length `m*l`.  A constant-probability HMAC distinguisher must satisfy
at least one of

```text
q_h*l^(5/3) + Q*l^(5/3) = Omega(2^(n/3)),
q_h + Q*l                 = Omega(2^(k/2)),
```

where `Q` is the number of HMAC/random-function queries and `q_h` the number
of compression-QRO queries.  The constants are hidden.  HMAC-SHA3-512 is not
an instance of that construction: SHA3-512 is a sponge over a public
permutation, not Merkle--Damgard over an independent quantum-random-oracle
compression function.  The full-sponge bridge above is vacuous at `2^64`, so
composing the two papers does not repair the mismatch.  HMAC-SHA-512 would
likewise require a concrete SHA-512 compression-to-QRO bridge with exact loss.

HMAC/HKDF is therefore not logically unavoidable for already independent
uniform key material--KMAC is a standardized alternative--but some reviewed
keyed construction and reduction is unavoidable for a role claimed as a
PRF/KDF.  Neither raw `SHA3-512(domain || secret || message)` nor raw keyed
BLAKE2b turns a width screen into such a reduction.

## Composition no-go and smallest standard candidate

Let the eventual composed claim have the required form

```text
delta_total
  = delta_PCS
  + delta_IOP
  + delta_FS-QROM
  + delta_hash_instantiation
  + delta_semantic_PRF/KDF
  + delta_commitment_hiding
  + delta_grinding
  + delta_multi_role/history
  + delta_refinement
  < 2^-128.
```

The current construction cannot populate at least
`delta_hash_instantiation`, `delta_semantic_PRF/KDF`, and
`delta_commitment_hiding` with applicable finite exact bounds.  In addition,
the PCS/IOP/Fiat--Shamir, complete-ZK, adaptive-opening, history, and
Rust/refinement terms remain open in the parent certificate.  An absent or
asymptotic-hidden-constant term is not zero.  Hence no defensible `>=128`
composition exists, irrespective of the generic 448/512-bit width screens.

Among the scoped standard constructions, **KMAC256 is the smallest standard
keyed mode found with a directly relevant primary post-quantum PRF theorem**.
That statement is deliberately narrow:

* it can only be a candidate for keyed semantic roles;
* the theorem requires a fresh independent uniform key longer than 1088 bits;
* under one illustrative, unenforced `q_Q=2^64`, `sigma<=64`,
  `U=15*2^32` envelope, 1512 bits is the first byte-aligned key that puts the
  KMAC term alone below `2^-128`, while 1536 or 1568 bits provides some
  arithmetic margin;
* no such key distribution or caps exist in the relation today;
* it still needs a reviewed real-Keccak instantiation bridge; and
* it does not solve collision-only public bindings, proof transcripts,
  commitments, or Fiat--Shamir.

Therefore there is **no smallest production-selectable 15-role suite yet**.
Do not rotate the protocol/profile identity to KMAC, BLAKE2b, or split
SHA3-512 on this evidence.  The smallest defensible next experiment is a fresh
candidate identity that:

1. samples and source-binds independent, uniform, role-separated KMAC256 keys
   long enough for an exact consensus-bound `U/sigma/q_Q` ledger;
2. uses typed KMAC customization strings and charges two independently tagged
   calls for every 896-bit result;
3. leaves public collision roles fail-closed until an exact conventional-hash
   QROM/collapsing bridge is pinned;
4. gives the oracle and attestation authorities explicit constructors,
   grammars and secrecy classifications, and widens or supersedes the live
   384-bit policy constructor under a fresh compatibility-preserving binding;
5. recomposes PCS, IOP, Fiat--Shamir, hash, grinding, history, complete-ZK, and
   refinement losses with exact constants.

That experiment will necessarily change relation geometry and proof bytes.
No claimed size from the current mixed candidate survives as a production
measurement for it.

## Primary sources

* NIST, [FIPS 202: SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final).
* NIST, [SP 800-185: SHA-3 Derived Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).
* NIST, [SP 800-108 Revision 1 Update 1: KDFs](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final).
* NIST, [official MAC project and HMAC/KMAC status](https://csrc.nist.gov/projects/message-authentication-codes).
* IETF, [RFC 7693: The BLAKE2 Cryptographic Hash and MAC](https://www.rfc-editor.org/rfc/rfc7693.html).
* Aumasson et al., [BLAKE2: Simpler, Smaller, Fast as MD5](https://www.blake2.net/blake2_20130129.pdf).
* Luykx, Mennink, and Neves, [Security Analysis of BLAKE2's Modes of Operation](https://eprint.iacr.org/2016/827.pdf), ToSC 2016, [DOI](https://doi.org/10.46586/tosc.v2016.i1.158-176).
* BLAKE2 designers, [BLAKE2X specification](https://www.blake2.net/blake2x.pdf) and [official project status](https://www.blake2.net/).
* Zhandry, [How to Record Quantum Queries, and Applications to Quantum Indifferentiability](https://eprint.iacr.org/2018/276.pdf).
* Fehr, [Classical Proofs for the Quantum Collapsing Property of Classical Hash Functions](https://eprint.iacr.org/2018/887.pdf).
* Zcash protocol authors, [ZIP 2005: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-2005) (status: Proposed).
* Alagic, Carolan, Majenz, and Tokat, [The Sponge is Quantum Indifferentiable](https://arxiv.org/abs/2504.16887) ([ePrint 2025/731](https://eprint.iacr.org/2025/731.pdf)).
* Hosoyamada, [Post-Quantum Security of Keyed Sponge-Based Constructions through a Modular Approach](https://eprint.iacr.org/2025/1059).
* Hosoyamada and Iwata, [On Tight Quantum Security of HMAC and NMAC in the QROM](https://eprint.iacr.org/2021/774.pdf).
* Xagawa and Yamakawa, [(Tightly) QCCA-Secure Key-Encapsulation Mechanism in the Quantum Random Oracle Model](https://eprint.iacr.org/2018/838.pdf), Lemma 2.1.
* Grubbs, Maram, and Paterson, [Anonymous, Robust Post-Quantum Public Key Encryption](https://eprint.iacr.org/2021/708.pdf), Appendix B, Lemmas 3 and 6.
* Carstens, Ebrahimi, Tabia, and Unruh, [On Quantum Indifferentiability](https://eprint.iacr.org/2018/257.pdf), Definition 2.

## Capability flags

```text
blake2b_qrom_instantiation = false
blake2b_multi_user_qprf = false
shake256_concrete_qrom_instantiation = false
sha3_512_concrete_qrom_instantiation = false
kmac256_current_key_profile_applicable = false
kmac256_multi_user_bound_source_bound = false
hmac_sha3_qrom_instantiation = false
secret_prefix_current_multi_user_bound_strictly_above_128 = false
all_15_typed_roles_instantiated = false
composed_pq128 = false
production_authorized = false
```
