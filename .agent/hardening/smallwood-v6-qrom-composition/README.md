# SmallWood V6 PQ/QROM composition certificate

## Verdict

This directory contains an exact-integer, dependency-free, fail-closed security ledger for a prospective SmallWood V6 successor. It is not a reduction, audit, benchmark, or production authorizer. The checked artifact always reports `composed_pq128 = false` and `production_authorized = false`.

The primary-source concrete-hash follow-up is in
`CONCRETE_HASH_QROM_AUDIT.md`.  It leaves all 15 security-bearing typed roles
unauthorized: keyed BLAKE2b has only a classical weakly-ideal-cipher multi-key
theorem; current 384/448-bit keys do not meet the directly relevant KMAC256
quantum-ideal-permutation theorem's `key_bits > 1088` premise; and the known
full-sponge quantum-indifferentiability bound is vacuous at the certificate's
`2^64` query cap.  Ideal-QRO secret-prefix bounds are recorded but are not
treated as concrete BLAKE2b, Keccak, or SHA-512 reductions.

The bounded conventional-suite and LaZer escape-hatch audit is in
`STANDARD_SUITE_ESCAPE_HATCH_AUDIT.md`, with exact-integer reproduction in
`escape_hatch.py`. It finds no selectable suite. The single-primitive
minimum-assumption experiment is standard SHA-512 left-truncated to 400 bits
under an explicit concrete tagged-product-QRO assumption; that assumption is
not a deployed-hash theorem and all authority flags remain false.

The currently encoded **historical negative** candidate is the fresh tuple `circuit=6, crypto=5, family=1, action=8, backend=2, profile=3, domain_set=2`, statement magic `HGF6ST02`, semantic frame `HEG-F6V2`, and typed hash registry `HGF6HR02`. Its 893-byte statement is transported losslessly as 128 consecutive seven-byte little-endian Goldilocks values with exactly three zero padding bytes. Intent, balance tag, and both 2,147-byte ciphertext hashes remain inside that rejected relation.

The newer source-only diagnostic `HX448C02` supersedes that statement geometry
for tournament work: it is exactly 869 bytes / 125 seven-byte limbs, retains
eleven 56-byte relation/consensus digests, and carries the three live
stablecoin authorities as exact 48-byte values. It has no production identity
or proof artifact. A robust 400-bit compatibility experiment that retains
those three fields and adds fresh typed constructors is 953 bytes / 137 limbs;
809 bytes / 116 limbs is only a replacement migration that drops the live
fields.

`HGF6HR02` is disqualified as a conventional-hash production profile. Its `Shake512Output448` algorithm is Keccak-f[1600] with rate 72, capacity 1,024, and the SHAKE suffix `0x1f`. FIPS 202 standardizes SHAKE128 and SHAKE256, not “SHAKE512”; this construction is therefore a new XOF authority. Its generic capacity/output screens have margin, but no profile may convert those screens into conventional-hash or production authority.

The historical profile-2 uniform-SHAKE256 alternative is also disqualified. FIPS SHAKE256 has at most 256 classical preimage strength and 128-bit generic quantum preimage strength. Six unavoidable secret/preimage/PRF roles would therefore reach exactly 128 bits, while this lane requires every primitive role cap to be strictly greater than 128. Equality never passes.

The proof-system field/channel follow-up is recorded separately in
`FIELD_CHALLENGE_AUDIT.md`.  It does not fold the live B128/SHA-256/96-bit
negative control into the proposed framed-SHA-512 channel.  On the retained
depth-20, rate-`1/8` distinct-query schedule, `q=318` is the exact minimum only
for the historical 264-bit query-component allocation.  Freezing the other
eleven terms of the incomplete scaffold gives a different modeled threshold,
`q=310`, with a 1,528,928-byte E384 fixed-synthetic-transcript projection.  Neither is a
production minimum, and 512 KiB remains a provisional parser-safety screen,
not an immutable consensus limit or a universal BaseFold lower bound.  The
same fixed-synthetic-transcript serializer projects 695,840 E384 bytes even at
the rejected historical `q=116` count, so no enumerated retained 4+3-tree
checkpoint passes that provisional screen.  The
systematic leaf-zero privacy failure, missing adaptive FRI/Fiat–Shamir/QROM
reductions, and absent exact field-degree registry keep every capability false.
Both byte checkpoints are zero-ZK-cost counterfactuals: the source-faithful
Diamond BaseFold mask appends random coefficients and changes the committed
dimension, so the tree, query, frontier, and serializer schedules require a
fresh calculation after integration.  The stabilized source assessment says
the current mixed backend matches none of the required Diamond commitment,
virtual-oracle, interleaving, terminal-pair, or salted-opening grammar.

The exact 214-byte `HGF6HR02` registry hashes under raw SHA-512 to:

    840e4426ab9b8b74e6400f4573109db0b2324df6b2fd81a81f24c2cc801dd0767b8caaa2a58e219db3f0e90494d2312e39fc83642d21b81a6becdf3373a19631

The broader checker-owned 43-role property/domain audit is separately digest-bound. Its digest changes whenever an algorithm, purpose, property, domain, width, source owner, or role status changes.

    8b5ef178cad2253035c22f5d4b6dbb3b2245c56bfc458034582545db2240138c53be861b3e8cb51c14a13cc2a4a29bf6171802f89ebc84dc543fb2f586b7b824

## Role classification

The rejected registry contains nine families, 79 invocations, and 145 Keccak permutations:

| Family | Required purpose | Encoded primitive | Calls | Permutations |
| --- | --- | --- | ---: | ---: |
| `note.cm3` | preimage-hiding commitment and collision binding | nonstandard Keccak[c=1024] XOF, 448-bit output | 4 | 16 |
| `nullif.2` | keyed PRF/KDF and collision binding | nonstandard Keccak[c=1024] XOF, 448-bit output | 2 | 4 |
| `merk.nd2` | collision-only Merkle binding | FIPS SHAKE256-448 | 64 | 64 |
| `sp.keys2` | secret XOF/KDF | nonstandard Keccak[c=1024] XOF, 896-bit output | 2 | 6 |
| `policy.1` | private-policy preimage hiding and collision binding | nonstandard Keccak[c=1024] XOF, 448-bit output | 1 | 6 |
| `auth.mux` | accumulator/value-lock PRF/KDF | nonstandard Keccak[c=1024] XOF, 896-bit output | 2 | 8 |
| `intent.1` | collision-only public binding | FIPS SHAKE256-448 | 1 | 6 |
| `bal.tag1` | collision-only public binding | FIPS SHAKE256-448 | 1 | 1 |
| `ct.hash1` | collision-only ciphertext binding | FIPS SHAKE256-448 | 2 | 34 |

The six unavoidable semantic secret roles are `semantic.note_commitment`, `semantic.nullifier`, `semantic.spend_key_xof`, `semantic.authorization_policy`, `semantic.authorization_accumulator`, and `semantic.authorization_value_lock`. As a parameter screen only, the shortest selected nonstandard-XOF output has a 224-bit generic quantum preimage cap; its 896-bit outputs are capped at 256 bits by the 1,024-bit capacity. A 448-bit collision role has a generic quantum collision cap of `floor(448/3) = 149` bits. Full SHA-512 proof binding has a 170-bit generic quantum collision cap and a 256-bit generic preimage cap. Fiat-Shamir and XOF roles are not authorized from width caps; their QROM transformations remain external losses.

Eleven consensus `hash448` roles bind rules, genesis, chain, block, action, semantic action, action root, commitment-tree root, nullifier-accumulator root, state root, and transaction-proof binding. They are classified collision-only, with typed FIPS SHAKE256-448 domains owned by `crypto/hash448`. Accepted alternate encodings must reduce to a collision; the certificate never silently assumes native SHAKE256 second-preimage strength.

The SHA-512 proof registry separately classifies inline proof binding; field and coefficient XOFs; PIOP input/transcript/opening; DECS opening/query/disjoint-coset binding; Merkle leaf/node/root; opened-leaf tape; and disabled grinding. Merkle leaves and opened-leaf tapes require hiding/preimage properties. Grinding has zero configured bits and contributes no prover retry multiplier, but its retry/abort composition remains external.

The three live stablecoin authorities are exact 48-byte public statement
fields. `stablecoin_policy_hash` now has an exact 61-byte public SCALE source
tuple and an RFC 7693 BLAKE2b-384 constructor, but a 384-bit robust-collision
binding has no positive strict composed margin. Oracle and attestation retain
manifest/current-height admission but still lack canonical source grammars and
secrecy classifications. If either source hides secret material, it needs a
fresh independent qualifying key in addition to a wider typed constructor.
Compatibility admission is not a hash/QROM reduction, so all three keep the
strict role gate false.

A conventional successor can investigate SHA3-512. A 448-bit truncation retains a 224-bit generic quantum output-preimage screen. Splitting every former 896-bit output into separately tagged SHA3-512 calls gives 83 primitive invocations, 11 relation families, 46 secret-role Keccak permutations, and 151 total permutations when the 105 collision-only SHAKE256 permutations are retained. The 384-bit spend seed caps generic Grover key search at 192 bits. Raw `SHA3-512(domain || secret || message)` is enough to state collision/preimage screens, but it is not by itself an executed PRF/KDF QROM reduction. HMAC or HKDF is not mathematically unavoidable for a uniform high-entropy seed; some reviewed keyed construction and reduction is unavoidable for roles claimed as PRF/KDF. A lower-bound HMAC-SHA3-512 split schedule is already 173 permutations before HKDF extract, fixed-mux padding, or compiler rows. No concrete Keccak/sponge-to-QROM bridge with bounded loss is pinned.

RFC 7693 BLAKE2b with digest length 56 has the same 149-bit collision and 224-bit output-preimage screens. The exact mixed unkeyed screen is 83 primitive invocations, 28 secret-role BLAKE2b compressions, and 105 collision-role SHAKE256 permutations—133 heterogeneous cores—but raw secret hashing has no PRF/KDF authority. The keyed/personalized repair is 83 invocations, 32 BLAKE2b compressions plus the same 105 SHAKE permutations—137 heterogeneous cores. BLAKE2b keyed mode is a conventional MAC construction and accepts the 48-byte spend key and 56-byte derived keys, whose generic Grover key-search caps are 192 and 224 bits respectively. No reviewed deployed BLAKE2b-as-QRO or multi-user PRF/KDF reduction with bounded QROM loss is pinned. More importantly, the authorization frames expose no enforced min-entropy contract for the proposed `policy_root` key: source validation checks it only for nonzero and consistency. Keyed hashing cannot manufacture entropy.

Generic work factors are not composition terms, and Keccak permutations and BLAKE2b compression calls are not comparable proof rows or proof bytes. No conventional successor wins yet. Do not rotate identity until the keyed-role semantics, entropy contract, exact fixed-shape compiler, measured geometry, and concrete-hash/QROM reductions are chosen.

## Exact composition terms

Let `q = 2^64 - 2^32 + 1`, `rho = eta = 5`, `s = 5` PIOP openings, `p = 64` packing points, `N = 2^20` DECS positions, and `d = 23` openings. For measured V6 geometry, let `D` be the consistency-discrepancy degree, `L` the LVCS column count, and `K` the base-game arity cap. The interactive ledger is exactly:

    epsilon_interactive = 1/q^eta
                        + 1/q^rho
                        + falling(D,s)/falling(q-p,s)
                        + falling(L+d-1,d)/falling(N,d).

At one total quantum-query budget `Q`, the ideal CMS envelope is:

    12 Q^2 epsilon_interactive + 48 Q^3/2^512 + 2 K^2/2^512.

The global primitive screens, each included once rather than once per call or permutation, are:

    FIPS SHAKE256 collision       = 4 Q^3 / 2^448
    nonstandard XOF collision     = 4 Q^3 / 2^448
    nonstandard XOF preimage/PRF  = Q^2 / 2^448
    SHA-512 leaf hiding           = Q^2 / 2^512.

At `Q=2^64`, these are `2^-254`, `2^-254`, `2^-320`, and `2^-384`. At `Q=2^128`, they are `2^-62`, `2^-62`, `2^-192`, and `2^-256`. The rejected uniform-SHAKE256 secret-preimage screen is `Q^2/2^256`: exactly `2^-128` at `Q=2^64` and one at `Q=2^128`. These are screens only. PCS/IOP, Fiat-Shamir, SHA-512, SHAKE256, novel-XOF, leaf-hiding, extraction, history, and retry reductions are separate exact-valued profile fields and are null in the checked artifact.

The low-advantage gate is an exact rational comparison requiring strictly less than `2^-128` at `Q=2^64`. The work-factor gate requires success below `1/2` at `Q=2^128`. The selected history model is one shared tagged-product oracle with one total query budget. A `2^32` per-proof union is reported only as a rejected counterfactual.

## DECS, physical calls, and source binding

The strict DECS identity requires a multiplicative coset disjoint from LVCS interpolation points and rejects a radix-2 subgroup. Every opened leaf must bind an independent 64-byte random tape and its index, for 1,472 raw tape bytes across 23 openings. The adaptive hiding theorem and compiled refinement remain absent.

Physical SHA-512 calls are not capped today. Goldilocks rejection sampling can draw unbounded raw SHA-512 blocks, and the optimized prover leaf path bypasses the existing digest counter. The checker inventories structural minima and upper bounds, but requires an enforced per-proof cap, a `2^32`-proof epoch cap, and a combined honest-plus-adversarial history ledger before numeric gates may pass.

Twelve exact source roles cover the engine, statement/registry owner, consensus `hash448` registry, Boolean hash compiler, rejected full relation, frozen conventional scalar candidate, frozen mixed-M4 candidate and its source checker, envelope, adapter, compiled verifier, and this checker. Each pin is a SHA-512 digest of a bounded, non-symlink, checker-owned path. The M4 source must also contain the frozen Binius-tree digest checked by its dependency-free source checker. A framed manifest binds identity, statement, proof system, hashes, budgets, projection, geometry, and all observed pins. `HGF6ST02`, `HEG-F6V2`, and `HGF6HR02` are sole-owner literals; every typed domain must be defined by its designated source. Pinning never discharges a reduction or refinement.

The checked profile retains an exact twelve-file rejection/tournament snapshot and framed manifest. Its current source-binding gate passes with manifest SHA-512 `6458fedfcd900d548e640eaeaf6e681c0183dc62c721de43e4e623bdb2bddee3d8c66b4dce62b35931312c987b2204d8a6853261ec09bb7b8ed7aa8edacc20b9`. Any later edit by a concurrent owner causes a digest mismatch and keeps the certificate closed; repinning is a review action, not an authorization action.

## Validation and claim ceiling

Run the lightweight suite from the repository root:

    python3 -m unittest discover -s .agent/hardening/smallwood-v6-qrom-composition -p 'test_*.py' -v

The current suite has 55 passing tests. It includes exact registry/digest reproduction, role-cap classification, an unavoidable-preimage mutation that reaches exactly 128 bits and fails, the no-winner conventional-successor gate, unresolved-authority rejection, domain/source mutations, exact sampler checks, stale identity/projection rejection, history-union rejection, CLI fail-closed behavior, live SHA-256 negative controls, exact finite-query thresholds, source-pinned q116/q319/q318/q310 retained-tree projections, the 395/400-bit ideal-collision boundary, exact source-operation schedules, lower-query-cap relabeling rejection, duplicate escape-domain rejection, and LaZer/DFM20 widening arithmetic.

Run the negative certificate with:

    python3 .agent/hardening/smallwood-v6-qrom-composition/composition.py --profile .agent/hardening/smallwood-v6-qrom-composition/profile.json --repo-root .

Valid but unauthorized input exits 2; malformed input exits 1. The novel `HGF6HR02` primitive, exact V6 geometry, enforced physical/history caps, quantitative reductions, complete zero knowledge, relation-to-IOP and Rust-verifier refinements, parser/wire refinement, and independent review remain blockers. The historical 699-row test fixture and synthetic loss values exercise arithmetic only and are not V6 evidence.
