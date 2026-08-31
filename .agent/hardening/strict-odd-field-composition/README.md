# Strict odd-field composition ledger

Status: **valid negative, fail closed**. There is no selected architecture,
production profile, strict composed bound, or qualifying proof artifact.

This package is the exact arithmetic and source-binding gate for the current
odd-field R1CS plus HVZK-WHIR/ProveKit architecture screen. It does not turn a
source-only compiler, a one-polynomial PCS example, a classical `security_level`
parameter, or a generic hash-width estimate into production authority.

## Outcome

The ledger intentionally reports two different hash outcomes.

**A. Theorem-only concrete deployed hashes.** No pinned primary theorem gives
an applicable finite, exact deployed-hash-to-QRO bound for the full SHA-512,
SHAKE256, BLAKE2b, and semantic-role composition. The concrete-instantiation
advantage is therefore `null`, not zero, and this lane is unbounded and
fail-closed.

**B. Conventional hashes explicitly assumed to be QROs.** The ledger names
each `Adv_QRO-inst(...)` assumption and leaves its value `null`. Even the
counterfactual that sets those instantiation advantages to zero does not pass:

- a 384-bit single-key ideal-QRO secret-prefix term is exactly `2^-127`;
- a 448-bit prefix under the two-input, `2^32`-proof epoch hybrid is exactly
  `2^-126`;
- BCS Lemma 7.5's `p(x)` is total IOP proof length in bits. Theorem 11.3's
  communication formula, rate-one injectivity, `ell_in>=4`, and
  `ell_out>=2*ell_in` give at least 33,555,190 prover field elements. In the
  local 40-byte E320 coefficient representation this is
  `p(x)>=10,737,660,800` bits, leaving fewer than 93 bits at `lambda=512`.

The target is strict: total advantage must be **less than** `2^-128`. Equality
rejects. At that floor, `lambda=648` still fails and 656 is the first
multiple-of-four and byte-aligned value to pass the floor-only term. Exact
`p(x)` and the required lambda remain `null` until all 105 encoded-oracle
codeword lengths, randomness lengths, and direct messages are selected.
Neither SHA-512 nor SHAKE256 with a 512-bit output is that profile, and merely
requesting a longer SHAKE output does not establish the missing capacity and
reduction claims.

## Direct SmallWood GHCM21 route

Literal BCS is not the only conceivable zero-knowledge route.  GHCM21
Theorem 1 and Proposition 2 bound adaptive QRO reprogramming by

```text
(3*R/2) * sqrt(q_H * pmax).
```

For the conservative whole-SmallWood screen `R=2*N+8=2,097,160`, global
`q_H=2^64`, `pmax=2^-512`, and `U=2^64` sequential proofs, the exact lifetime
term is

```text
3,145,740 / 2^160 = approximately 2^-138.4150319958445.
```

The earlier `139.415` display used only `N+8` programming points and is not
retained.  Widening leaf tapes does not widen the eight transcript/output-chain
programming points.  The correct heterogeneous `U=2^64` history union is

```text
2*N leaf programs at h=576:  3 / 2^172
8 chain programs at h=512:   3 / 2^158
sum: 3*(1 + 2^-14) / 2^158 = approximately 2^-156.4149494468487.
```

The old `3,145,740 / 2^192`, approximately `2^-170.4150319958445`, remains
only a homogeneous sensitivity in which every one of the `2*N+8` programs is
assumed to have 576 bits of fresh conditional entropy.  It is not the widened-
leaf route.  Tape widening also adds 8,388,608 bytes of prover-private
randomness across all `N` tapes.

This is conditional arithmetic, not a complete-QROM-ZK certificate.  A proof
must map the whole simulator to at most `2*N+8` reprogramming calls, preserve
fresh conditional min-entropy after every earlier call and all returned side
information, give canonical injective tagged-oracle inputs, and account for
RNG failure, aborts, retries, and the exact global-versus-per-proof query
interpretation.  The current global salt is only 32 bytes.  If the first
Fiat--Shamir program relies on that salt alone, its one-proof GHCM term is
`3/2^97` (about 95.415 bits) and fails before any union.  A fail-closed repair
therefore needs a 64-byte global salt or a separate proof of at least 512 bits
of conditional entropy in the first programming point.  Widening the salt
adds 32 proof bytes, but that salt is revealed after its first use and cannot
also establish entropy for later chain programs.  Each later program needs a
proved fresh conditionally uniform 512-bit prior digest or an independent
salt.  The opened-wire sensitivities are parameterized by the DECS query count:

- `q_D=23`: 184 bytes for widened tapes, or 216 bytes including the one-time
  32-byte salt delta;
- `q_D=48`: 384 bytes, or 416 bytes including that salt delta;
- `q_D=55`: 440 bytes, or 472 bytes including that salt delta.

These are byte sensitivities, not proof that the salt or chain-entropy repair
is sufficient and not a selected production query profile.

GHCM establishes only indistinguishability of the reprogrammed-oracle hybrid.
It does not prove PCS binding, IOP soundness, RBR knowledge, extraction, or the
exact transaction relation.  CMS19 Theorem 8.6(3) separately confirms QROM
statistical ZK for the BCS construction when the IOP is HVZK, but Theorem
8.6(1--2) cannot be inherited by the custom SmallWood vector-leaf transform
without a new BCS/CMS refinement and exact RBR premises.  The provisional
SmallWood query counts 55 (`beta=1`) and 48 (`beta=2`) are recorded only as
inputs to that missing soundness proof.  Both `Adv_QRO-inst(SHA-512)` and
`Adv_QRO-inst(SHAKE256-512)` remain explicit `null` assumptions.

## Exact relation and Section 11 geometry

The pinned mixed source-only relation has:

- 20,457,227 constraints;
- 19,311,555 nonconstant variables;
- 10,152 public variables;
- 77,376 private transport variables and 19,224,027 derived auxiliaries;
- 94,551,238 source matrix nonzeros.

The equal-half Construction 11.4 candidate embedding has `ell=2^25` and a
`2*ell=2^26` total carrier. Those numbers are not a WHIR multilinear
polynomial variable count; that count remains `null` until a complete reduction
and parameter profile select it.

For `log2(ell)+1=26`, the printed Section 11 encoding has 78 inner-mask
oracles, 26 outer-mask oracles, and one witness oracle: 105 encoded oracles in
total. The statistical HVZK union has the exact shape
`(4*log2(ell)+5)*zeta = 105*zeta`; `zeta` is not instantiated, so the term is
`null`. The RBR ledger has 26 repeated sumcheck-alpha coordinates and 29 total
challenge coordinates after the initial, last-alpha/non-Boolean, and
rho/zero-evader terms are included. The printed initial `(L_out+1)/|F|`
numerator is not used as authority without `L_out >= d` or the conservative
`d+1` repair. The printed endpoint state has a separate honest-completeness
failure: `st2=(0,1,0,...)` reads a coefficient rather than evaluating at one,
so `s(X)=X^2-X` satisfies `s(0)=s(1)=0` but gives `st2*s=-1`. The repair is
`st2=pow(1)=(1,1,...)`. The printed main identity also needs the typed form
`row_M(M,alpha)[b]=Mhat(alpha,b,1)` with `alpha` in the state. Full theorem,
RBR knowledge, soundness, and inherited completeness therefore remain unset.

## Field and hash screens

Only locally implemented Plonky3 field choices are recorded:

- Goldilocks binomial degrees 2 and 5 (`E128`, `E320`);
- KoalaBear and BabyBear binomial degree 8, each about 248 field bits.

No unsupported Goldilocks `E384` or `E512` is projected onto the local code.
E320 is the only listed field retaining headroom in the deliberately
conservative local sensitivity screen: multiplying one `1/|F|` event by the
entire `2^26` carrier and applying the retained CMS local-policy lift leaves a
162-bit integer display. This coefficient is not supplied by the primary
theorem and does not select E320. E128, KoalaBear-8, and BabyBear-8 fail the
same carrier screen.

At `q=2^64`, the local unit width screens make SHA-256, Keccak-256, and
BLAKE3-256 immediate no-gos: collision is `2^-64`, while the optimistic
preimage term is exactly `2^-128` and therefore fails the strict comparison.
SHA-512 and SHAKE256-512 pass those unit width screens only. Actual transcript,
MMCS, physical-call, augmented-query, challenge-sampling, retry, and history
unions remain `null`.

The semantic ledger includes all 15 security-bearing typed roles, not merely
the 15 physical secret-role BLAKE calls or the 14 proof-wire role types. It
records key/prefix transport widths and leaves every unenforced min-entropy
claim `null`. The current mixed relation's unkeyed BLAKE2b-448 secret-derived
roles and SHAKE256-448 collision roles have no deployed, bounded-loss QROM
bridge. Stablecoin oracle and attestation constructors remain opaque, and the
four host-only relation predicates independently prevent a full production
relation.

Pinned ProveKit main is independently disqualified: its source enables
sumcheck ZK but disables witness ZK and uses a non-hiding witness commitment;
its conventional transcript/MMCS choices are 256-bit. Its numerical WHIR
`security_level` is classical, not a PQ/QROM composition. The local
CapacityBound is conjectural, and the local Johnson calculation uses `f64`
while retaining only a dominant theorem term. Neither can authorize a profile;
UniqueDecoding and a full exact-rational Johnson instantiation remain absent.

The comparison-only Goldilocks-E320 Ligerito projection remains 190,520 bytes
at `q=130`. It is not HVZK-WHIR wire, not a proof measurement, not complete ZK,
and not used in the composition.

## Artifacts and checks

- `ledger.json` is canonical JSON with sorted keys, compact separators, and one
  trailing newline.
- `composition_ledger.py` regenerates and validates every exact fraction,
  source pin, geometry constant, null boundary, and fail-closed capability.
- `check_composition.py` is the release-gate entrypoint.
- `test_composition_ledger.py` includes arithmetic, source, structure, and
  fail-open mutation tests.

Run only the dependency-free checks:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  .agent/hardening/strict-odd-field-composition/check_composition.py

PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s .agent/hardening/strict-odd-field-composition -p 'test_*.py' -v
```

No Cargo, Lake, Rust compiler, proof generation, or network access is required.
