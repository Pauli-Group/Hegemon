# Native Backend Cryptanalysis Note

This note is the repository’s direct cryptanalysis of the active native backend’s exact flattened SIS instance and the `GoldilocksFrog` quotient. It is not a new security claim. It analyzes the exact claim the code already exports, asks what concrete attack surface the split quotient introduces, and records what does and does not look dangerous today.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`
- `soundness_scope_label = "verified_leaf_aggregation"`
- `ring_profile = GoldilocksFrog`
- `commitment_security_model = "bounded_kernel_module_sis"`
- `commitment_estimator_model = "sis_lattice_euclidean_adps16"`

Exact conservative flattened instance exported by code:

- `q = 18446744069414584321`
- `n_eq = 594`
- `m = 4104`
- `B_inf = 255`
- `B_2 = 16336`
- `estimated block size β = 3294`
- `classical = 961`
- `quantum = 872`
- `paranoid = 683`

The theorem-backed reduction and flattening statement are in [native_backend_formal_theorems.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_formal_theorems.md). The exported claim surface is in [native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md). The current open-gap ledger is in [KNOWN_GAPS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/KNOWN_GAPS.md).

## Bottom Line

The quotient is genuinely split:

```text
R_q = F_q[X] / (X^54 + X^27 + 1) ≅ F_{q^27} × F_{q^27}.
```

That is exactly the kind of algebraic structure that makes it wrong to claim “ring hardness” casually. If this backend were trying to inherit the usual intuition from irreducible or cyclotomic ring problems, this split would be a major red flag.

But the shipped claim does not rely on ring hardness. It relies on a direct bounded-kernel reduction and then on the flattened coefficient-space SIS instance above. For that exact claimed bounded class, I do **not** see a concrete split-ring exploit today:

- the obvious one-component / zero-divisor shortcut is blocked by the tiny live bound `255`,
- balanced CRT pairs can stay small, but any nonzero component difference explodes immediately,
- the explicit CRT idempotents are enormous in the coefficient basis, roughly `q/3`,
- the known subfield and weak-ring attack literature is a reason for caution, but it does not directly instantiate on this exact deterministic bounded-kernel commitment path.

So the correct current stance is:

- the quotient is not “harmless” in a paper-theory sense,
- the quotient does not currently give me a concrete exploit against the claimed bounded witness set,
- the remaining uncertainty is a structural-algorithmic one: whether a future attack can beat the current coefficient-space SIS model by an unexpectedly large margin on this exact highly structured q-ary lattice.

## 1. Exact Algebra Of The Quotient

Let

```text
q = 18446744069414584321
ω = 4294967295
ω^2 = 18446744065119617025 = -4294967296 (centered)
```

with `ω^3 = 1` in `F_q`. Then

```text
X^54 + X^27 + 1 = (X^27 - ω)(X^27 - ω^2)
```

and both degree-27 factors are irreducible over `F_q`. Therefore

```text
R_q ≅ F_q[X]/(X^27 - ω) × F_q[X]/(X^27 - ω^2)
    ≅ F_{q^27} × F_{q^27}.
```

Writing a ring element as

```text
r(X) = a(X) + X^27 b(X)
```

with `deg a, deg b < 27`, the CRT coordinates are

```text
r_1 = a + ω b
r_2 = a + ω^2 b.
```

The inverse CRT map is

```text
b = (r_1 - r_2) / (ω - ω^2)
a = (ω r_2 - ω^2 r_1) / (ω - ω^2).
```

This identity is the real cryptanalytic bridge. A split-ring attack is only useful if it can produce CRT components `(r_1, r_2)` whose inverse-CRT coefficients `a, b` stay inside the claimed small coefficient box.

It also immediately shows why a blanket “inverse CRT always blows up” claim would be wrong: if `r_1 = r_2 = t`, then `b = 0` and `a = t`, so perfectly balanced CRT pairs can remain small. The real obstruction is not equality itself; it is nonzero component difference.

## 2. Explicit CRT Idempotents

The two CRT idempotents are

```text
e_1 = (X^27 - ω^2) / (ω - ω^2)
e_2 = (X^27 - ω) / (ω^2 - ω).
```

In the coefficient basis `(1, X, ..., X^53)`, each idempotent has only a constant term and an `X^27` term, but those coefficients are huge. The centered values are:

- `e_1[X^27]  =  6148914686941549910`
- `e_1[1]     = -6148914691236517205`
- `e_2[X^27]  = -6148914686941549910`
- `e_2[1]     =  6148914691236517206`

So the quotient does split, but the projectors onto the two factors are not “small” objects. They live at scale `~ q / 3`, not at scale `255`.

That matters because the simplest direct-product exploit would be:

1. find a kernel vector in one CRT component,
2. multiply by `e_1` or `e_2`,
3. get a ring-kernel vector supported only on one side.

That move exists algebraically, but it leaves the claimed bounded coefficient class immediately.

## 3. Why The Obvious Zero-Divisor Shortcut Fails In The Claimed Class

Suppose a nonzero bounded element

```text
r(X) = a(X) + X^27 b(X)
```

had one zero CRT component. Then either

```text
a = -ω b
```

or

```text
a = -ω^2 b
```

coefficientwise in `F_q`.

Now use the actual numbers:

- `|ω| = 2^32 - 1`
- `|ω^2| = 2^32`
- the claimed centered coefficient bound is only `255`

For every nonzero centered component difference

```text
δ = r_1 - r_2 ∈ [-255,255] \ {0},
```

the lifted `X^27` coefficient is

```text
b = δ / (ω - ω^2).
```

The exact finite search over the live box gives:

- `min_{δ != 0} |b| = 8589934591 = 2^33 - 1`

and the exact finite search over all bounded pairs `(r_1, r_2) ∈ [-255,255]^2` with `r_1 != r_2` gives:

- `min max(|a|, |b|) = 8589934591`

with one minimizing example `(-255, -252) -> (a, b) = (4294967042, 8589934591)` in centered form.

So balanced pairs such as `(-1, -1) -> (-1, 0)` can stay tiny, but the moment the two CRT components differ inside the live box, the inverse lift leaves the claimed witness class by an enormous margin. That is exactly the property a one-component or component-imbalanced split-ring exploit would need and exactly the property the live coefficient bound blocks.

Therefore a nonzero ring element with all centered coefficients in `[-255,255]` cannot annihilate one component of the quotient, and more generally cannot realize any small bounded CRT imbalance. The most obvious split-ring exploit is blocked by the actual live witness bound, not by wishful thinking.

This argument is much stronger than “the coefficients looked random in tests.” It is a direct incompatibility between the claimed bounded class and the quotient’s projector geometry.

## 4. What The Split Quotient Still Changes

The quotient is still not a field. It still has:

- zero divisors,
- nontrivial idempotents,
- two degree-27 CRT factors,
- and proper subfields inside each factor (`F_{q^3}` and `F_{q^9}`).

That means the usual cryptanalytic instinct is correct: this quotient deserves more suspicion than an irreducible field quotient.

The right consequence is not “the scheme is broken.” The right consequence is:

1. do not market this as ring-hardness-based cryptography,
2. do not assume structure only helps performance and never attacks,
3. ask whether the split structure creates a shortcut specifically for the exact bounded-kernel search problem the commitment reduction produces.

That is the real question of this note.

## 5. Literature-Relevant Attack Families

### 5.1 Weak-ring / skewed-embedding attacks

The Ring-LWE literature has concrete examples where special rings or bases lead to weak instances. See [Provably Weak Instances of Ring-LWE Revisited (ePrint 2016/239)](https://eprint.iacr.org/2016/239), which exploits highly skewed coefficient-basis behavior in certain RLWE families.

That matters here as a warning sign, not as a direct exploit:

- those attacks use an **error distribution** and a **search/decision RLWE** interface,
- the native backend commitment path is **deterministic** and **bounded-kernel**, not RLWE,
- and the current claim does **not** rely on any Ring-LWE worst-case reduction.

So this literature says “be suspicious of structured rings,” which is correct, but it does not currently instantiate an attack on the exact native commitment game.

### 5.2 Subfield attacks

The subfield attack literature shows that algebraic structure can lower concrete cost in ring/module lattices when the scheme and parameter regime cooperate with the subfield geometry. See [A subfield lattice attack (ePrint 2016/127)](https://eprint.iacr.org/2016/127).

Again, the relevance is cautionary rather than decisive here:

- each CRT factor is a degree-27 field and therefore does contain proper subfields,
- but the commitment matrix entries are derived coefficientwise and, under the CRT bijection, behave as uniform elements of the full product `F_{q^27} × F_{q^27}`,
- so there is no obvious “all public data secretly lives in a proper subfield” failure mode,
- and the claimed witness class is defined in the coefficient basis with a tiny coefficient cap, which strongly constrains how a subfield-structured vector could look after inverse CRT.

I therefore do **not** see a direct subfield attack today. But this is still a legitimate place for an expert external reviewer to push harder than this note does.

### 5.3 Generic structured-lattice speedups

The strongest remaining concern is more general: `A_flat` is not a uniformly random dense `594 × 4104` matrix over `F_q`. It is a block matrix of multiplication operators coming from a split quotient ring. That is real structure.

The repo’s current estimator treats the instance as coefficient-space SIS after exact flattening. That is conservative in the sense that it does not claim ideal-lattice hardness. It is not conservative in the stronger sense of “we proved no structured attack can do better than coefficient-space BKZ.”

This is the real open cryptanalytic question:

> Can the exact `GoldilocksFrog` multiplication structure reduce the true cost of the bounded-kernel search problem by a very large factor compared with the current coefficient-space estimator?

I do not currently know a concrete attack that does that. But this is the right place to spend external review effort.

## 6. How Much Margin The Exact SIS Instance Has

The current conservative line is:

- `β = 3294`
- `quantum bits = floor(0.265 β) = 872`

The overall exported native backend floor is currently transcript-limited at `305` bits, not commitment-limited. So commitment cryptanalysis has to do two different kinds of damage:

1. First it must drop below `305` just to become the active bottleneck.
2. Then it must drop below `128` to endanger the public `128`-bit claim directly.

Under the repo’s own linear bit-from-`β` line, the required block sizes are:

- to fall below `305` bits: `β < 1151`
- to fall below `256` bits: `β < 967`
- to fall below `192` bits: `β < 725`
- to fall below `128` bits: `β < 484`

Compared with the current `β = 3294`, that means:

- the attack model would need to lose about `2143` block-size points just to undercut the transcript floor,
- and about `2810` block-size points to threaten the public `128`-bit claim.

That is an enormous haircut. Put differently:

- the current commitment line can lose roughly `65%` of its effective block size and still not become the active bottleneck,
- and it can lose roughly `85%` of its effective block size before the public `128`-bit claim is threatened.

This does **not** prove the claim. It does show that the commitment side is not currently knife-edge.

## 7. Conservative Versus Exact Live Message Class

The exported claim uses the manifest-owned padded cap `76` ring elements, not the exact currently shipped `TxLeafPublicRelation` live size of only `12` ring elements.

That matters because the real live deterministic message class is a strict subclass of the conservative exported ambient space. Any attack on the exact live class is therefore attacking something **harder** than the public claim surface, not something easier.

So the public line is already conservative in two ways:

- it uses the padded `76`-element ambient cap instead of the exact live `12`-element class,
- and it then composes that with a transcript floor that is still the active bottleneck at `305` bits.

## 8. Confidence Statement

My current confidence split is:

- **High** that there is no obvious direct split-ring exploit inside the claimed coefficient-bounded class. The projector geometry and the `255` bound simply do not line up.
- **Moderate** that the current flattened SIS model is the right *kind* of public claim for this backend. It is much more defensible than pretending the split quotient gives generic ring hardness.
- **Moderate-to-low** that the concrete `872`-bit commitment number should be treated as settled external truth. That number still depends on the repo’s chosen coefficient-space attack model for a highly structured instance.

The most likely future negative result is not “instant break by zero divisors.” It is “someone finds a better-than-expected algorithm for this structured q-ary lattice family,” which would reduce the concrete commitment estimate. Given the current margin, that would need to be a very large improvement before it endangers the public `128`-bit claim.

## 9. Practical Verdict

For the exact question “does the `GoldilocksFrog` split quotient obviously invalidate the active native backend claim?”, my answer is:

```text
No, not on the exact bounded witness class the code currently claims.
```

For the broader question “is the current cryptanalytic story fully finished?”, my answer is:

```text
Also no.
```

The repo is now in a materially better state:

- it has theorem-backed transcript and reduction notes,
- it has a concrete direct-product quotient analysis,
- it has a specific argument against the simplest split-ring exploit,
- and it has large apparent slack between the conservative commitment estimate and the public `128`-bit floor.

What remains is serious external work on the structured-lattice side, not because the current line looks obviously broken, but because this exact product-ring geometry is nonstandard enough that it deserves hostile review.

## Sources

- [Native Backend Formal Theorems](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_formal_theorems.md)
- [Native Backend Security Analysis](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md)
- [Native Backend Commitment Reduction](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md)
- [Known Gaps](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/KNOWN_GAPS.md)
- [Provably Weak Instances of Ring-LWE Revisited (ePrint 2016/239)](https://eprint.iacr.org/2016/239)
- [A subfield lattice attack (ePrint 2016/127)](https://eprint.iacr.org/2016/127.pdf)
- [Ring-LWE challenges and non-two-power cyclotomic caution (ePrint 2016/782)](https://eprint.iacr.org/2016/782.pdf)
