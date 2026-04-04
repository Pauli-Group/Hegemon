# Native Backend Cryptanalysis Of The Flattened SIS Instance And GoldilocksFrog Quotient

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this work, the repository will contain a concrete cryptanalysis note for the active native backend family rather than a vague statement that external reviewers are still needed. A reader should be able to open one repo-local document and see the exact split-ring attack surface of `GoldilocksFrog`, the exact conservative flattened SIS instance the code claims, what attacks look plausible, what attacks were checked directly, and how much margin remains before the exported `128`-bit claim would be in danger.

The visible proof of success is a checked-in note under `docs/crypto/` that names the exact live instance, analyzes the CRT split of `Z_q[X]/(X^54 + X^27 + 1)`, records the consequences for zero divisors, idempotents, subfields, and structured-lattice attacks, and states a concrete confidence judgment plus the remaining open risks.

## Progress

- [x] (2026-04-04 06:49Z) Re-read `DESIGN.md`, `METHODS.md`, `docs/crypto/native_backend_formal_theorems.md`, `docs/crypto/native_backend_security_analysis.md`, and `audits/native-backend-128b/KNOWN_GAPS.md` to freeze the current claim surface.
- [x] (2026-04-04 06:56Z) Re-derived the exact `GoldilocksFrog` CRT split and computed the explicit idempotent coefficients locally.
- [x] (2026-04-04 06:58Z) Verified locally that no nonzero coefficient in the claimed `[-255,255]` bound can be multiplied by `ω = 2^32 - 1` and stay within that same bound, which blocks the simplest one-component zero-divisor shortcut.
- [x] (2026-04-04 07:21Z) Wrote [docs/crypto/native_backend_cryptanalysis_note.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_cryptanalysis_note.md) with the exact quotient analysis, structured-lattice risk framing, SIS margin arithmetic, and a concrete confidence statement.
- [x] (2026-04-04 07:23Z) Linked the new note from [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md) and [audits/native-backend-128b/KNOWN_GAPS.md](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/KNOWN_GAPS.md).

## Surprises & Discoveries

- Observation: the quotient splits completely as a direct product of two degree-27 fields, but the corresponding CRT idempotents are not even remotely “small”.
  Evidence: the explicit centered coefficients of the two degree-27 idempotents are approximately `±q/3`, namely about `±6.14891469e18`, not anything near the live bounded coefficient cap `255`.

- Observation: the exact live bound `255` is so small relative to the quotient split constants that the most obvious direct-product shortcut is blocked immediately.
  Evidence: for every nonzero centered integer `a ∈ [-255,255]`, the centered product `ω a (mod q)` has absolute value strictly greater than `255`, so a bounded element cannot zero out one CRT component without leaving the claimed witness class.

- Observation: the exported SIS margin is enormous compared with the `128`-bit target.
  Evidence: the active claim uses `β = 3294`, which corresponds to `872` quantum bits under the repo’s ADPS16-style line. To fall to `128` quantum bits under that same line, the effective block size would need to collapse to about `484`, a haircut of roughly `2810`.

## Decision Log

- Decision: treat the quotient split as a first-class cryptanalytic issue instead of hand-waving it away because the repo claims coefficient-space SIS.
  Rationale: a split quotient introduces zero divisors and CRT components, which are exactly the kinds of structure that can make ring-based claims brittle. Even if the exported claim is flattened, the quotient still matters if it creates unusually short bounded witnesses.
  Date/Author: 2026-04-04 / Codex

- Decision: write the outcome as a cryptanalysis note in `docs/crypto/` instead of only updating `KNOWN_GAPS.md`.
  Rationale: the user asked for the cryptanalysis itself, not merely for a gap label. A dedicated note can state both the negative result (“no obvious split-ring exploit in the claimed bounded class”) and the remaining uncertainty precisely.
  Date/Author: 2026-04-04 / Codex

## Outcomes & Retrospective

The repository now has a concrete cryptanalysis note for the exact flattened SIS instance and the split `GoldilocksFrog` quotient. The main result is narrower than “proof of security” but stronger than the old placeholder: the quotient really does split, but the explicit idempotents live at roughly `q/3`, and the claimed `[-255,255]` bounded witness class rules out the simplest one-component zero-divisor exploit directly.

The remaining uncertainty is now focused correctly. The risk is no longer “maybe the quotient trivially breaks everything.” The real open question is whether the exact structured q-ary lattice obtained from this split quotient admits a large algorithmic speedup over the current coefficient-space estimator. The note quantifies how large that speedup would need to be before it even becomes the active bottleneck and before it threatens the public `128`-bit claim.

## Context and Orientation

The active family lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). The formal theorem note in [docs/crypto/native_backend_formal_theorems.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_formal_theorems.md) already proves the exact five-challenge transcript law, the exact deterministic-commitment collision reduction, and the zero-loss coefficient flattening used by the active claim. The security-analysis document in [docs/crypto/native_backend_security_analysis.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_security_analysis.md) states the exported claim surface. The remaining cryptanalytic question is narrower: given that exact claim surface, does the split `GoldilocksFrog` quotient or the structure of the exact flattened SIS instance create a realistic shortcut that the repo’s estimate is missing?

In this plan, “GoldilocksFrog quotient” means the ring

    R_q = F_q[X] / (X^54 + X^27 + 1)

with `q = 18446744069414584321`, where

    X^54 + X^27 + 1 = (X^27 - ω)(X^27 - ω^2)

over `F_q` and `ω = 4294967295` is a primitive cube root of unity. This means the quotient is not a field: it is isomorphic to `F_{q^27} × F_{q^27}`. That split is potentially dangerous in any ring-based construction, so it has to be analyzed directly.

In this plan, “exact flattened SIS instance” means the explicit conservative instance the repo exports after flattening the direct bounded-kernel reduction into coefficient coordinates:

    q = 18446744069414584321
    n_eq = 594
    m = 4104
    B_inf = 255
    B_2 = 16336

The code currently evaluates this instance with the in-repo `sis_lattice_euclidean_adps16` model and obtains `β = 3294`, `classical = 961`, `quantum = 872`, `paranoid = 683`.

## Plan of Work

First, write down the exact quotient attack surface in plain language. That means deriving the CRT decomposition, the explicit idempotents, and the exact inverse-CRT formulas that map a pair of degree-26 field representatives back into the degree-53 coefficient basis. This is the crucial bridge from abstract “the ring splits” to the actual product path, because the bounded witness class is defined in coefficient coordinates, not in CRT coordinates.

Second, analyze the direct attacks the split quotient invites. The note must cover the simplest one-component or zero-divisor strategy, the risk from proper subfields inside `F_{q^27}`, and the fact that the flattened commitment matrix is highly structured rather than a uniformly random `594 × 4104` matrix over `F_q`. The note must state what is ruled out directly, what only seems implausible, and what still needs external cryptanalysis.

Third, quantify the slack in the exact exported SIS line. The note must show what effective BKZ block size would correspond to `128`, `192`, `256`, and larger quantum-bit floors under the same cost model, so a reader can see whether the current claim survives only narrowly or by a very large margin.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Local quotient checks already performed:

    python3 - <<'PY'
    q = 18446744069414584321
    omega = 4294967295
    omega2 = 18446744065119617025
    den1 = (omega - omega2) % q
    inv_den1 = pow(den1, -1, q)
    den2 = (omega2 - omega) % q
    inv_den2 = pow(den2, -1, q)
    for name, val in [
        ("e1_x27", inv_den1),
        ("e1_const", (-omega2 * inv_den1) % q),
        ("e2_x27", inv_den2),
        ("e2_const", (-omega * inv_den2) % q),
    ]:
        centered = val if val <= q // 2 else val - q
        print(name, centered)
    PY

Expected observation: all four centered coefficients have magnitude about `q/3`, not anything like `255`.

Bounded zero-divisor check already performed:

    python3 - <<'PY'
    q = 18446744069414584321
    omega = 4294967295
    B = 255
    for a in range(-B, B + 1):
        if a == 0:
            continue
        prod = (omega * a) % q
        centered = prod if prod <= q // 2 else prod - q
        assert abs(centered) > B
    print("no nonzero bounded coefficient survives the omega scaling test")
    PY

Expected observation: the script prints the final line without finding a counterexample.

## Validation and Acceptance

This work is accepted when a reader can open the new cryptanalysis note and verify all of the following directly from the repo:

1. The note states the exact quotient split, exact bounded witness class, and exact flattened SIS parameters.
2. The note explains why the most obvious split-ring exploit does not produce a nonzero witness inside the claimed coefficient bound.
3. The note explains what remains uncertain and why external cryptanalysis is still appropriate.
4. The note quantifies how much attack-model degradation would be needed before the exact exported `128`-bit floor is threatened.

The note itself is the user-visible artifact. A successful run therefore means the markdown exists, is internally coherent, and matches the numbers exported by the code.

## Idempotence and Recovery

This work is additive documentation and local analysis only. Re-running the local arithmetic checks is safe and deterministic. If the note needs revision, edit it in place and update this plan’s `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections to match the new state.

## Artifacts and Notes

Current local evidence:

    q mod 81 = 4
    omega^3 mod q = 1
    centered e1_x27  =  6148914686941549910
    centered e1_const = -6148914691236517205
    centered e2_x27  = -6148914686941549910
    centered e2_const =  6148914691236517206

This is exactly the shape we wanted to test: the quotient does split, but the projection idempotents are huge in the coefficient basis.

## Interfaces and Dependencies

The output of this plan is a markdown note under `docs/crypto/`. It should cite and remain consistent with:

- `docs/crypto/native_backend_formal_theorems.md`
- `docs/crypto/native_backend_security_analysis.md`
- `docs/crypto/native_backend_commitment_reduction.md`
- `audits/native-backend-128b/KNOWN_GAPS.md`
- `circuits/superneo-backend-lattice/src/lib.rs`

The note should not invent a new security claim. It must analyze the exact existing `verified_leaf_aggregation` claim surface and the exact `bounded_kernel_module_sis` / `sis_lattice_euclidean_adps16` line that the code already exports.

Revision note: created on 2026-04-04 to turn the repo’s remaining “needs external cryptanalysis” sentence into a concrete, repo-local cryptanalysis note with explicit quotient findings and exact SIS slack arithmetic.
