# MiTH / VOLE-in-the-head backup architecture source screen

This ExecPlan is a living record governed by `.agent/PLANS.md`. The work is intentionally confined to `.agent/hardening/mith-backup-screen/` and is not a production implementation.

## Purpose and success condition

Screen transparent, non-ECC MPC-in-the-head and VOLE-in-the-head proof architectures against the checked-in Hegemon odd-field R1CS lower-bound geometry. A successful screen pins primary sources, states theorem scope without upgrading honest-verifier or hybrid claims, computes reproducible byte floors/projections, and leaves every authority bit false. It must run with the Python standard library only and must not build Rust, Cargo, Lake, or any proof.

## Progress

- [x] (2026-08-22) Confirmed the checked-in odd-field lower-bound geometry: Goldilocks `p = 0xffffffff00000001`, 20,457,227 constraints, 19,311,555 nonconstant variables, and 10,152 public variables.
- [x] (2026-08-22) Pinned QuickSilver, VOLE-in-the-head, ZKBoo, and FAEST v2 primary PDFs by exact SHA-256 and byte length.
- [x] (2026-08-22) Added Aurora plus the CMS19 QROM compiler as a control so the IOP lane is not falsely dismissed; it remains owned by the separate odd-field IOP/WHIR track.
- [x] (2026-08-22) Derived the exact QuickSilver one-element/gate correction floor, the exact VOLEitH Table-1 profile projection, and the optimistic direct ZKBoo view size.
- [x] (2026-08-22) Implemented the canonical source certificate, fail-closed checker, mutation corpus, tests, and retained hash manifest.

## Findings and surprises

- QuickSilver Theorem 2 is materially stronger than witness obfuscation: it gives information-theoretic malicious-verifier simulation in the ideal extended-sVOLE hybrid. It is still not self-contained.
- The generic public VOLEitH compiler's noninteractive theorem is in the programmable classical random-oracle model. The pinned 2023 paper contains no QROM theorem.
- FAEST v2 does contain a concrete finite-query QROM reduction, but its theorem is EUF-CMA for the fixed AES/Rijndael signature relation. It is not a generic NIZK complete-zero-knowledge theorem.
- Aurora/CMS19 is a genuine QROM control and must not be rejected merely for lacking a theorem. This bounded package does not duplicate that existing IOP investigation.
- The source's 128-bit large-`Fp` VOLEitH profile uses an average of three field elements per multiplication gate. Applied to 20,457,227 gates at eight bytes per Goldilocks element, the arithmetic projection alone is 490,973,448 bytes.

## Decision log

- Keep the checked-in mixed-hash R1CS counts only as a monotone lower bound. The fresh all-W64 row215 manifest closure is not compiled, so exact production geometry may only grow.
- Distinguish an actual lower floor from a profile projection. QuickSilver's designated-verifier correction vector is a one-field-element/gate floor of 163,657,816 bytes. The 490,973,448-byte number is an exact projection from VOLEitH Table 1's 128-bit `Fp` profile, not a measured Hegemon proof or universal theorem lower bound.
- Disqualify MiTH/VOLEitH promptly: both numbers exceed the 512-KiB outer envelope before self-containment, framing, and all-W64 growth; the generic noninteractive QROM gate is also absent.
- Do not promote FAEST's small fixed-relation signatures to arbitrary R1CS evidence.
- Leave all architecture, security, proof, integration, and production capabilities false.

## Context and source boundary

The geometry pin is `.agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json`. The all-W64 boundary pin is `.agent/hardening/manifest-authority-closure/capability_ledger.json`. Both hashes are checked on every run. Primary PDFs are not redistributed; their URLs, exact byte lengths, SHA-256 digests, versions, and theorem anchors are retained in `source_certificate.json`. The optional checker flag can verify a local PDF cache against those pins.

## Validation

Run only these dependency-free source checks:

    python3 .agent/hardening/mith-backup-screen/checker.py
    python3 .agent/hardening/mith-backup-screen/test_checker.py
    python3 .agent/hardening/mith-backup-screen/checker.py --verify-primary-dir /private/tmp/hegemon-mith-sources

The first two commands remain sufficient after the temporary source cache is removed. Success means the canonical artifact hashes match, all mutations fail, repository pins match, and every authority bit remains false. It does not mean a proof exists.

## Outcome

No MiTH or VOLEitH backup is admitted. The screen is closed on size and missing generic finite-QROM complete-ZK composition. The separate Aurora/CMS19 IOP control remains unassessed here and gains no authority. Production state is unchanged and fail-closed.
