# Dependency Audit Log

This log tracks `cargo audit` runs for the workspace. CI and release builds now
run `./scripts/dependency-audit-gate.sh`, which fails on every unwaived
vulnerability, warning, or yanked crate. Waivers live in
`config/dependency-audit-waivers.json` and must include a reason, tracking id,
package/version, kind, and expiry. A waiver must also match a current
`cargo audit` finding; stale waivers are release-gate failures and must be
removed when the underlying finding disappears.

The waiver decision table is represented in Lean by
`formal/lean/Hegemon/Release/DependencyAuditPolicy.lean`. The formal-core gate
checks Lean-generated vectors against the dependency audit policy helper, while
`cargo audit` remains the source of actual advisory findings.

Run:

    ./scripts/dependency-audit.sh --record
    ./scripts/dependency-audit-gate.sh

Each entry records the exit status and summary output so changes can be reviewed
over time.

## 2025-12-20 05:06Z

Command: cargo audit --color never --json --no-fetch --stale
Exit status: 1

Summary:

    Database: last-commit=unknown last-updated=unknown advisories=887
    Vulnerabilities: 2
    - RUSTSEC-2025-0009 ring 0.16.20 https://github.com/briansmith/ring/blob/main/RELEASES.md#version-01712-2025-03-05
    - RUSTSEC-2025-0118 wasmtime 35.0.0 https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-hc7m-r6v8-hg9q
    unmaintained: 9
    - RUSTSEC-2024-0375 atty 0.2.14 https://github.com/softprops/atty/issues/57
    - RUSTSEC-2024-0388 derivative 2.2.0 https://github.com/mcarton/rust-derivative/issues/117
    - RUSTSEC-2025-0057 fxhash 0.2.1 https://github.com/cbreeden/fxhash/issues/20
    - RUSTSEC-2024-0384 instant 0.1.13
    - RUSTSEC-2022-0061 parity-wasm 0.45.0 https://github.com/paritytech/parity-wasm/pull/334
    - RUSTSEC-2024-0436 paste 1.0.15 https://github.com/dtolnay/paste
    - RUSTSEC-2024-0370 proc-macro-error 1.0.4 https://gitlab.com/CreepySkeleton/proc-macro-error/-/issues/20
    - RUSTSEC-2025-0010 ring 0.16.20 https://github.com/briansmith/ring/discussions/2450
    - RUSTSEC-2025-0134 rustls-pemfile 2.2.0 https://github.com/rustls/pemfile/issues/61
    unsound: 1
    - RUSTSEC-2021-0145 atty 0.2.14 https://github.com/softprops/atty/issues/50
    yanked: 1
    - unknown kvdb-rocksdb 0.20.1


## 2025-12-20 05:08Z

Command: cargo audit --color never --json --no-fetch --stale
Exit status: 1

Summary:

    Database: last-commit=unknown last-updated=unknown advisories=887
    Vulnerabilities: 2
    - RUSTSEC-2025-0009 ring 0.16.20 https://github.com/briansmith/ring/blob/main/RELEASES.md#version-01712-2025-03-05
    - RUSTSEC-2025-0118 wasmtime 35.0.0 https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-hc7m-r6v8-hg9q
    unmaintained: 9
    - RUSTSEC-2024-0375 atty 0.2.14 https://github.com/softprops/atty/issues/57
    - RUSTSEC-2024-0388 derivative 2.2.0 https://github.com/mcarton/rust-derivative/issues/117
    - RUSTSEC-2025-0057 fxhash 0.2.1 https://github.com/cbreeden/fxhash/issues/20
    - RUSTSEC-2024-0384 instant 0.1.13
    - RUSTSEC-2022-0061 parity-wasm 0.45.0 https://github.com/paritytech/parity-wasm/pull/334
    - RUSTSEC-2024-0436 paste 1.0.15 https://github.com/dtolnay/paste
    - RUSTSEC-2024-0370 proc-macro-error 1.0.4 https://gitlab.com/CreepySkeleton/proc-macro-error/-/issues/20
    - RUSTSEC-2025-0010 ring 0.16.20 https://github.com/briansmith/ring/discussions/2450
    - RUSTSEC-2025-0134 rustls-pemfile 2.2.0 https://github.com/rustls/pemfile/issues/61
    unsound: 1
    - RUSTSEC-2021-0145 atty 0.2.14 https://github.com/softprops/atty/issues/50
    yanked: 1
    - unknown kvdb-rocksdb 0.20.1

## 2026-05-31 05:30Z

Command: cargo audit --color never --json --no-fetch --stale
Exit status: 1

Summary:

    Database: last-commit=unknown last-updated=unknown advisories=1099
    Vulnerabilities: 1
    - RUSTSEC-2025-0055 tracing-subscriber 0.2.25 https://github.com/advisories/GHSA-xwfj-jgwm-7wp5
    unmaintained: 6
    - RUSTSEC-2025-0141 bincode 1.3.3 https://git.sr.ht/~stygianentity/bincode/tree/v3.0/item/README.md
    - RUSTSEC-2024-0388 derivative 2.2.0 https://github.com/mcarton/rust-derivative/issues/117
    - RUSTSEC-2025-0057 fxhash 0.2.1 https://github.com/cbreeden/fxhash/issues/20
    - RUSTSEC-2024-0384 instant 0.1.13
    - RUSTSEC-2024-0436 paste 1.0.15 https://github.com/dtolnay/paste
    - RUSTSEC-2025-0134 rustls-pemfile 2.2.0 https://github.com/rustls/pemfile/issues/61
    unsound: 3
    - RUSTSEC-2026-0012 keccak 0.1.5 https://github.com/RustCrypto/sponges/pull/101
    - RUSTSEC-2026-0097 rand 0.8.5 https://github.com/rust-random/rand/pull/1763
    - RUSTSEC-2026-0097 rand 0.9.2 https://github.com/rust-random/rand/pull/1763
    yanked: 1
    - unknown keccak 0.1.5

## 2026-06-17

Command: ./scripts/dependency-audit-gate.sh
Exit status: 0

Summary:

    dependency audit findings: 8 total, 8 waived, 0 unwaived, 0 unused waivers
    waived unmaintained RUSTSEC-2025-0141 bincode 1.3.3 until 2026-08-31 (DEP-2026-0002)
    waived unmaintained RUSTSEC-2025-0057 fxhash 0.2.1 until 2026-08-31 (DEP-2026-0004)
    waived unmaintained RUSTSEC-2024-0384 instant 0.1.13 until 2026-08-31 (DEP-2026-0005)
    waived unmaintained RUSTSEC-2024-0436 paste 1.0.15 until 2026-08-31 (DEP-2026-0006)
    waived unsound RUSTSEC-2026-0012 keccak 0.1.5 until 2026-08-31 (DEP-2026-0008)
    waived unsound RUSTSEC-2026-0097 rand 0.8.5 until 2026-08-31 (DEP-2026-0009)
    waived unsound RUSTSEC-2026-0097 rand 0.9.2 until 2026-08-31 (DEP-2026-0009)
    waived yanked yanked:keccak:0.1.5 keccak 0.1.5 until 2026-08-31 (DEP-2026-0008)

Stale waivers for tracing-subscriber 0.2.25, derivative 2.2.0, and
rustls-pemfile 2.2.0 were removed after the stricter unused-waiver gate
proved and enforced that every checked-in waiver must match a current finding.
