# Dependency Audit Log

This log tracks `cargo audit` runs for the workspace. It is advisory only and
does not gate builds unless explicitly wired into CI.

Run:

    ./scripts/dependency-audit.sh --record

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

