# Dependency Audit Log

This log tracks `cargo audit` runs for the workspace. It is advisory only and
does not gate builds unless explicitly wired into CI.

Run:

    ./scripts/dependency-audit.sh --record

Each entry records the exit status and raw output so changes can be reviewed
over time.

## 2025-12-20 04:56Z

Command: cargo audit --color never
Exit status: 1

Output:

        Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
          Loaded 887 security advisories (from /Users/pldd/.cargo/advisory-db)
        Updating crates.io index
        Scanning Cargo.lock for vulnerabilities (1114 crate dependencies)
    Crate:     ring
    Version:   0.16.20
    Title:     Some AES functions may panic when overflow checking is enabled.
    Date:      2025-03-06
    ID:        RUSTSEC-2025-0009
    URL:       https://rustsec.org/advisories/RUSTSEC-2025-0009
    Solution:  Upgrade to >=0.17.12
    Dependency tree:
    ring 0.16.20
    └── rcgen 0.11.3
        └── libp2p-tls 0.5.0
            └── libp2p-quic 0.11.1
                └── libp2p 0.54.1
                    ├── sc-telemetry 15.0.0
                    │   ├── sc-sysinfo 27.0.0
                    │   │   └── sc-service 0.35.0
                    │   │       ├── sc-cli 0.36.0
                    │   │       │   └── hegemon-node 0.3.0-alpha
                    │   │       │       └── security-tests 0.1.0
                    │   │       └── hegemon-node 0.3.0-alpha
                    │   ├── sc-service 0.35.0
                    │   ├── sc-cli 0.36.0
                    │   ├── sc-chain-spec 28.0.0
                    │   │   ├── sc-service 0.35.0
                    │   │   ├── sc-rpc-spec-v2 0.34.0
                    │   │   │   └── sc-service 0.35.0
                    │   │   ├── sc-rpc-api 0.33.0
                    │   │   │   ├── substrate-frame-rpc-system 28.0.0
                    │   │   │   │   └── hegemon-node 0.3.0-alpha
                    │   │   │   ├── sc-rpc-server 11.0.0
                    │   │   │   │   └── sc-service 0.35.0
                    │   │   │   ├── sc-rpc 29.0.0
                    │   │   │   │   ├── sc-service 0.35.0
                    │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
                    │   │   │   │   └── hegemon-node 0.3.0-alpha
                    │   │   │   └── hegemon-node 0.3.0-alpha
                    │   │   ├── sc-rpc 29.0.0
                    │   │   └── hegemon-node 0.3.0-alpha
                    │   └── sc-basic-authorship 0.34.0
                    │       └── hegemon-node 0.3.0-alpha
                    └── sc-network 0.34.0
                        ├── sc-service 0.35.0
                        ├── sc-network-transactions 0.33.0
                        │   └── sc-service 0.35.0
                        ├── sc-network-sync 0.33.0
                        │   ├── sc-service 0.35.0
                        │   ├── sc-network-transactions 0.33.0
                        │   └── sc-informant 0.33.0
                        │       └── sc-service 0.35.0
                        ├── sc-network-light 0.33.0
                        │   └── sc-service 0.35.0
                        ├── sc-mixnet 0.4.0
                        │   ├── sc-rpc-api 0.33.0
                        │   ├── sc-rpc 29.0.0
                        │   └── sc-cli 0.36.0
                        ├── sc-informant 0.33.0
                        ├── sc-cli 0.36.0
                        └── sc-chain-spec 28.0.0
    
    Crate:     wasmtime
    Version:   35.0.0
    Title:     Unsound API access to a WebAssembly shared linear memory
    Date:      2025-11-11
    ID:        RUSTSEC-2025-0118
    URL:       https://rustsec.org/advisories/RUSTSEC-2025-0118
    Severity:  1.8 (low)
    Solution:  Upgrade to >=38.0.4 OR >=37.0.3, <38.0.0 OR >=36.0.3, <37.0.0 OR >=24.0.5, <25.0.0
    Dependency tree:
    wasmtime 35.0.0
    ├── sp-wasm-interface 20.0.0
    │   ├── sp-runtime-interface 24.0.0
    │   │   ├── sp-statement-store 10.0.0
    │   │   │   └── sc-rpc 29.0.0
    │   │   │       ├── sc-service 0.35.0
    │   │   │       │   ├── sc-cli 0.36.0
    │   │   │       │   │   └── hegemon-node 0.3.0-alpha
    │   │   │       │   │       └── security-tests 0.1.0
    │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │       ├── sc-rpc-spec-v2 0.34.0
    │   │   │       │   └── sc-service 0.35.0
    │   │   │       └── hegemon-node 0.3.0-alpha
    │   │   ├── sp-io 30.0.0
    │   │   │   ├── sp-runtime 31.0.1
    │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── sp-version 29.0.0
    │   │   │   │   │   ├── sp-api 26.0.0
    │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   ├── sp-transaction-pool 26.0.0
    │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       └── consensus 0.1.0
    │   │   │   │   │   │   │           ├── security-tests 0.1.0
    │   │   │   │   │   │   │           └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── sp-statement-store 10.0.0
    │   │   │   │   │   │   ├── sp-session 27.0.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   │   │   └── pallet-session 28.0.0
    │   │   │   │   │   │   │       └── runtime 0.1.0
    │   │   │   │   │   │   ├── sp-offchain 26.0.0
    │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   └── runtime 0.1.0
    │   │   │   │   │   │   ├── sp-mixnet 0.4.0
    │   │   │   │   │   │   │   └── sc-mixnet 0.4.0
    │   │   │   │   │   │   │       ├── sc-rpc-api 0.33.0
    │   │   │   │   │   │   │       │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   │       │   ├── sc-rpc-server 11.0.0
    │   │   │   │   │   │   │       │   │   └── sc-service 0.35.0
    │   │   │   │   │   │   │       │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │       └── sc-cli 0.36.0
    │   │   │   │   │   │   ├── sp-genesis-builder 0.8.0
    │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   │   │   └── frame-support 28.0.0
    │   │   │   │   │   │   │       ├── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-treasury 27.0.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-transaction-payment 28.0.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   └── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-timestamp 27.0.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │   │   │   │   │   │   │       │   │   └── runtime 0.1.0
    │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       ├── pallet-sudo 28.0.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-shielded-pool 0.1.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       ├── pallet-settlement 0.1.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-session 28.0.0
    │   │   │   │   │   │   │       ├── pallet-oracles 0.1.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-observability 0.1.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-membership 28.0.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-identity 0.1.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       │   └── pallet-asset-registry 0.1.0
    │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       ├── pallet-feature-flags 0.1.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-difficulty 0.1.0
    │   │   │   │   │   │   │       ├── pallet-collective 28.0.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-coinbase 0.1.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       ├── pallet-balances 28.0.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
    │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       │   └── pallet-coinbase 0.1.0
    │   │   │   │   │   │   │       ├── pallet-attestations 0.1.0
    │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── pallet-asset-registry 0.1.0
    │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │       ├── frame-try-runtime 0.34.0
    │   │   │   │   │   │   │       │   └── frame-executive 28.0.0
    │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │   │   │   │       ├── frame-system 28.0.0
    │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
    │   │   │   │   │   │   │       │   ├── pallet-transaction-payment 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-timestamp 27.0.0
    │   │   │   │   │   │   │       │   ├── pallet-sudo 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-observability 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-membership 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-identity 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-feature-flags 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-collective 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-coinbase 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-balances 28.0.0
    │   │   │   │   │   │   │       │   ├── pallet-attestations 0.1.0
    │   │   │   │   │   │   │       │   ├── pallet-asset-registry 0.1.0
    │   │   │   │   │   │   │       │   ├── frame-executive 28.0.0
    │   │   │   │   │   │   │       │   └── frame-benchmarking 28.0.0
    │   │   │   │   │   │   │       │       ├── runtime 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-treasury 27.0.0
    │   │   │   │   │   │   │       │       ├── pallet-transaction-payment 28.0.0
    │   │   │   │   │   │   │       │       ├── pallet-timestamp 27.0.0
    │   │   │   │   │   │   │       │       ├── pallet-sudo 28.0.0
    │   │   │   │   │   │   │       │       ├── pallet-shielded-pool 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-settlement 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-oracles 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-observability 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-membership 28.0.0
    │   │   │   │   │   │   │       │       ├── pallet-fee-model 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-feature-flags 0.1.0
    │   │   │   │   │   │   │       │       ├── pallet-collective 28.0.0
    │   │   │   │   │   │   │       │       ├── pallet-balances 28.0.0
    │   │   │   │   │   │   │       │       └── pallet-attestations 0.1.0
    │   │   │   │   │   │   │       ├── frame-executive 28.0.0
    │   │   │   │   │   │   │       └── frame-benchmarking 28.0.0
    │   │   │   │   │   │   ├── sp-consensus-pow 0.32.0
    │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   │   └── consensus 0.1.0
    │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   └── consensus 0.1.0
    │   │   │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   │   │   │   │   │   └── sc-network-sync 0.33.0
    │   │   │   │   │   │   │       ├── sc-service 0.35.0
    │   │   │   │   │   │   │       ├── sc-network-transactions 0.33.0
    │   │   │   │   │   │   │       │   └── sc-service 0.35.0
    │   │   │   │   │   │   │       └── sc-informant 0.33.0
    │   │   │   │   │   │   │           └── sc-service 0.35.0
    │   │   │   │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   │   ├── sc-transaction-pool-api 28.0.0
    │   │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   │   │   │   │   │   │   └── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   ├── sc-network 0.34.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   │   │   │   └── sc-chain-spec 28.0.0
    │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
    │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   │   │   │   ├── sc-network 0.34.0
    │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
    │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── sp-block-builder 26.0.0
    │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   ├── sc-executor 0.32.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── frame-try-runtime 0.34.0
    │   │   │   │   │   │   ├── frame-system-rpc-runtime-api 26.0.0
    │   │   │   │   │   │   │   └── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   │   ├── frame-support 28.0.0
    │   │   │   │   │   │   ├── frame-benchmarking 28.0.0
    │   │   │   │   │   │   └── consensus 0.1.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   ├── sc-executor 0.32.0
    │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   └── frame-system 28.0.0
    │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
    │   │   │   │   │   └── sc-service 0.35.0
    │   │   │   │   ├── sp-transaction-pool 26.0.0
    │   │   │   │   ├── sp-timestamp 26.0.0
    │   │   │   │   │   ├── pallet-timestamp 27.0.0
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── sp-statement-store 10.0.0
    │   │   │   │   ├── sp-staking 26.0.0
    │   │   │   │   │   ├── sp-session 27.0.0
    │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   ├── pallet-session 28.0.0
    │   │   │   │   │   └── frame-support 28.0.0
    │   │   │   │   ├── sp-session 27.0.0
    │   │   │   │   ├── sp-offchain 26.0.0
    │   │   │   │   ├── sp-keyring 31.0.0
    │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   ├── sp-inherents 26.0.0
    │   │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
    │   │   │   │   │   ├── sp-timestamp 26.0.0
    │   │   │   │   │   ├── sp-consensus 0.32.0
    │   │   │   │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   ├── sp-block-builder 26.0.0
    │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   ├── pallet-timestamp 27.0.0
    │   │   │   │   │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │   │   ├── pallet-coinbase 0.1.0
    │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   └── frame-support 28.0.0
    │   │   │   │   ├── sp-genesis-builder 0.8.0
    │   │   │   │   ├── sp-consensus-pow 0.32.0
    │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   │   │   ├── sp-consensus 0.32.0
    │   │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   │   ├── sp-block-builder 26.0.0
    │   │   │   │   ├── sp-api 26.0.0
    │   │   │   │   ├── sc-transaction-pool-api 28.0.0
    │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   ├── sc-network-common 0.33.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   └── sc-network 0.34.0
    │   │   │   │   ├── sc-network 0.34.0
    │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   ├── sc-client-db 0.35.0
    │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   ├── pallet-treasury 27.0.0
    │   │   │   │   ├── pallet-transaction-payment 28.0.0
    │   │   │   │   ├── pallet-timestamp 27.0.0
    │   │   │   │   ├── pallet-sudo 28.0.0
    │   │   │   │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │   ├── pallet-settlement 0.1.0
    │   │   │   │   ├── pallet-session 28.0.0
    │   │   │   │   ├── pallet-oracles 0.1.0
    │   │   │   │   ├── pallet-observability 0.1.0
    │   │   │   │   ├── pallet-membership 28.0.0
    │   │   │   │   ├── pallet-identity 0.1.0
    │   │   │   │   ├── pallet-fee-model 0.1.0
    │   │   │   │   ├── pallet-feature-flags 0.1.0
    │   │   │   │   ├── pallet-difficulty 0.1.0
    │   │   │   │   ├── pallet-collective 28.0.0
    │   │   │   │   ├── pallet-coinbase 0.1.0
    │   │   │   │   ├── pallet-balances 28.0.0
    │   │   │   │   ├── pallet-attestations 0.1.0
    │   │   │   │   ├── pallet-asset-registry 0.1.0
    │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── frame-try-runtime 0.34.0
    │   │   │   │   ├── frame-system 28.0.0
    │   │   │   │   ├── frame-support 28.0.0
    │   │   │   │   ├── frame-executive 28.0.0
    │   │   │   │   ├── frame-benchmarking 28.0.0
    │   │   │   │   └── consensus 0.1.0
    │   │   │   ├── sp-application-crypto 30.0.0
    │   │   │   │   ├── sp-statement-store 10.0.0
    │   │   │   │   ├── sp-runtime 31.0.1
    │   │   │   │   ├── sp-mixnet 0.4.0
    │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   │   │   ├── sc-keystore 25.0.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   └── frame-benchmarking 28.0.0
    │   │   │   ├── sc-sysinfo 27.0.0
    │   │   │   │   └── sc-service 0.35.0
    │   │   │   ├── sc-executor 0.32.0
    │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   ├── runtime 0.1.0
    │   │   │   ├── pallet-transaction-payment 28.0.0
    │   │   │   ├── pallet-sudo 28.0.0
    │   │   │   ├── pallet-shielded-pool 0.1.0
    │   │   │   ├── pallet-settlement 0.1.0
    │   │   │   ├── pallet-session 28.0.0
    │   │   │   ├── pallet-observability 0.1.0
    │   │   │   ├── pallet-membership 28.0.0
    │   │   │   ├── pallet-fee-model 0.1.0
    │   │   │   ├── pallet-feature-flags 0.1.0
    │   │   │   ├── pallet-difficulty 0.1.0
    │   │   │   ├── pallet-collective 28.0.0
    │   │   │   ├── pallet-coinbase 0.1.0
    │   │   │   ├── pallet-attestations 0.1.0
    │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   ├── frame-system 28.0.0
    │   │   │   ├── frame-support 28.0.0
    │   │   │   ├── frame-executive 28.0.0
    │   │   │   └── frame-benchmarking 28.0.0
    │   │   ├── sp-api 26.0.0
    │   │   ├── sc-executor-wasmtime 0.29.0
    │   │   │   └── sc-executor 0.32.0
    │   │   ├── sc-executor 0.32.0
    │   │   └── frame-benchmarking 28.0.0
    │   ├── sc-executor-wasmtime 0.29.0
    │   ├── sc-executor-polkavm 0.29.0
    │   │   └── sc-executor 0.32.0
    │   ├── sc-executor-common 0.29.0
    │   │   ├── sc-executor-wasmtime 0.29.0
    │   │   ├── sc-executor-polkavm 0.29.0
    │   │   └── sc-executor 0.32.0
    │   ├── sc-executor 0.32.0
    │   └── sc-allocator 23.0.0
    │       ├── sc-executor-wasmtime 0.29.0
    │       └── sc-executor-common 0.29.0
    └── sc-executor-wasmtime 0.29.0
    
    Crate:     atty
    Version:   0.2.14
    Warning:   unmaintained
    Title:     `atty` is unmaintained
    Date:      2024-09-25
    ID:        RUSTSEC-2024-0375
    URL:       https://rustsec.org/advisories/RUSTSEC-2024-0375
    Dependency tree:
    atty 0.2.14
    └── hegemon-node 0.3.0-alpha
        └── security-tests 0.1.0
    
    Crate:     derivative
    Version:   2.2.0
    Warning:   unmaintained
    Title:     `derivative` is unmaintained; consider using an alternative
    Date:      2024-06-26
    ID:        RUSTSEC-2024-0388
    URL:       https://rustsec.org/advisories/RUSTSEC-2024-0388
    Dependency tree:
    derivative 2.2.0
    ├── ark-poly 0.4.2
    │   └── ark-ec 0.4.2
    │       ├── w3f-bls 0.1.9
    │       │   └── sp-core 28.0.0
    │       │       ├── substrate-frame-rpc-system 28.0.0
    │       │       │   └── hegemon-node 0.3.0-alpha
    │       │       │       └── security-tests 0.1.0
    │       │       ├── sp-trie 29.0.0
    │       │       │   ├── sp-transaction-storage-proof 26.0.0
    │       │       │   │   └── sc-service 0.35.0
    │       │       │   │       ├── sc-cli 0.36.0
    │       │       │   │       │   └── hegemon-node 0.3.0-alpha
    │       │       │   │       └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sp-state-machine 0.35.0
    │       │       │   │   ├── sp-io 30.0.0
    │       │       │   │   │   ├── sp-runtime 31.0.1
    │       │       │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   ├── sp-version 29.0.0
    │       │       │   │   │   │   │   ├── sp-api 26.0.0
    │       │       │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   ├── sp-transaction-pool 26.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       └── consensus 0.1.0
    │       │       │   │   │   │   │   │   │           ├── security-tests 0.1.0
    │       │       │   │   │   │   │   │   │           └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── sp-statement-store 10.0.0
    │       │       │   │   │   │   │   │   │   └── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │       ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │       ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   │       │   └── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │       └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── sp-session 27.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │   └── pallet-session 28.0.0
    │       │       │   │   │   │   │   │   │       └── runtime 0.1.0
    │       │       │   │   │   │   │   │   ├── sp-offchain 26.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   ├── sp-mixnet 0.4.0
    │       │       │   │   │   │   │   │   │   └── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   │       ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   │   │   │       │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── sc-rpc-server 11.0.0
    │       │       │   │   │   │   │   │   │       │   │   └── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │       │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │       └── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   ├── sp-genesis-builder 0.8.0
    │       │       │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │   └── frame-support 28.0.0
    │       │       │   │   │   │   │   │   │       ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-treasury 27.0.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-transaction-payment 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │       │       │   │   │   │   │   │   │       │   │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       ├── pallet-sudo 28.0.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       ├── pallet-settlement 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-session 28.0.0
    │       │       │   │   │   │   │   │   │       ├── pallet-oracles 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-observability 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-membership 28.0.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-identity 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── pallet-asset-registry 0.1.0
    │       │       │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-feature-flags 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-difficulty 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-collective 28.0.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-coinbase 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       ├── pallet-balances 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── pallet-coinbase 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-attestations 0.1.0
    │       │       │   │   │   │   │   │   │       │   └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── pallet-asset-registry 0.1.0
    │       │       │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │       ├── frame-try-runtime 0.34.0
    │       │       │   │   │   │   │   │   │       │   └── frame-executive 28.0.0
    │       │       │   │   │   │   │   │   │       │       └── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       ├── frame-system 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-transaction-payment 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-sudo 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-observability 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-membership 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-identity 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-feature-flags 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-collective 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-coinbase 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-balances 28.0.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-attestations 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── pallet-asset-registry 0.1.0
    │       │       │   │   │   │   │   │   │       │   ├── frame-executive 28.0.0
    │       │       │   │   │   │   │   │   │       │   └── frame-benchmarking 28.0.0
    │       │       │   │   │   │   │   │   │       │       ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-treasury 27.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-transaction-payment 28.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-sudo 28.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-settlement 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-oracles 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-observability 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-membership 28.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-feature-flags 0.1.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-collective 28.0.0
    │       │       │   │   │   │   │   │   │       │       ├── pallet-balances 28.0.0
    │       │       │   │   │   │   │   │   │       │       └── pallet-attestations 0.1.0
    │       │       │   │   │   │   │   │   │       ├── frame-executive 28.0.0
    │       │       │   │   │   │   │   │   │       └── frame-benchmarking 28.0.0
    │       │       │   │   │   │   │   │   ├── sp-consensus-pow 0.32.0
    │       │       │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   │   └── consensus 0.1.0
    │       │       │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   └── consensus 0.1.0
    │       │       │   │   │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │       │       │   │   │   │   │   │   │   └── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   │       ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │       ├── sc-network-transactions 0.33.0
    │       │       │   │   │   │   │   │   │       │   └── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │       └── sc-informant 0.33.0
    │       │       │   │   │   │   │   │   │           └── sc-service 0.35.0
    │       │       │   │   │   │   │   │   ├── sp-blockchain 28.0.0
    │       │       │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-transaction-pool-api 28.0.0
    │       │       │   │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-network 0.34.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   │   │   │   └── sc-chain-spec 28.0.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-network 0.34.0
    │       │       │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
    │       │       │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── sp-block-builder 26.0.0
    │       │       │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │       │       │   │   │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │       │       │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   ├── sc-executor 0.32.0
    │       │       │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   │   │   ├── sc-block-builder 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   │   ├── frame-try-runtime 0.34.0
    │       │       │   │   │   │   │   │   ├── frame-system-rpc-runtime-api 26.0.0
    │       │       │   │   │   │   │   │   │   └── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   │   ├── frame-support 28.0.0
    │       │       │   │   │   │   │   │   ├── frame-benchmarking 28.0.0
    │       │       │   │   │   │   │   │   └── consensus 0.1.0
    │       │       │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   ├── sc-executor 0.32.0
    │       │       │   │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   └── frame-system 28.0.0
    │       │       │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
    │       │       │   │   │   │   ├── sp-transaction-pool 26.0.0
    │       │       │   │   │   │   ├── sp-timestamp 26.0.0
    │       │       │   │   │   │   │   ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   ├── sp-statement-store 10.0.0
    │       │       │   │   │   │   ├── sp-staking 26.0.0
    │       │       │   │   │   │   │   ├── sp-session 27.0.0
    │       │       │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   ├── pallet-session 28.0.0
    │       │       │   │   │   │   │   └── frame-support 28.0.0
    │       │       │   │   │   │   ├── sp-session 27.0.0
    │       │       │   │   │   │   ├── sp-offchain 26.0.0
    │       │       │   │   │   │   ├── sp-keyring 31.0.0
    │       │       │   │   │   │   │   └── sc-cli 0.36.0
    │       │       │   │   │   │   ├── sp-inherents 26.0.0
    │       │       │   │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
    │       │       │   │   │   │   │   ├── sp-timestamp 26.0.0
    │       │       │   │   │   │   │   ├── sp-consensus 0.32.0
    │       │       │   │   │   │   │   │   ├── sp-blockchain 28.0.0
    │       │       │   │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │       │       │   │   │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   ├── sp-block-builder 26.0.0
    │       │       │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   │   ├── sc-block-builder 0.33.0
    │       │       │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   │   ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   │   ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   │   ├── pallet-coinbase 0.1.0
    │       │       │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   │   └── frame-support 28.0.0
    │       │       │   │   │   │   ├── sp-genesis-builder 0.8.0
    │       │       │   │   │   │   ├── sp-consensus-pow 0.32.0
    │       │       │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │       │       │   │   │   │   ├── sp-consensus 0.32.0
    │       │       │   │   │   │   ├── sp-blockchain 28.0.0
    │       │       │   │   │   │   ├── sp-block-builder 26.0.0
    │       │       │   │   │   │   ├── sp-api 26.0.0
    │       │       │   │   │   │   ├── sc-transaction-pool-api 28.0.0
    │       │       │   │   │   │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   │   │   ├── sc-tracing 28.0.0
    │       │       │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   ├── sc-network-light 0.33.0
    │       │       │   │   │   │   ├── sc-network-common 0.33.0
    │       │       │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   │   │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   │   │   │   └── sc-network 0.34.0
    │       │       │   │   │   │   ├── sc-network 0.34.0
    │       │       │   │   │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   │   ├── sc-informant 0.33.0
    │       │       │   │   │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   │   │   ├── sc-consensus 0.33.0
    │       │       │   │   │   │   ├── sc-client-db 0.35.0
    │       │       │   │   │   │   ├── sc-client-api 28.0.0
    │       │       │   │   │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   │   ├── sc-block-builder 0.33.0
    │       │       │   │   │   │   ├── sc-basic-authorship 0.34.0
    │       │       │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   ├── pallet-treasury 27.0.0
    │       │       │   │   │   │   ├── pallet-transaction-payment 28.0.0
    │       │       │   │   │   │   ├── pallet-timestamp 27.0.0
    │       │       │   │   │   │   ├── pallet-sudo 28.0.0
    │       │       │   │   │   │   ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   │   ├── pallet-settlement 0.1.0
    │       │       │   │   │   │   ├── pallet-session 28.0.0
    │       │       │   │   │   │   ├── pallet-oracles 0.1.0
    │       │       │   │   │   │   ├── pallet-observability 0.1.0
    │       │       │   │   │   │   ├── pallet-membership 28.0.0
    │       │       │   │   │   │   ├── pallet-identity 0.1.0
    │       │       │   │   │   │   ├── pallet-fee-model 0.1.0
    │       │       │   │   │   │   ├── pallet-feature-flags 0.1.0
    │       │       │   │   │   │   ├── pallet-difficulty 0.1.0
    │       │       │   │   │   │   ├── pallet-collective 28.0.0
    │       │       │   │   │   │   ├── pallet-coinbase 0.1.0
    │       │       │   │   │   │   ├── pallet-balances 28.0.0
    │       │       │   │   │   │   ├── pallet-attestations 0.1.0
    │       │       │   │   │   │   ├── pallet-asset-registry 0.1.0
    │       │       │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   ├── frame-try-runtime 0.34.0
    │       │       │   │   │   │   ├── frame-system 28.0.0
    │       │       │   │   │   │   ├── frame-support 28.0.0
    │       │       │   │   │   │   ├── frame-executive 28.0.0
    │       │       │   │   │   │   ├── frame-benchmarking 28.0.0
    │       │       │   │   │   │   └── consensus 0.1.0
    │       │       │   │   │   ├── sp-application-crypto 30.0.0
    │       │       │   │   │   │   ├── sp-statement-store 10.0.0
    │       │       │   │   │   │   ├── sp-runtime 31.0.1
    │       │       │   │   │   │   ├── sp-mixnet 0.4.0
    │       │       │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │       │       │   │   │   │   ├── sc-keystore 25.0.0
    │       │       │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   └── sc-cli 0.36.0
    │       │       │   │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   │   └── frame-benchmarking 28.0.0
    │       │       │   │   │   ├── sc-sysinfo 27.0.0
    │       │       │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   ├── sc-executor 0.32.0
    │       │       │   │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   │   ├── runtime 0.1.0
    │       │       │   │   │   ├── pallet-transaction-payment 28.0.0
    │       │       │   │   │   ├── pallet-sudo 28.0.0
    │       │       │   │   │   ├── pallet-shielded-pool 0.1.0
    │       │       │   │   │   ├── pallet-settlement 0.1.0
    │       │       │   │   │   ├── pallet-session 28.0.0
    │       │       │   │   │   ├── pallet-observability 0.1.0
    │       │       │   │   │   ├── pallet-membership 28.0.0
    │       │       │   │   │   ├── pallet-fee-model 0.1.0
    │       │       │   │   │   ├── pallet-feature-flags 0.1.0
    │       │       │   │   │   ├── pallet-difficulty 0.1.0
    │       │       │   │   │   ├── pallet-collective 28.0.0
    │       │       │   │   │   ├── pallet-coinbase 0.1.0
    │       │       │   │   │   ├── pallet-attestations 0.1.0
    │       │       │   │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   │   ├── frame-system 28.0.0
    │       │       │   │   │   ├── frame-support 28.0.0
    │       │       │   │   │   ├── frame-executive 28.0.0
    │       │       │   │   │   └── frame-benchmarking 28.0.0
    │       │       │   │   ├── sp-consensus 0.32.0
    │       │       │   │   ├── sp-blockchain 28.0.0
    │       │       │   │   ├── sp-api 26.0.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-consensus 0.33.0
    │       │       │   │   ├── sc-client-db 0.35.0
    │       │       │   │   ├── sc-client-api 28.0.0
    │       │       │   │   ├── sc-chain-spec 28.0.0
    │       │       │   │   ├── pallet-session 28.0.0
    │       │       │   │   └── frame-support 28.0.0
    │       │       │   ├── sp-runtime 31.0.1
    │       │       │   ├── sp-io 30.0.0
    │       │       │   ├── sp-api 26.0.0
    │       │       │   ├── sc-service 0.35.0
    │       │       │   ├── sc-executor 0.32.0
    │       │       │   ├── sc-client-db 0.35.0
    │       │       │   ├── sc-client-api 28.0.0
    │       │       │   ├── sc-block-builder 0.33.0
    │       │       │   ├── sc-basic-authorship 0.34.0
    │       │       │   ├── pallet-session 28.0.0
    │       │       │   └── frame-support 28.0.0
    │       │       ├── sp-transaction-storage-proof 26.0.0
    │       │       ├── sp-statement-store 10.0.0
    │       │       ├── sp-state-machine 0.35.0
    │       │       ├── sp-staking 26.0.0
    │       │       ├── sp-session 27.0.0
    │       │       ├── sp-runtime 31.0.1
    │       │       ├── sp-rpc 26.0.0
    │       │       │   ├── sc-tracing 28.0.0
    │       │       │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   ├── sc-rpc-api 0.33.0
    │       │       │   └── sc-rpc 29.0.0
    │       │       ├── sp-offchain 26.0.0
    │       │       ├── sp-keystore 0.34.0
    │       │       │   ├── sp-session 27.0.0
    │       │       │   ├── sp-io 30.0.0
    │       │       │   ├── sp-consensus-grandpa 13.0.0
    │       │       │   ├── sc-service 0.35.0
    │       │       │   ├── sc-rpc 29.0.0
    │       │       │   ├── sc-mixnet 0.4.0
    │       │       │   ├── sc-keystore 25.0.0
    │       │       │   ├── sc-cli 0.36.0
    │       │       │   └── hegemon-node 0.3.0-alpha
    │       │       ├── sp-keyring 31.0.0
    │       │       ├── sp-io 30.0.0
    │       │       ├── sp-consensus-pow 0.32.0
    │       │       ├── sp-consensus-grandpa 13.0.0
    │       │       ├── sp-blockchain 28.0.0
    │       │       ├── sp-application-crypto 30.0.0
    │       │       ├── sp-api 26.0.0
    │       │       ├── security-tests 0.1.0
    │       │       ├── sc-transaction-pool-api 28.0.0
    │       │       ├── sc-transaction-pool 28.0.0
    │       │       ├── sc-tracing 28.0.0
    │       │       ├── sc-sysinfo 27.0.0
    │       │       ├── sc-state-db 0.30.0
    │       │       │   └── sc-client-db 0.35.0
    │       │       ├── sc-service 0.35.0
    │       │       ├── sc-rpc-spec-v2 0.34.0
    │       │       ├── sc-rpc-api 0.33.0
    │       │       ├── sc-rpc 29.0.0
    │       │       ├── sc-network-sync 0.33.0
    │       │       ├── sc-network-light 0.33.0
    │       │       ├── sc-network 0.34.0
    │       │       ├── sc-mixnet 0.4.0
    │       │       ├── sc-keystore 25.0.0
    │       │       ├── sc-executor 0.32.0
    │       │       ├── sc-consensus-pow 0.33.0
    │       │       ├── sc-consensus 0.33.0
    │       │       ├── sc-client-db 0.35.0
    │       │       ├── sc-client-api 28.0.0
    │       │       ├── sc-cli 0.36.0
    │       │       ├── sc-chain-spec 28.0.0
    │       │       ├── sc-block-builder 0.33.0
    │       │       ├── sc-basic-authorship 0.34.0
    │       │       ├── sc-allocator 23.0.0
    │       │       │   ├── sc-executor-wasmtime 0.29.0
    │       │       │   │   └── sc-executor 0.32.0
    │       │       │   └── sc-executor-common 0.29.0
    │       │       │       ├── sc-executor-wasmtime 0.29.0
    │       │       │       ├── sc-executor-polkavm 0.29.0
    │       │       │       │   └── sc-executor 0.32.0
    │       │       │       └── sc-executor 0.32.0
    │       │       ├── runtime 0.1.0
    │       │       ├── pallet-treasury 27.0.0
    │       │       ├── pallet-shielded-pool 0.1.0
    │       │       ├── pallet-settlement 0.1.0
    │       │       ├── pallet-session 28.0.0
    │       │       ├── pallet-membership 28.0.0
    │       │       ├── pallet-difficulty 0.1.0
    │       │       ├── pallet-collective 28.0.0
    │       │       ├── pallet-coinbase 0.1.0
    │       │       ├── pallet-balances 28.0.0
    │       │       ├── hegemon-node 0.3.0-alpha
    │       │       ├── frame-system 28.0.0
    │       │       ├── frame-support 28.0.0
    │       │       ├── frame-executive 28.0.0
    │       │       ├── frame-benchmarking 28.0.0
    │       │       └── consensus 0.1.0
    │       ├── ark-bls12-381 0.4.0
    │       │   └── w3f-bls 0.1.9
    │       └── ark-bls12-377 0.4.0
    │           └── w3f-bls 0.1.9
    ├── ark-ff 0.4.2
    │   ├── w3f-bls 0.1.9
    │   ├── ark-poly 0.4.2
    │   ├── ark-ec 0.4.2
    │   ├── ark-bls12-381 0.4.0
    │   └── ark-bls12-377 0.4.0
    └── ark-ec 0.4.2
    
    Crate:     fxhash
    Version:   0.2.1
    Warning:   unmaintained
    Title:     fxhash - no longer maintained
    Date:      2025-09-05
    ID:        RUSTSEC-2025-0057
    URL:       https://rustsec.org/advisories/RUSTSEC-2025-0057
    Dependency tree:
    fxhash 0.2.1
    ├── sled 0.34.7
    │   └── hegemon-node 0.3.0-alpha
    │       └── security-tests 0.1.0
    └── fxprof-processed-profile 0.6.0
        └── wasmtime 35.0.0
            ├── sp-wasm-interface 20.0.0
            │   ├── sp-runtime-interface 24.0.0
            │   │   ├── sp-statement-store 10.0.0
            │   │   │   └── sc-rpc 29.0.0
            │   │   │       ├── sc-service 0.35.0
            │   │   │       │   ├── sc-cli 0.36.0
            │   │   │       │   │   └── hegemon-node 0.3.0-alpha
            │   │   │       │   └── hegemon-node 0.3.0-alpha
            │   │   │       ├── sc-rpc-spec-v2 0.34.0
            │   │   │       │   └── sc-service 0.35.0
            │   │   │       └── hegemon-node 0.3.0-alpha
            │   │   ├── sp-io 30.0.0
            │   │   │   ├── sp-runtime 31.0.1
            │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   ├── sp-version 29.0.0
            │   │   │   │   │   ├── sp-api 26.0.0
            │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   ├── sp-transaction-pool 26.0.0
            │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       └── consensus 0.1.0
            │   │   │   │   │   │   │           ├── security-tests 0.1.0
            │   │   │   │   │   │   │           └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   ├── sp-statement-store 10.0.0
            │   │   │   │   │   │   ├── sp-session 27.0.0
            │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   │   │   └── pallet-session 28.0.0
            │   │   │   │   │   │   │       └── runtime 0.1.0
            │   │   │   │   │   │   ├── sp-offchain 26.0.0
            │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   └── runtime 0.1.0
            │   │   │   │   │   │   ├── sp-mixnet 0.4.0
            │   │   │   │   │   │   │   └── sc-mixnet 0.4.0
            │   │   │   │   │   │   │       ├── sc-rpc-api 0.33.0
            │   │   │   │   │   │   │       │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   │       │   ├── sc-rpc-server 11.0.0
            │   │   │   │   │   │   │       │   │   └── sc-service 0.35.0
            │   │   │   │   │   │   │       │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │       └── sc-cli 0.36.0
            │   │   │   │   │   │   ├── sp-genesis-builder 0.8.0
            │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
            │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   │   │   └── frame-support 28.0.0
            │   │   │   │   │   │   │       ├── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-treasury 27.0.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-transaction-payment 28.0.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   └── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       │       └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-timestamp 27.0.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
            │   │   │   │   │   │   │       │   │   └── runtime 0.1.0
            │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       ├── pallet-sudo 28.0.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-shielded-pool 0.1.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       ├── pallet-settlement 0.1.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-session 28.0.0
            │   │   │   │   │   │   │       ├── pallet-oracles 0.1.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-observability 0.1.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-membership 28.0.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-identity 0.1.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       │   └── pallet-asset-registry 0.1.0
            │   │   │   │   │   │   │       │       └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       ├── pallet-feature-flags 0.1.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-difficulty 0.1.0
            │   │   │   │   │   │   │       ├── pallet-collective 28.0.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-coinbase 0.1.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       ├── pallet-balances 28.0.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
            │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       │   └── pallet-coinbase 0.1.0
            │   │   │   │   │   │   │       ├── pallet-attestations 0.1.0
            │   │   │   │   │   │   │       │   └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── pallet-asset-registry 0.1.0
            │   │   │   │   │   │   │       ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │       ├── frame-try-runtime 0.34.0
            │   │   │   │   │   │   │       │   └── frame-executive 28.0.0
            │   │   │   │   │   │   │       │       └── runtime 0.1.0
            │   │   │   │   │   │   │       ├── frame-system 28.0.0
            │   │   │   │   │   │   │       │   ├── runtime 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-treasury 27.0.0
            │   │   │   │   │   │   │       │   ├── pallet-transaction-payment 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-timestamp 27.0.0
            │   │   │   │   │   │   │       │   ├── pallet-sudo 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-settlement 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-session 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-oracles 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-observability 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-membership 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-identity 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-feature-flags 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-difficulty 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-collective 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-coinbase 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-balances 28.0.0
            │   │   │   │   │   │   │       │   ├── pallet-attestations 0.1.0
            │   │   │   │   │   │   │       │   ├── pallet-asset-registry 0.1.0
            │   │   │   │   │   │   │       │   ├── frame-executive 28.0.0
            │   │   │   │   │   │   │       │   └── frame-benchmarking 28.0.0
            │   │   │   │   │   │   │       │       ├── runtime 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-treasury 27.0.0
            │   │   │   │   │   │   │       │       ├── pallet-transaction-payment 28.0.0
            │   │   │   │   │   │   │       │       ├── pallet-timestamp 27.0.0
            │   │   │   │   │   │   │       │       ├── pallet-sudo 28.0.0
            │   │   │   │   │   │   │       │       ├── pallet-shielded-pool 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-settlement 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-oracles 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-observability 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-membership 28.0.0
            │   │   │   │   │   │   │       │       ├── pallet-fee-model 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-feature-flags 0.1.0
            │   │   │   │   │   │   │       │       ├── pallet-collective 28.0.0
            │   │   │   │   │   │   │       │       ├── pallet-balances 28.0.0
            │   │   │   │   │   │   │       │       └── pallet-attestations 0.1.0
            │   │   │   │   │   │   │       ├── frame-executive 28.0.0
            │   │   │   │   │   │   │       └── frame-benchmarking 28.0.0
            │   │   │   │   │   │   ├── sp-consensus-pow 0.32.0
            │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   │   └── consensus 0.1.0
            │   │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   └── consensus 0.1.0
            │   │   │   │   │   │   ├── sp-consensus-grandpa 13.0.0
            │   │   │   │   │   │   │   └── sc-network-sync 0.33.0
            │   │   │   │   │   │   │       ├── sc-service 0.35.0
            │   │   │   │   │   │   │       ├── sc-network-transactions 0.33.0
            │   │   │   │   │   │   │       │   └── sc-service 0.35.0
            │   │   │   │   │   │   │       └── sc-informant 0.33.0
            │   │   │   │   │   │   │           └── sc-service 0.35.0
            │   │   │   │   │   │   ├── sp-blockchain 28.0.0
            │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   │   ├── sc-transaction-pool-api 28.0.0
            │   │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   │   │   │   ├── sc-rpc-api 0.33.0
            │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
            │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
            │   │   │   │   │   │   │   │   │   │   └── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   ├── sc-network 0.34.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   │   │   │   │   │   │   └── sc-chain-spec 28.0.0
            │   │   │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   │   │   │   │   │   ├── sc-informant 0.33.0
            │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
            │   │   │   │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   │   │   │   └── sc-cli 0.36.0
            │   │   │   │   │   │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   │   │   │   ├── sc-tracing 28.0.0
            │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
            │   │   │   │   │   │   │   ├── sc-network 0.34.0
            │   │   │   │   │   │   │   ├── sc-informant 0.33.0
            │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   │   ├── sc-consensus 0.33.0
            │   │   │   │   │   │   │   ├── sc-client-db 0.35.0
            │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
            │   │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   ├── sp-block-builder 26.0.0
            │   │   │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   │   ├── sc-block-builder 0.33.0
            │   │   │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   │   │   ├── sc-tracing 28.0.0
            │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   │   │   ├── sc-executor 0.32.0
            │   │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   │   │   ├── sc-block-builder 0.33.0
            │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   │   ├── frame-try-runtime 0.34.0
            │   │   │   │   │   │   ├── frame-system-rpc-runtime-api 26.0.0
            │   │   │   │   │   │   │   └── substrate-frame-rpc-system 28.0.0
            │   │   │   │   │   │   ├── frame-support 28.0.0
            │   │   │   │   │   │   ├── frame-benchmarking 28.0.0
            │   │   │   │   │   │   └── consensus 0.1.0
            │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   │   ├── sc-rpc-api 0.33.0
            │   │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   │   ├── sc-executor 0.32.0
            │   │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   └── frame-system 28.0.0
            │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
            │   │   │   │   │   └── sc-service 0.35.0
            │   │   │   │   ├── sp-transaction-pool 26.0.0
            │   │   │   │   ├── sp-timestamp 26.0.0
            │   │   │   │   │   ├── pallet-timestamp 27.0.0
            │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   ├── sp-statement-store 10.0.0
            │   │   │   │   ├── sp-staking 26.0.0
            │   │   │   │   │   ├── sp-session 27.0.0
            │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   ├── pallet-session 28.0.0
            │   │   │   │   │   └── frame-support 28.0.0
            │   │   │   │   ├── sp-session 27.0.0
            │   │   │   │   ├── sp-offchain 26.0.0
            │   │   │   │   ├── sp-keyring 31.0.0
            │   │   │   │   │   └── sc-cli 0.36.0
            │   │   │   │   ├── sp-inherents 26.0.0
            │   │   │   │   │   ├── sp-transaction-storage-proof 26.0.0
            │   │   │   │   │   ├── sp-timestamp 26.0.0
            │   │   │   │   │   ├── sp-consensus 0.32.0
            │   │   │   │   │   │   ├── sp-blockchain 28.0.0
            │   │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
            │   │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   │   ├── sc-consensus 0.33.0
            │   │   │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
            │   │   │   │   │   ├── sp-block-builder 26.0.0
            │   │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   │   ├── sc-block-builder 0.33.0
            │   │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   │   ├── pallet-timestamp 27.0.0
            │   │   │   │   │   ├── pallet-shielded-pool 0.1.0
            │   │   │   │   │   ├── pallet-coinbase 0.1.0
            │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   │   │   └── frame-support 28.0.0
            │   │   │   │   ├── sp-genesis-builder 0.8.0
            │   │   │   │   ├── sp-consensus-pow 0.32.0
            │   │   │   │   ├── sp-consensus-grandpa 13.0.0
            │   │   │   │   ├── sp-consensus 0.32.0
            │   │   │   │   ├── sp-blockchain 28.0.0
            │   │   │   │   ├── sp-block-builder 26.0.0
            │   │   │   │   ├── sp-api 26.0.0
            │   │   │   │   ├── sc-transaction-pool-api 28.0.0
            │   │   │   │   ├── sc-transaction-pool 28.0.0
            │   │   │   │   ├── sc-tracing 28.0.0
            │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
            │   │   │   │   ├── sc-rpc-api 0.33.0
            │   │   │   │   ├── sc-rpc 29.0.0
            │   │   │   │   ├── sc-network-transactions 0.33.0
            │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   ├── sc-network-light 0.33.0
            │   │   │   │   ├── sc-network-common 0.33.0
            │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   ├── sc-network-transactions 0.33.0
            │   │   │   │   │   ├── sc-network-sync 0.33.0
            │   │   │   │   │   └── sc-network 0.34.0
            │   │   │   │   ├── sc-network 0.34.0
            │   │   │   │   ├── sc-mixnet 0.4.0
            │   │   │   │   ├── sc-informant 0.33.0
            │   │   │   │   ├── sc-consensus-pow 0.33.0
            │   │   │   │   ├── sc-consensus 0.33.0
            │   │   │   │   ├── sc-client-db 0.35.0
            │   │   │   │   ├── sc-client-api 28.0.0
            │   │   │   │   ├── sc-cli 0.36.0
            │   │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   │   ├── sc-block-builder 0.33.0
            │   │   │   │   ├── sc-basic-authorship 0.34.0
            │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   ├── pallet-treasury 27.0.0
            │   │   │   │   ├── pallet-transaction-payment 28.0.0
            │   │   │   │   ├── pallet-timestamp 27.0.0
            │   │   │   │   ├── pallet-sudo 28.0.0
            │   │   │   │   ├── pallet-shielded-pool 0.1.0
            │   │   │   │   ├── pallet-settlement 0.1.0
            │   │   │   │   ├── pallet-session 28.0.0
            │   │   │   │   ├── pallet-oracles 0.1.0
            │   │   │   │   ├── pallet-observability 0.1.0
            │   │   │   │   ├── pallet-membership 28.0.0
            │   │   │   │   ├── pallet-identity 0.1.0
            │   │   │   │   ├── pallet-fee-model 0.1.0
            │   │   │   │   ├── pallet-feature-flags 0.1.0
            │   │   │   │   ├── pallet-difficulty 0.1.0
            │   │   │   │   ├── pallet-collective 28.0.0
            │   │   │   │   ├── pallet-coinbase 0.1.0
            │   │   │   │   ├── pallet-balances 28.0.0
            │   │   │   │   ├── pallet-attestations 0.1.0
            │   │   │   │   ├── pallet-asset-registry 0.1.0
            │   │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   │   ├── frame-try-runtime 0.34.0
            │   │   │   │   ├── frame-system 28.0.0
            │   │   │   │   ├── frame-support 28.0.0
            │   │   │   │   ├── frame-executive 28.0.0
            │   │   │   │   ├── frame-benchmarking 28.0.0
            │   │   │   │   └── consensus 0.1.0
            │   │   │   ├── sp-application-crypto 30.0.0
            │   │   │   │   ├── sp-statement-store 10.0.0
            │   │   │   │   ├── sp-runtime 31.0.1
            │   │   │   │   ├── sp-mixnet 0.4.0
            │   │   │   │   ├── sp-consensus-grandpa 13.0.0
            │   │   │   │   ├── sc-keystore 25.0.0
            │   │   │   │   │   ├── sc-service 0.35.0
            │   │   │   │   │   └── sc-cli 0.36.0
            │   │   │   │   ├── runtime 0.1.0
            │   │   │   │   └── frame-benchmarking 28.0.0
            │   │   │   ├── sc-sysinfo 27.0.0
            │   │   │   │   └── sc-service 0.35.0
            │   │   │   ├── sc-executor 0.32.0
            │   │   │   ├── sc-chain-spec 28.0.0
            │   │   │   ├── runtime 0.1.0
            │   │   │   ├── pallet-transaction-payment 28.0.0
            │   │   │   ├── pallet-sudo 28.0.0
            │   │   │   ├── pallet-shielded-pool 0.1.0
            │   │   │   ├── pallet-settlement 0.1.0
            │   │   │   ├── pallet-session 28.0.0
            │   │   │   ├── pallet-observability 0.1.0
            │   │   │   ├── pallet-membership 28.0.0
            │   │   │   ├── pallet-fee-model 0.1.0
            │   │   │   ├── pallet-feature-flags 0.1.0
            │   │   │   ├── pallet-difficulty 0.1.0
            │   │   │   ├── pallet-collective 28.0.0
            │   │   │   ├── pallet-coinbase 0.1.0
            │   │   │   ├── pallet-attestations 0.1.0
            │   │   │   ├── hegemon-node 0.3.0-alpha
            │   │   │   ├── frame-system 28.0.0
            │   │   │   ├── frame-support 28.0.0
            │   │   │   ├── frame-executive 28.0.0
            │   │   │   └── frame-benchmarking 28.0.0
            │   │   ├── sp-api 26.0.0
            │   │   ├── sc-executor-wasmtime 0.29.0
            │   │   │   └── sc-executor 0.32.0
            │   │   ├── sc-executor 0.32.0
            │   │   └── frame-benchmarking 28.0.0
            │   ├── sc-executor-wasmtime 0.29.0
            │   ├── sc-executor-polkavm 0.29.0
            │   │   └── sc-executor 0.32.0
            │   ├── sc-executor-common 0.29.0
            │   │   ├── sc-executor-wasmtime 0.29.0
            │   │   ├── sc-executor-polkavm 0.29.0
            │   │   └── sc-executor 0.32.0
            │   ├── sc-executor 0.32.0
            │   └── sc-allocator 23.0.0
            │       ├── sc-executor-wasmtime 0.29.0
            │       └── sc-executor-common 0.29.0
            └── sc-executor-wasmtime 0.29.0
    
    Crate:     instant
    Version:   0.1.13
    Warning:   unmaintained
    Title:     `instant` is unmaintained
    Date:      2024-09-01
    ID:        RUSTSEC-2024-0384
    URL:       https://rustsec.org/advisories/RUSTSEC-2024-0384
    Dependency tree:
    instant 0.1.13
    ├── parking_lot_core 0.8.6
    │   └── parking_lot 0.11.2
    │       ├── wasm-timer 0.2.5
    │       │   ├── sc-telemetry 15.0.0
    │       │   │   ├── sc-sysinfo 27.0.0
    │       │   │   │   └── sc-service 0.35.0
    │       │   │   │       ├── sc-cli 0.36.0
    │       │   │   │       │   └── hegemon-node 0.3.0-alpha
    │       │   │   │       │       └── security-tests 0.1.0
    │       │   │   │       └── hegemon-node 0.3.0-alpha
    │       │   │   ├── sc-service 0.35.0
    │       │   │   ├── sc-cli 0.36.0
    │       │   │   ├── sc-chain-spec 28.0.0
    │       │   │   │   ├── sc-service 0.35.0
    │       │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │   │   │   │   └── sc-service 0.35.0
    │       │   │   │   ├── sc-rpc-api 0.33.0
    │       │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │   │   │   │   ├── sc-rpc-server 11.0.0
    │       │   │   │   │   │   └── sc-service 0.35.0
    │       │   │   │   │   ├── sc-rpc 29.0.0
    │       │   │   │   │   │   ├── sc-service 0.35.0
    │       │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │   │   │   ├── sc-rpc 29.0.0
    │       │   │   │   └── hegemon-node 0.3.0-alpha
    │       │   │   └── sc-basic-authorship 0.34.0
    │       │   │       └── hegemon-node 0.3.0-alpha
    │       │   └── sc-network 0.34.0
    │       │       ├── sc-service 0.35.0
    │       │       ├── sc-network-transactions 0.33.0
    │       │       │   └── sc-service 0.35.0
    │       │       ├── sc-network-sync 0.33.0
    │       │       │   ├── sc-service 0.35.0
    │       │       │   ├── sc-network-transactions 0.33.0
    │       │       │   └── sc-informant 0.33.0
    │       │       │       └── sc-service 0.35.0
    │       │       ├── sc-network-light 0.33.0
    │       │       │   └── sc-service 0.35.0
    │       │       ├── sc-mixnet 0.4.0
    │       │       │   ├── sc-rpc-api 0.33.0
    │       │       │   ├── sc-rpc 29.0.0
    │       │       │   └── sc-cli 0.36.0
    │       │       ├── sc-informant 0.33.0
    │       │       ├── sc-cli 0.36.0
    │       │       └── sc-chain-spec 28.0.0
    │       └── sled 0.34.7
    │           └── hegemon-node 0.3.0-alpha
    └── parking_lot 0.11.2
    
    Crate:     parity-wasm
    Version:   0.45.0
    Warning:   unmaintained
    Title:     Crate `parity-wasm` deprecated by the author
    Date:      2022-10-01
    ID:        RUSTSEC-2022-0061
    URL:       https://rustsec.org/advisories/RUSTSEC-2022-0061
    Dependency tree:
    parity-wasm 0.45.0
    ├── wasm-instrument 0.4.0
    │   └── sc-executor-common 0.29.0
    │       ├── sc-executor-wasmtime 0.29.0
    │       │   └── sc-executor 0.32.0
    │       │       ├── sc-service 0.35.0
    │       │       │   ├── sc-cli 0.36.0
    │       │       │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │       └── security-tests 0.1.0
    │       │       │   └── hegemon-node 0.3.0-alpha
    │       │       ├── sc-client-api 28.0.0
    │       │       │   ├── sc-transaction-pool 28.0.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-cli 0.36.0
    │       │       │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-tracing 28.0.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   └── sc-cli 0.36.0
    │       │       │   ├── sc-service 0.35.0
    │       │       │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   ├── sc-rpc 29.0.0
    │       │       │   ├── sc-network-sync 0.33.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   │   └── sc-service 0.35.0
    │       │       │   │   └── sc-informant 0.33.0
    │       │       │   │       └── sc-service 0.35.0
    │       │       │   ├── sc-network-light 0.33.0
    │       │       │   │   └── sc-service 0.35.0
    │       │       │   ├── sc-network 0.34.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   ├── sc-network-light 0.33.0
    │       │       │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   ├── sc-rpc-server 11.0.0
    │       │       │   │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   └── sc-cli 0.36.0
    │       │       │   │   ├── sc-informant 0.33.0
    │       │       │   │   ├── sc-cli 0.36.0
    │       │       │   │   └── sc-chain-spec 28.0.0
    │       │       │   │       ├── sc-service 0.35.0
    │       │       │   │       ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │       ├── sc-rpc-api 0.33.0
    │       │       │   │       ├── sc-rpc 29.0.0
    │       │       │   │       └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-mixnet 0.4.0
    │       │       │   ├── sc-informant 0.33.0
    │       │       │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   ├── hegemon-node 0.3.0-alpha
    │       │       │   │   └── consensus 0.1.0
    │       │       │   │       ├── security-tests 0.1.0
    │       │       │   │       └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-consensus 0.33.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   ├── sc-consensus-pow 0.33.0
    │       │       │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-client-db 0.35.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   └── sc-cli 0.36.0
    │       │       │   ├── sc-cli 0.36.0
    │       │       │   ├── sc-chain-spec 28.0.0
    │       │       │   └── hegemon-node 0.3.0-alpha
    │       │       ├── sc-chain-spec 28.0.0
    │       │       └── hegemon-node 0.3.0-alpha
    │       ├── sc-executor-polkavm 0.29.0
    │       │   └── sc-executor 0.32.0
    │       └── sc-executor 0.32.0
    ├── substrate-wasm-builder 17.0.0
    │   └── runtime 0.1.0
    │       ├── hegemon-node 0.3.0-alpha
    │       └── consensus 0.1.0
    └── sp-version 29.0.0
        ├── sp-api 26.0.0
        │   ├── substrate-frame-rpc-system 28.0.0
        │   ├── sp-transaction-pool 26.0.0
        │   │   ├── sc-transaction-pool 28.0.0
        │   │   ├── sc-service 0.35.0
        │   │   └── runtime 0.1.0
        │   ├── sp-statement-store 10.0.0
        │   │   └── sc-rpc 29.0.0
        │   ├── sp-session 27.0.0
        │   │   ├── sc-service 0.35.0
        │   │   ├── sc-rpc 29.0.0
        │   │   ├── runtime 0.1.0
        │   │   └── pallet-session 28.0.0
        │   │       └── runtime 0.1.0
        │   ├── sp-offchain 26.0.0
        │   │   ├── sc-rpc 29.0.0
        │   │   └── runtime 0.1.0
        │   ├── sp-mixnet 0.4.0
        │   │   └── sc-mixnet 0.4.0
        │   ├── sp-genesis-builder 0.8.0
        │   │   ├── sc-chain-spec 28.0.0
        │   │   ├── runtime 0.1.0
        │   │   └── frame-support 28.0.0
        │   │       ├── runtime 0.1.0
        │   │       ├── pallet-treasury 27.0.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-transaction-payment 28.0.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   └── pallet-fee-model 0.1.0
        │   │       │       └── runtime 0.1.0
        │   │       ├── pallet-timestamp 27.0.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   ├── pallet-session 28.0.0
        │   │       │   ├── pallet-difficulty 0.1.0
        │   │       │   │   └── runtime 0.1.0
        │   │       │   └── hegemon-node 0.3.0-alpha
        │   │       ├── pallet-sudo 28.0.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-shielded-pool 0.1.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   └── hegemon-node 0.3.0-alpha
        │   │       ├── pallet-settlement 0.1.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-session 28.0.0
        │   │       ├── pallet-oracles 0.1.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-observability 0.1.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-membership 28.0.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-identity 0.1.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   ├── pallet-oracles 0.1.0
        │   │       │   ├── pallet-fee-model 0.1.0
        │   │       │   └── pallet-asset-registry 0.1.0
        │   │       │       └── runtime 0.1.0
        │   │       ├── pallet-fee-model 0.1.0
        │   │       ├── pallet-feature-flags 0.1.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-difficulty 0.1.0
        │   │       ├── pallet-collective 28.0.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-coinbase 0.1.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   └── hegemon-node 0.3.0-alpha
        │   │       ├── pallet-balances 28.0.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   ├── pallet-treasury 27.0.0
        │   │       │   ├── pallet-shielded-pool 0.1.0
        │   │       │   ├── pallet-settlement 0.1.0
        │   │       │   ├── pallet-session 28.0.0
        │   │       │   ├── pallet-fee-model 0.1.0
        │   │       │   └── pallet-coinbase 0.1.0
        │   │       ├── pallet-attestations 0.1.0
        │   │       │   └── runtime 0.1.0
        │   │       ├── pallet-asset-registry 0.1.0
        │   │       ├── hegemon-node 0.3.0-alpha
        │   │       ├── frame-try-runtime 0.34.0
        │   │       │   └── frame-executive 28.0.0
        │   │       │       └── runtime 0.1.0
        │   │       ├── frame-system 28.0.0
        │   │       │   ├── runtime 0.1.0
        │   │       │   ├── pallet-treasury 27.0.0
        │   │       │   ├── pallet-transaction-payment 28.0.0
        │   │       │   ├── pallet-timestamp 27.0.0
        │   │       │   ├── pallet-sudo 28.0.0
        │   │       │   ├── pallet-shielded-pool 0.1.0
        │   │       │   ├── pallet-settlement 0.1.0
        │   │       │   ├── pallet-session 28.0.0
        │   │       │   ├── pallet-oracles 0.1.0
        │   │       │   ├── pallet-observability 0.1.0
        │   │       │   ├── pallet-membership 28.0.0
        │   │       │   ├── pallet-identity 0.1.0
        │   │       │   ├── pallet-fee-model 0.1.0
        │   │       │   ├── pallet-feature-flags 0.1.0
        │   │       │   ├── pallet-difficulty 0.1.0
        │   │       │   ├── pallet-collective 28.0.0
        │   │       │   ├── pallet-coinbase 0.1.0
        │   │       │   ├── pallet-balances 28.0.0
        │   │       │   ├── pallet-attestations 0.1.0
        │   │       │   ├── pallet-asset-registry 0.1.0
        │   │       │   ├── frame-executive 28.0.0
        │   │       │   └── frame-benchmarking 28.0.0
        │   │       │       ├── runtime 0.1.0
        │   │       │       ├── pallet-treasury 27.0.0
        │   │       │       ├── pallet-transaction-payment 28.0.0
        │   │       │       ├── pallet-timestamp 27.0.0
        │   │       │       ├── pallet-sudo 28.0.0
        │   │       │       ├── pallet-shielded-pool 0.1.0
        │   │       │       ├── pallet-settlement 0.1.0
        │   │       │       ├── pallet-oracles 0.1.0
        │   │       │       ├── pallet-observability 0.1.0
        │   │       │       ├── pallet-membership 28.0.0
        │   │       │       ├── pallet-fee-model 0.1.0
        │   │       │       ├── pallet-feature-flags 0.1.0
        │   │       │       ├── pallet-collective 28.0.0
        │   │       │       ├── pallet-balances 28.0.0
        │   │       │       └── pallet-attestations 0.1.0
        │   │       ├── frame-executive 28.0.0
        │   │       └── frame-benchmarking 28.0.0
        │   ├── sp-consensus-pow 0.32.0
        │   │   ├── sc-consensus-pow 0.33.0
        │   │   ├── hegemon-node 0.3.0-alpha
        │   │   └── consensus 0.1.0
        │   ├── sp-consensus-grandpa 13.0.0
        │   │   └── sc-network-sync 0.33.0
        │   ├── sp-blockchain 28.0.0
        │   │   ├── substrate-frame-rpc-system 28.0.0
        │   │   ├── sc-transaction-pool-api 28.0.0
        │   │   │   ├── substrate-frame-rpc-system 28.0.0
        │   │   │   ├── sc-transaction-pool 28.0.0
        │   │   │   ├── sc-service 0.35.0
        │   │   │   ├── sc-rpc-spec-v2 0.34.0
        │   │   │   ├── sc-rpc-api 0.33.0
        │   │   │   ├── sc-rpc 29.0.0
        │   │   │   ├── sc-mixnet 0.4.0
        │   │   │   ├── sc-client-api 28.0.0
        │   │   │   ├── sc-basic-authorship 0.34.0
        │   │   │   │   └── hegemon-node 0.3.0-alpha
        │   │   │   └── hegemon-node 0.3.0-alpha
        │   │   ├── sc-transaction-pool 28.0.0
        │   │   ├── sc-tracing 28.0.0
        │   │   ├── sc-service 0.35.0
        │   │   ├── sc-rpc-spec-v2 0.34.0
        │   │   ├── sc-rpc 29.0.0
        │   │   ├── sc-network-sync 0.33.0
        │   │   ├── sc-network-light 0.33.0
        │   │   ├── sc-network 0.34.0
        │   │   ├── sc-informant 0.33.0
        │   │   ├── sc-consensus-pow 0.33.0
        │   │   ├── sc-consensus 0.33.0
        │   │   ├── sc-client-db 0.35.0
        │   │   ├── sc-client-api 28.0.0
        │   │   ├── sc-cli 0.36.0
        │   │   ├── sc-chain-spec 28.0.0
        │   │   ├── sc-block-builder 0.33.0
        │   │   │   ├── sc-rpc 29.0.0
        │   │   │   ├── sc-basic-authorship 0.34.0
        │   │   │   └── hegemon-node 0.3.0-alpha
        │   │   ├── sc-basic-authorship 0.34.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   ├── sp-block-builder 26.0.0
        │   │   ├── substrate-frame-rpc-system 28.0.0
        │   │   ├── sc-consensus-pow 0.33.0
        │   │   ├── sc-block-builder 0.33.0
        │   │   ├── runtime 0.1.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   ├── sc-transaction-pool 28.0.0
        │   ├── sc-tracing 28.0.0
        │   ├── sc-service 0.35.0
        │   ├── sc-rpc-spec-v2 0.34.0
        │   ├── sc-rpc 29.0.0
        │   ├── sc-mixnet 0.4.0
        │   ├── sc-executor 0.32.0
        │   ├── sc-consensus-pow 0.33.0
        │   ├── sc-client-api 28.0.0
        │   ├── sc-block-builder 0.33.0
        │   ├── sc-basic-authorship 0.34.0
        │   ├── runtime 0.1.0
        │   ├── hegemon-node 0.3.0-alpha
        │   ├── frame-try-runtime 0.34.0
        │   ├── frame-system-rpc-runtime-api 26.0.0
        │   │   └── substrate-frame-rpc-system 28.0.0
        │   ├── frame-support 28.0.0
        │   ├── frame-benchmarking 28.0.0
        │   └── consensus 0.1.0
        ├── sc-service 0.35.0
        ├── sc-rpc-spec-v2 0.34.0
        ├── sc-rpc-api 0.33.0
        ├── sc-rpc 29.0.0
        ├── sc-executor 0.32.0
        ├── sc-cli 0.36.0
        ├── runtime 0.1.0
        └── frame-system 28.0.0
    
    Crate:     paste
    Version:   1.0.15
    Warning:   unmaintained
    Title:     paste - no longer maintained
    Date:      2024-10-07
    ID:        RUSTSEC-2024-0436
    URL:       https://rustsec.org/advisories/RUSTSEC-2024-0436
    Dependency tree:
    paste 1.0.15
    ├── sp-runtime 31.0.1
    │   ├── substrate-frame-rpc-system 28.0.0
    │   │   └── hegemon-node 0.3.0-alpha
    │   │       └── security-tests 0.1.0
    │   ├── sp-version 29.0.0
    │   │   ├── sp-api 26.0.0
    │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   ├── sp-transaction-pool 26.0.0
    │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   └── runtime 0.1.0
    │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │   │   │   │       └── consensus 0.1.0
    │   │   │   │           ├── security-tests 0.1.0
    │   │   │   │           └── hegemon-node 0.3.0-alpha
    │   │   │   ├── sp-statement-store 10.0.0
    │   │   │   │   └── sc-rpc 29.0.0
    │   │   │   │       ├── sc-service 0.35.0
    │   │   │   │       ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │       │   └── sc-service 0.35.0
    │   │   │   │       └── hegemon-node 0.3.0-alpha
    │   │   │   ├── sp-session 27.0.0
    │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   └── pallet-session 28.0.0
    │   │   │   │       └── runtime 0.1.0
    │   │   │   ├── sp-offchain 26.0.0
    │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   └── runtime 0.1.0
    │   │   │   ├── sp-mixnet 0.4.0
    │   │   │   │   └── sc-mixnet 0.4.0
    │   │   │   │       ├── sc-rpc-api 0.33.0
    │   │   │   │       │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │       │   ├── sc-rpc-server 11.0.0
    │   │   │   │       │   │   └── sc-service 0.35.0
    │   │   │   │       │   ├── sc-rpc 29.0.0
    │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │       ├── sc-rpc 29.0.0
    │   │   │   │       └── sc-cli 0.36.0
    │   │   │   ├── sp-genesis-builder 0.8.0
    │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   └── frame-support 28.0.0
    │   │   │   │       ├── runtime 0.1.0
    │   │   │   │       ├── pallet-treasury 27.0.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-transaction-payment 28.0.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   └── pallet-fee-model 0.1.0
    │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │       ├── pallet-timestamp 27.0.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │   │   │   │       │   │   └── runtime 0.1.0
    │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │       ├── pallet-sudo 28.0.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-shielded-pool 0.1.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │       ├── pallet-settlement 0.1.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-session 28.0.0
    │   │   │   │       ├── pallet-oracles 0.1.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-observability 0.1.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-membership 28.0.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-identity 0.1.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   ├── pallet-oracles 0.1.0
    │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │       │   └── pallet-asset-registry 0.1.0
    │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │       ├── pallet-fee-model 0.1.0
    │   │   │   │       ├── pallet-feature-flags 0.1.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-difficulty 0.1.0
    │   │   │   │       ├── pallet-collective 28.0.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-coinbase 0.1.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   └── hegemon-node 0.3.0-alpha
    │   │   │   │       ├── pallet-balances 28.0.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   ├── pallet-treasury 27.0.0
    │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │       │   ├── pallet-settlement 0.1.0
    │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │       │   └── pallet-coinbase 0.1.0
    │   │   │   │       ├── pallet-attestations 0.1.0
    │   │   │   │       │   └── runtime 0.1.0
    │   │   │   │       ├── pallet-asset-registry 0.1.0
    │   │   │   │       ├── hegemon-node 0.3.0-alpha
    │   │   │   │       ├── frame-try-runtime 0.34.0
    │   │   │   │       │   └── frame-executive 28.0.0
    │   │   │   │       │       └── runtime 0.1.0
    │   │   │   │       ├── frame-system 28.0.0
    │   │   │   │       │   ├── runtime 0.1.0
    │   │   │   │       │   ├── pallet-treasury 27.0.0
    │   │   │   │       │   ├── pallet-transaction-payment 28.0.0
    │   │   │   │       │   ├── pallet-timestamp 27.0.0
    │   │   │   │       │   ├── pallet-sudo 28.0.0
    │   │   │   │       │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │       │   ├── pallet-settlement 0.1.0
    │   │   │   │       │   ├── pallet-session 28.0.0
    │   │   │   │       │   ├── pallet-oracles 0.1.0
    │   │   │   │       │   ├── pallet-observability 0.1.0
    │   │   │   │       │   ├── pallet-membership 28.0.0
    │   │   │   │       │   ├── pallet-identity 0.1.0
    │   │   │   │       │   ├── pallet-fee-model 0.1.0
    │   │   │   │       │   ├── pallet-feature-flags 0.1.0
    │   │   │   │       │   ├── pallet-difficulty 0.1.0
    │   │   │   │       │   ├── pallet-collective 28.0.0
    │   │   │   │       │   ├── pallet-coinbase 0.1.0
    │   │   │   │       │   ├── pallet-balances 28.0.0
    │   │   │   │       │   ├── pallet-attestations 0.1.0
    │   │   │   │       │   ├── pallet-asset-registry 0.1.0
    │   │   │   │       │   ├── frame-executive 28.0.0
    │   │   │   │       │   └── frame-benchmarking 28.0.0
    │   │   │   │       │       ├── runtime 0.1.0
    │   │   │   │       │       ├── pallet-treasury 27.0.0
    │   │   │   │       │       ├── pallet-transaction-payment 28.0.0
    │   │   │   │       │       ├── pallet-timestamp 27.0.0
    │   │   │   │       │       ├── pallet-sudo 28.0.0
    │   │   │   │       │       ├── pallet-shielded-pool 0.1.0
    │   │   │   │       │       ├── pallet-settlement 0.1.0
    │   │   │   │       │       ├── pallet-oracles 0.1.0
    │   │   │   │       │       ├── pallet-observability 0.1.0
    │   │   │   │       │       ├── pallet-membership 28.0.0
    │   │   │   │       │       ├── pallet-fee-model 0.1.0
    │   │   │   │       │       ├── pallet-feature-flags 0.1.0
    │   │   │   │       │       ├── pallet-collective 28.0.0
    │   │   │   │       │       ├── pallet-balances 28.0.0
    │   │   │   │       │       └── pallet-attestations 0.1.0
    │   │   │   │       ├── frame-executive 28.0.0
    │   │   │   │       └── frame-benchmarking 28.0.0
    │   │   │   ├── sp-consensus-pow 0.32.0
    │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   │   └── consensus 0.1.0
    │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   └── consensus 0.1.0
    │   │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   │   │   └── sc-network-sync 0.33.0
    │   │   │   │       ├── sc-service 0.35.0
    │   │   │   │       ├── sc-network-transactions 0.33.0
    │   │   │   │       │   └── sc-service 0.35.0
    │   │   │   │       └── sc-informant 0.33.0
    │   │   │   │           └── sc-service 0.35.0
    │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   ├── sc-transaction-pool-api 28.0.0
    │   │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   ├── sc-rpc-api 0.33.0
    │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   │   │   │   └── sc-service 0.35.0
    │   │   │   │   │   │   ├── sc-network 0.34.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   │   └── sc-chain-spec 28.0.0
    │   │   │   │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   │   ├── sc-client-db 0.35.0
    │   │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   │   ├── sc-tracing 28.0.0
    │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   │   ├── sc-network-light 0.33.0
    │   │   │   │   ├── sc-network 0.34.0
    │   │   │   │   ├── sc-informant 0.33.0
    │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   ├── sc-consensus 0.33.0
    │   │   │   │   ├── sc-client-db 0.35.0
    │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   ├── sc-cli 0.36.0
    │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   │   ├── sc-rpc 29.0.0
    │   │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   ├── sp-block-builder 26.0.0
    │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │   │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   ├── sc-transaction-pool 28.0.0
    │   │   │   ├── sc-tracing 28.0.0
    │   │   │   ├── sc-service 0.35.0
    │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   │   ├── sc-rpc 29.0.0
    │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   ├── sc-executor 0.32.0
    │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   ├── sc-client-api 28.0.0
    │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   ├── sc-client-api 28.0.0
    │   │   │   ├── sc-block-builder 0.33.0
    │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   ├── runtime 0.1.0
    │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   ├── frame-try-runtime 0.34.0
    │   │   │   ├── frame-system-rpc-runtime-api 26.0.0
    │   │   │   │   └── substrate-frame-rpc-system 28.0.0
    │   │   │   ├── frame-support 28.0.0
    │   │   │   ├── frame-benchmarking 28.0.0
    │   │   │   └── consensus 0.1.0
    │   │   ├── sc-service 0.35.0
    │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   ├── sc-rpc-api 0.33.0
    │   │   ├── sc-rpc 29.0.0
    │   │   ├── sc-executor 0.32.0
    │   │   ├── sc-cli 0.36.0
    │   │   ├── runtime 0.1.0
    │   │   └── frame-system 28.0.0
    │   ├── sp-transaction-storage-proof 26.0.0
    │   │   └── sc-service 0.35.0
    │   ├── sp-transaction-pool 26.0.0
    │   ├── sp-timestamp 26.0.0
    │   │   ├── pallet-timestamp 27.0.0
    │   │   └── hegemon-node 0.3.0-alpha
    │   ├── sp-statement-store 10.0.0
    │   ├── sp-staking 26.0.0
    │   │   ├── sp-session 27.0.0
    │   │   ├── runtime 0.1.0
    │   │   ├── pallet-session 28.0.0
    │   │   └── frame-support 28.0.0
    │   ├── sp-session 27.0.0
    │   ├── sp-offchain 26.0.0
    │   ├── sp-keyring 31.0.0
    │   │   └── sc-cli 0.36.0
    │   ├── sp-inherents 26.0.0
    │   │   ├── sp-transaction-storage-proof 26.0.0
    │   │   ├── sp-timestamp 26.0.0
    │   │   ├── sp-consensus 0.32.0
    │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   ├── sc-service 0.35.0
    │   │   │   ├── sc-network-transactions 0.33.0
    │   │   │   ├── sc-network-sync 0.33.0
    │   │   │   ├── sc-mixnet 0.4.0
    │   │   │   ├── sc-consensus-pow 0.33.0
    │   │   │   ├── sc-consensus 0.33.0
    │   │   │   ├── sc-client-api 28.0.0
    │   │   │   ├── sc-basic-authorship 0.34.0
    │   │   │   └── hegemon-node 0.3.0-alpha
    │   │   ├── sp-block-builder 26.0.0
    │   │   ├── sc-consensus-pow 0.33.0
    │   │   ├── sc-block-builder 0.33.0
    │   │   ├── sc-basic-authorship 0.34.0
    │   │   ├── runtime 0.1.0
    │   │   ├── pallet-timestamp 27.0.0
    │   │   ├── pallet-shielded-pool 0.1.0
    │   │   ├── pallet-coinbase 0.1.0
    │   │   ├── hegemon-node 0.3.0-alpha
    │   │   └── frame-support 28.0.0
    │   ├── sp-genesis-builder 0.8.0
    │   ├── sp-consensus-pow 0.32.0
    │   ├── sp-consensus-grandpa 13.0.0
    │   ├── sp-consensus 0.32.0
    │   ├── sp-blockchain 28.0.0
    │   ├── sp-block-builder 26.0.0
    │   ├── sp-api 26.0.0
    │   ├── sc-transaction-pool-api 28.0.0
    │   ├── sc-transaction-pool 28.0.0
    │   ├── sc-tracing 28.0.0
    │   ├── sc-service 0.35.0
    │   ├── sc-rpc-spec-v2 0.34.0
    │   ├── sc-rpc-api 0.33.0
    │   ├── sc-rpc 29.0.0
    │   ├── sc-network-transactions 0.33.0
    │   ├── sc-network-sync 0.33.0
    │   ├── sc-network-light 0.33.0
    │   ├── sc-network-common 0.33.0
    │   │   ├── sc-service 0.35.0
    │   │   ├── sc-network-transactions 0.33.0
    │   │   ├── sc-network-sync 0.33.0
    │   │   └── sc-network 0.34.0
    │   ├── sc-network 0.34.0
    │   ├── sc-mixnet 0.4.0
    │   ├── sc-informant 0.33.0
    │   ├── sc-consensus-pow 0.33.0
    │   ├── sc-consensus 0.33.0
    │   ├── sc-client-db 0.35.0
    │   ├── sc-client-api 28.0.0
    │   ├── sc-cli 0.36.0
    │   ├── sc-chain-spec 28.0.0
    │   ├── sc-block-builder 0.33.0
    │   ├── sc-basic-authorship 0.34.0
    │   ├── runtime 0.1.0
    │   ├── pallet-treasury 27.0.0
    │   ├── pallet-transaction-payment 28.0.0
    │   ├── pallet-timestamp 27.0.0
    │   ├── pallet-sudo 28.0.0
    │   ├── pallet-shielded-pool 0.1.0
    │   ├── pallet-settlement 0.1.0
    │   ├── pallet-session 28.0.0
    │   ├── pallet-oracles 0.1.0
    │   ├── pallet-observability 0.1.0
    │   ├── pallet-membership 28.0.0
    │   ├── pallet-identity 0.1.0
    │   ├── pallet-fee-model 0.1.0
    │   ├── pallet-feature-flags 0.1.0
    │   ├── pallet-difficulty 0.1.0
    │   ├── pallet-collective 28.0.0
    │   ├── pallet-coinbase 0.1.0
    │   ├── pallet-balances 28.0.0
    │   ├── pallet-attestations 0.1.0
    │   ├── pallet-asset-registry 0.1.0
    │   ├── hegemon-node 0.3.0-alpha
    │   ├── frame-try-runtime 0.34.0
    │   ├── frame-system 28.0.0
    │   ├── frame-support 28.0.0
    │   ├── frame-executive 28.0.0
    │   ├── frame-benchmarking 28.0.0
    │   └── consensus 0.1.0
    ├── sp-core 28.0.0
    │   ├── substrate-frame-rpc-system 28.0.0
    │   ├── sp-trie 29.0.0
    │   │   ├── sp-transaction-storage-proof 26.0.0
    │   │   ├── sp-state-machine 0.35.0
    │   │   │   ├── sp-io 30.0.0
    │   │   │   │   ├── sp-runtime 31.0.1
    │   │   │   │   ├── sp-application-crypto 30.0.0
    │   │   │   │   │   ├── sp-statement-store 10.0.0
    │   │   │   │   │   ├── sp-runtime 31.0.1
    │   │   │   │   │   ├── sp-mixnet 0.4.0
    │   │   │   │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   │   │   │   ├── sc-keystore 25.0.0
    │   │   │   │   │   │   ├── sc-service 0.35.0
    │   │   │   │   │   │   └── sc-cli 0.36.0
    │   │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   │   └── frame-benchmarking 28.0.0
    │   │   │   │   ├── sc-sysinfo 27.0.0
    │   │   │   │   │   └── sc-service 0.35.0
    │   │   │   │   ├── sc-executor 0.32.0
    │   │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   │   ├── runtime 0.1.0
    │   │   │   │   ├── pallet-transaction-payment 28.0.0
    │   │   │   │   ├── pallet-sudo 28.0.0
    │   │   │   │   ├── pallet-shielded-pool 0.1.0
    │   │   │   │   ├── pallet-settlement 0.1.0
    │   │   │   │   ├── pallet-session 28.0.0
    │   │   │   │   ├── pallet-observability 0.1.0
    │   │   │   │   ├── pallet-membership 28.0.0
    │   │   │   │   ├── pallet-fee-model 0.1.0
    │   │   │   │   ├── pallet-feature-flags 0.1.0
    │   │   │   │   ├── pallet-difficulty 0.1.0
    │   │   │   │   ├── pallet-collective 28.0.0
    │   │   │   │   ├── pallet-coinbase 0.1.0
    │   │   │   │   ├── pallet-attestations 0.1.0
    │   │   │   │   ├── hegemon-node 0.3.0-alpha
    │   │   │   │   ├── frame-system 28.0.0
    │   │   │   │   ├── frame-support 28.0.0
    │   │   │   │   ├── frame-executive 28.0.0
    │   │   │   │   └── frame-benchmarking 28.0.0
    │   │   │   ├── sp-consensus 0.32.0
    │   │   │   ├── sp-blockchain 28.0.0
    │   │   │   ├── sp-api 26.0.0
    │   │   │   ├── sc-service 0.35.0
    │   │   │   ├── sc-consensus 0.33.0
    │   │   │   ├── sc-client-db 0.35.0
    │   │   │   ├── sc-client-api 28.0.0
    │   │   │   ├── sc-chain-spec 28.0.0
    │   │   │   ├── pallet-session 28.0.0
    │   │   │   └── frame-support 28.0.0
    │   │   ├── sp-runtime 31.0.1
    │   │   ├── sp-io 30.0.0
    │   │   ├── sp-api 26.0.0
    │   │   ├── sc-service 0.35.0
    │   │   ├── sc-executor 0.32.0
    │   │   ├── sc-client-db 0.35.0
    │   │   ├── sc-client-api 28.0.0
    │   │   ├── sc-block-builder 0.33.0
    │   │   ├── sc-basic-authorship 0.34.0
    │   │   ├── pallet-session 28.0.0
    │   │   └── frame-support 28.0.0
    │   ├── sp-transaction-storage-proof 26.0.0
    │   ├── sp-statement-store 10.0.0
    │   ├── sp-state-machine 0.35.0
    │   ├── sp-staking 26.0.0
    │   ├── sp-session 27.0.0
    │   ├── sp-runtime 31.0.1
    │   ├── sp-rpc 26.0.0
    │   │   ├── sc-tracing 28.0.0
    │   │   ├── sc-rpc-spec-v2 0.34.0
    │   │   ├── sc-rpc-api 0.33.0
    │   │   └── sc-rpc 29.0.0
    │   ├── sp-offchain 26.0.0
    │   ├── sp-keystore 0.34.0
    │   │   ├── sp-session 27.0.0
    │   │   ├── sp-io 30.0.0
    │   │   ├── sp-consensus-grandpa 13.0.0
    │   │   ├── sc-service 0.35.0
    │   │   ├── sc-rpc 29.0.0
    │   │   ├── sc-mixnet 0.4.0
    │   │   ├── sc-keystore 25.0.0
    │   │   ├── sc-cli 0.36.0
    │   │   └── hegemon-node 0.3.0-alpha
    │   ├── sp-keyring 31.0.0
    │   ├── sp-io 30.0.0
    │   ├── sp-consensus-pow 0.32.0
    │   ├── sp-consensus-grandpa 13.0.0
    │   ├── sp-blockchain 28.0.0
    │   ├── sp-application-crypto 30.0.0
    │   ├── sp-api 26.0.0
    │   ├── security-tests 0.1.0
    │   ├── sc-transaction-pool-api 28.0.0
    │   ├── sc-transaction-pool 28.0.0
    │   ├── sc-tracing 28.0.0
    │   ├── sc-sysinfo 27.0.0
    │   ├── sc-state-db 0.30.0
    │   │   └── sc-client-db 0.35.0
    │   ├── sc-service 0.35.0
    │   ├── sc-rpc-spec-v2 0.34.0
    │   ├── sc-rpc-api 0.33.0
    │   ├── sc-rpc 29.0.0
    │   ├── sc-network-sync 0.33.0
    │   ├── sc-network-light 0.33.0
    │   ├── sc-network 0.34.0
    │   ├── sc-mixnet 0.4.0
    │   ├── sc-keystore 25.0.0
    │   ├── sc-executor 0.32.0
    │   ├── sc-consensus-pow 0.33.0
    │   ├── sc-consensus 0.33.0
    │   ├── sc-client-db 0.35.0
    │   ├── sc-client-api 28.0.0
    │   ├── sc-cli 0.36.0
    │   ├── sc-chain-spec 28.0.0
    │   ├── sc-block-builder 0.33.0
    │   ├── sc-basic-authorship 0.34.0
    │   ├── sc-allocator 23.0.0
    │   │   ├── sc-executor-wasmtime 0.29.0
    │   │   │   └── sc-executor 0.32.0
    │   │   └── sc-executor-common 0.29.0
    │   │       ├── sc-executor-wasmtime 0.29.0
    │   │       ├── sc-executor-polkavm 0.29.0
    │   │       │   └── sc-executor 0.32.0
    │   │       └── sc-executor 0.32.0
    │   ├── runtime 0.1.0
    │   ├── pallet-treasury 27.0.0
    │   ├── pallet-shielded-pool 0.1.0
    │   ├── pallet-settlement 0.1.0
    │   ├── pallet-session 28.0.0
    │   ├── pallet-membership 28.0.0
    │   ├── pallet-difficulty 0.1.0
    │   ├── pallet-collective 28.0.0
    │   ├── pallet-coinbase 0.1.0
    │   ├── pallet-balances 28.0.0
    │   ├── hegemon-node 0.3.0-alpha
    │   ├── frame-system 28.0.0
    │   ├── frame-support 28.0.0
    │   ├── frame-executive 28.0.0
    │   ├── frame-benchmarking 28.0.0
    │   └── consensus 0.1.0
    ├── simba 0.9.1
    │   └── nalgebra 0.33.2
    │       └── linregress 0.5.4
    │           └── frame-benchmarking 28.0.0
    ├── netlink-packet-utils 0.5.2
    │   ├── rtnetlink 0.13.1
    │   │   └── if-watch 3.2.1
    │   │       ├── libp2p-tcp 0.42.0
    │   │       │   └── libp2p 0.54.1
    │   │       │       ├── sc-telemetry 15.0.0
    │   │       │       │   ├── sc-sysinfo 27.0.0
    │   │       │       │   ├── sc-service 0.35.0
    │   │       │       │   ├── sc-cli 0.36.0
    │   │       │       │   ├── sc-chain-spec 28.0.0
    │   │       │       │   └── sc-basic-authorship 0.34.0
    │   │       │       └── sc-network 0.34.0
    │   │       ├── libp2p-quic 0.11.1
    │   │       │   └── libp2p 0.54.1
    │   │       └── libp2p-mdns 0.46.0
    │   │           └── libp2p 0.54.1
    │   ├── netlink-packet-route 0.17.1
    │   │   ├── rtnetlink 0.13.1
    │   │   ├── netdev 0.31.0
    │   │   │   └── natpmp 0.5.0
    │   │   │       └── network 0.1.0
    │   │   │           ├── security-tests 0.1.0
    │   │   │           ├── hegemon-node 0.3.0-alpha
    │   │   │           └── consensus 0.1.0
    │   │   └── if-watch 3.2.1
    │   └── netlink-packet-core 0.7.0
    │       ├── rtnetlink 0.13.1
    │       ├── netlink-proto 0.11.5
    │       │   ├── rtnetlink 0.13.1
    │       │   └── if-watch 3.2.1
    │       ├── netlink-packet-route 0.17.1
    │       ├── netdev 0.31.0
    │       └── if-watch 3.2.1
    ├── frame-support 28.0.0
    ├── frame-benchmarking 28.0.0
    ├── ark-ff 0.5.0
    │   ├── w3f-ring-proof 0.0.2
    │   │   └── ark-vrf 0.1.0
    │   │       └── sp-core 28.0.0
    │   ├── w3f-plonk-common 0.0.2
    │   │   └── w3f-ring-proof 0.0.2
    │   ├── w3f-pcs 0.0.2
    │   │   ├── w3f-ring-proof 0.0.2
    │   │   └── w3f-plonk-common 0.0.2
    │   ├── ark-vrf 0.1.0
    │   ├── ark-transcript 0.0.3
    │   │   └── w3f-ring-proof 0.0.2
    │   ├── ark-poly 0.5.0
    │   │   ├── w3f-ring-proof 0.0.2
    │   │   ├── w3f-plonk-common 0.0.2
    │   │   ├── w3f-pcs 0.0.2
    │   │   └── ark-ec 0.5.0
    │   │       ├── w3f-ring-proof 0.0.2
    │   │       ├── w3f-plonk-common 0.0.2
    │   │       ├── w3f-pcs 0.0.2
    │   │       ├── ark-vrf 0.1.0
    │   │       ├── ark-ed-on-bls12-381-bandersnatch 0.5.0
    │   │       │   └── ark-vrf 0.1.0
    │   │       └── ark-bls12-381 0.5.0
    │   │           ├── ark-vrf 0.1.0
    │   │           └── ark-ed-on-bls12-381-bandersnatch 0.5.0
    │   ├── ark-ed-on-bls12-381-bandersnatch 0.5.0
    │   ├── ark-ec 0.5.0
    │   └── ark-bls12-381 0.5.0
    └── ark-ff 0.4.2
        ├── w3f-bls 0.1.9
        │   └── sp-core 28.0.0
        ├── ark-poly 0.4.2
        │   └── ark-ec 0.4.2
        │       ├── w3f-bls 0.1.9
        │       ├── ark-bls12-381 0.4.0
        │       │   └── w3f-bls 0.1.9
        │       └── ark-bls12-377 0.4.0
        │           └── w3f-bls 0.1.9
        ├── ark-ec 0.4.2
        ├── ark-bls12-381 0.4.0
        └── ark-bls12-377 0.4.0
    
    Crate:     proc-macro-error
    Version:   1.0.4
    Warning:   unmaintained
    Title:     proc-macro-error is unmaintained
    Date:      2024-09-01
    ID:        RUSTSEC-2024-0370
    URL:       https://rustsec.org/advisories/RUSTSEC-2024-0370
    Dependency tree:
    proc-macro-error 1.0.4
    ├── multihash-derive 0.8.1
    │   └── multihash 0.17.0
    │       ├── multiaddr 0.17.1
    │       │   └── litep2p 0.12.2
    │       │       ├── sc-network-types 0.10.0
    │       │       │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-cli 0.36.0
    │       │       │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │       └── security-tests 0.1.0
    │       │       │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-network-transactions 0.33.0
    │       │       │   │   └── sc-service 0.35.0
    │       │       │   ├── sc-network-sync 0.33.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   └── sc-informant 0.33.0
    │       │       │   │       └── sc-service 0.35.0
    │       │       │   ├── sc-network-light 0.33.0
    │       │       │   │   └── sc-service 0.35.0
    │       │       │   ├── sc-network 0.34.0
    │       │       │   │   ├── sc-service 0.35.0
    │       │       │   │   ├── sc-network-transactions 0.33.0
    │       │       │   │   ├── sc-network-sync 0.33.0
    │       │       │   │   ├── sc-network-light 0.33.0
    │       │       │   │   ├── sc-mixnet 0.4.0
    │       │       │   │   │   ├── sc-rpc-api 0.33.0
    │       │       │   │   │   │   ├── substrate-frame-rpc-system 28.0.0
    │       │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   ├── sc-rpc-server 11.0.0
    │       │       │   │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   │   │   ├── sc-service 0.35.0
    │       │       │   │   │   │   │   ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │   │   │   │   │   └── sc-service 0.35.0
    │       │       │   │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   │   └── hegemon-node 0.3.0-alpha
    │       │       │   │   │   ├── sc-rpc 29.0.0
    │       │       │   │   │   └── sc-cli 0.36.0
    │       │       │   │   ├── sc-informant 0.33.0
    │       │       │   │   ├── sc-cli 0.36.0
    │       │       │   │   └── sc-chain-spec 28.0.0
    │       │       │   │       ├── sc-service 0.35.0
    │       │       │   │       ├── sc-rpc-spec-v2 0.34.0
    │       │       │   │       ├── sc-rpc-api 0.33.0
    │       │       │   │       ├── sc-rpc 29.0.0
    │       │       │   │       └── hegemon-node 0.3.0-alpha
    │       │       │   ├── sc-mixnet 0.4.0
    │       │       │   └── sc-consensus 0.33.0
    │       │       │       ├── sc-service 0.35.0
    │       │       │       ├── sc-network-sync 0.33.0
    │       │       │       ├── sc-consensus-pow 0.33.0
    │       │       │       │   ├── hegemon-node 0.3.0-alpha
    │       │       │       │   └── consensus 0.1.0
    │       │       │       │       ├── security-tests 0.1.0
    │       │       │       │       └── hegemon-node 0.3.0-alpha
    │       │       │       └── hegemon-node 0.3.0-alpha
    │       │       └── sc-network 0.34.0
    │       ├── litep2p 0.12.2
    │       └── cid 0.9.0
    │           └── sc-network 0.34.0
    └── aquamarine 0.5.0
        ├── frame-support 28.0.0
        │   ├── runtime 0.1.0
        │   │   ├── hegemon-node 0.3.0-alpha
        │   │   └── consensus 0.1.0
        │   ├── pallet-treasury 27.0.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-transaction-payment 28.0.0
        │   │   ├── runtime 0.1.0
        │   │   └── pallet-fee-model 0.1.0
        │   │       └── runtime 0.1.0
        │   ├── pallet-timestamp 27.0.0
        │   │   ├── runtime 0.1.0
        │   │   ├── pallet-session 28.0.0
        │   │   │   └── runtime 0.1.0
        │   │   ├── pallet-difficulty 0.1.0
        │   │   │   └── runtime 0.1.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   ├── pallet-sudo 28.0.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-shielded-pool 0.1.0
        │   │   ├── runtime 0.1.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   ├── pallet-settlement 0.1.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-session 28.0.0
        │   ├── pallet-oracles 0.1.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-observability 0.1.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-membership 28.0.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-identity 0.1.0
        │   │   ├── runtime 0.1.0
        │   │   ├── pallet-oracles 0.1.0
        │   │   ├── pallet-fee-model 0.1.0
        │   │   └── pallet-asset-registry 0.1.0
        │   │       └── runtime 0.1.0
        │   ├── pallet-fee-model 0.1.0
        │   ├── pallet-feature-flags 0.1.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-difficulty 0.1.0
        │   ├── pallet-collective 28.0.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-coinbase 0.1.0
        │   │   ├── runtime 0.1.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   ├── pallet-balances 28.0.0
        │   │   ├── runtime 0.1.0
        │   │   ├── pallet-treasury 27.0.0
        │   │   ├── pallet-shielded-pool 0.1.0
        │   │   ├── pallet-settlement 0.1.0
        │   │   ├── pallet-session 28.0.0
        │   │   ├── pallet-fee-model 0.1.0
        │   │   └── pallet-coinbase 0.1.0
        │   ├── pallet-attestations 0.1.0
        │   │   └── runtime 0.1.0
        │   ├── pallet-asset-registry 0.1.0
        │   ├── hegemon-node 0.3.0-alpha
        │   ├── frame-try-runtime 0.34.0
        │   │   └── frame-executive 28.0.0
        │   │       └── runtime 0.1.0
        │   ├── frame-system 28.0.0
        │   │   ├── runtime 0.1.0
        │   │   ├── pallet-treasury 27.0.0
        │   │   ├── pallet-transaction-payment 28.0.0
        │   │   ├── pallet-timestamp 27.0.0
        │   │   ├── pallet-sudo 28.0.0
        │   │   ├── pallet-shielded-pool 0.1.0
        │   │   ├── pallet-settlement 0.1.0
        │   │   ├── pallet-session 28.0.0
        │   │   ├── pallet-oracles 0.1.0
        │   │   ├── pallet-observability 0.1.0
        │   │   ├── pallet-membership 28.0.0
        │   │   ├── pallet-identity 0.1.0
        │   │   ├── pallet-fee-model 0.1.0
        │   │   ├── pallet-feature-flags 0.1.0
        │   │   ├── pallet-difficulty 0.1.0
        │   │   ├── pallet-collective 28.0.0
        │   │   ├── pallet-coinbase 0.1.0
        │   │   ├── pallet-balances 28.0.0
        │   │   ├── pallet-attestations 0.1.0
        │   │   ├── pallet-asset-registry 0.1.0
        │   │   ├── frame-executive 28.0.0
        │   │   └── frame-benchmarking 28.0.0
        │   │       ├── runtime 0.1.0
        │   │       ├── pallet-treasury 27.0.0
        │   │       ├── pallet-transaction-payment 28.0.0
        │   │       ├── pallet-timestamp 27.0.0
        │   │       ├── pallet-sudo 28.0.0
        │   │       ├── pallet-shielded-pool 0.1.0
        │   │       ├── pallet-settlement 0.1.0
        │   │       ├── pallet-oracles 0.1.0
        │   │       ├── pallet-observability 0.1.0
        │   │       ├── pallet-membership 28.0.0
        │   │       ├── pallet-fee-model 0.1.0
        │   │       ├── pallet-feature-flags 0.1.0
        │   │       ├── pallet-collective 28.0.0
        │   │       ├── pallet-balances 28.0.0
        │   │       └── pallet-attestations 0.1.0
        │   ├── frame-executive 28.0.0
        │   └── frame-benchmarking 28.0.0
        └── frame-executive 28.0.0
    
    Crate:     ring
    Version:   0.16.20
    Warning:   unmaintained
    Title:     Versions of *ring* prior to 0.17 are unmaintained.
    Date:      2025-03-05
    ID:        RUSTSEC-2025-0010
    URL:       https://rustsec.org/advisories/RUSTSEC-2025-0010
    
    Crate:     rustls-pemfile
    Version:   2.2.0
    Warning:   unmaintained
    Title:     rustls-pemfile is unmaintained
    Date:      2025-11-28
    ID:        RUSTSEC-2025-0134
    URL:       https://rustsec.org/advisories/RUSTSEC-2025-0134
    Dependency tree:
    rustls-pemfile 2.2.0
    └── axum-server 0.7.3
        └── hegemon-node 0.3.0-alpha
            └── security-tests 0.1.0
    
    Crate:     atty
    Version:   0.2.14
    Warning:   unsound
    Title:     Potential unaligned read
    Date:      2021-07-04
    ID:        RUSTSEC-2021-0145
    URL:       https://rustsec.org/advisories/RUSTSEC-2021-0145
    
    Crate:     kvdb-rocksdb
    Version:   0.20.1
    Warning:   yanked
    Dependency tree:
    kvdb-rocksdb 0.20.1
    └── sc-client-db 0.35.0
        ├── sc-service 0.35.0
        │   ├── sc-cli 0.36.0
        │   │   └── hegemon-node 0.3.0-alpha
        │   │       └── security-tests 0.1.0
        │   └── hegemon-node 0.3.0-alpha
        └── sc-cli 0.36.0
    
    error: 2 vulnerabilities found!
    warning: 11 allowed warnings found
