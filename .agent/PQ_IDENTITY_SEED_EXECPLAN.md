# Persist PQ Network Identity Seeds

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

The PQ transport identity keys must be derived from secret, non-public seeds so peers cannot impersonate each other by recomputing private keys from public IDs. After this change, the node will load a persisted 32-byte PQ identity seed (or generate one once and store it with locked-down permissions), derive the PQ network and PQ-Noise identities from that secret, and refuse to ever derive keys from public peer IDs. A user can start the node twice and observe the PQ peer ID is stable across restarts without any public seed in the logs; the seed file itself is kept out of git and has restrictive permissions.

The visible proof is that a seed file appears under the node base path (or a configured path), its mode is 0600, and repeated node starts log the same PQ peer ID without regenerating the seed.

## Progress

- [x] (2025-12-21 03:08Z) Review relevant design/methods docs and update this ExecPlan with any constraints needed.
- [x] (2025-12-21 03:12Z) Implement PQ identity seed load/generate with domain-separated derivations for PQ network keypair and PQ-Noise identity.
- [x] (2025-12-21 03:12Z) Add gitignore coverage for PQ identity seed artifacts.
- [x] (2025-12-21 03:12Z) Update DESIGN.md, METHODS.md, and docs/THREAT_MODEL.md to document the new identity seed handling.
- [ ] Validate seed persistence behavior and update this plan’s evidence sections (blocked by current `make node` WASM build failure; see Surprises).

## Surprises & Discoveries

- Observation: `make node` currently fails during WASM runtime build because `f64::log2` is unavailable in the `wasm32-unknown-unknown` build of `transaction-core`.
  Evidence: `circuits/transaction-core/src/dimensions.rs:95` error `no method named 'log2' found for type 'f64'` when running `make node`.

## Decision Log

- Decision: Persist a 32-byte PQ identity seed under the node base path as hex with 0600 permissions and allow overrides via env var/path.
  Rationale: Keeps identity material secret while enabling stable peer identity across restarts and explicit operator control.
  Date/Author: 2025-12-20 / Codex

- Decision: Derive separate PQ network and PQ-Noise seeds from the base seed using domain-separated SHA-256 labels.
  Rationale: Avoids reusing identical seed material across distinct key roles while keeping a single persisted secret for operators to manage.
  Date/Author: 2025-12-21 / Codex

## Outcomes & Retrospective

Pending.

## Context and Orientation

The Substrate node wiring lives in `node/src/substrate/service.rs`. This file constructs the PQ transport identity and network keypair. Today it generates a PQ network keypair and then derives a “seed” from the public peer ID, which makes the private keys predictable. `network/src/pq_transport.rs` and `pq-noise/src/types.rs` show that the PQ identity keys are deterministically derived from whatever seed they receive.

A “PQ identity seed” in this plan means a 32-byte random secret that the node persists on disk and reuses to derive PQ key material. The “base path” is the node’s data directory (Substrate configuration `config.base_path.path()`), which is where other persistent files live. We will store a hex-encoded seed file there with restrictive permissions so it is not checked into git.

Key files:

- `node/src/substrate/service.rs`: generate/load PQ identity seed and build PQ key material.
- `.gitignore`: ensure seed artifacts are ignored.
- `DESIGN.md`, `METHODS.md`, `docs/THREAT_MODEL.md`: document the new identity seed handling.

## Plan of Work

First, add a helper in `node/src/substrate/service.rs` to load a PQ identity seed. The helper should read `HEGEMON_PQ_IDENTITY_SEED` (hex string) if present; otherwise read `HEGEMON_PQ_IDENTITY_SEED_PATH` or default to `config.base_path.path().join("pq-identity.seed")`. When no file exists, generate 32 random bytes via `OsRng`, write them as hex to the file using `create_new` with 0600 permissions, and return the seed. When a file exists, parse the hex contents and validate length; if invalid, return a clear error.

Second, derive two domain-separated seeds from the base seed (for example using SHA-256 labels) so the PQ network keypair and PQ-Noise identity do not share the same raw seed. Use these derived seeds for `PqNetworkKeypair::from_seed` and `PqPeerIdentity::new` respectively, replacing the existing peer-id-based seed.

Third, update `.gitignore` to exclude the seed file name so it cannot be committed even when the base path is inside the repository.

Finally, update `DESIGN.md`, `METHODS.md`, and `docs/THREAT_MODEL.md` to describe that PQ network identity seeds are generated from OS entropy, persisted under the base path with strict permissions, and never derived from public peer IDs. Mention the env var/path override for operator control.

## Concrete Steps

All commands below assume the working directory is the repository root.

Fresh clone prerequisites (run once on a new machine):

  make setup
  make node

Implementation steps:

  1) Edit `node/src/substrate/service.rs` to add the seed load/generate helper and use it when building the PQ identities.
  2) Edit `.gitignore` to ignore `pq-identity.seed`.
  3) Update documentation in `DESIGN.md`, `METHODS.md`, and `docs/THREAT_MODEL.md`.

When recording evidence, capture the seed file path, permissions, and stable peer ID logs.

## Validation and Acceptance

Start the node twice and confirm the PQ peer ID is stable and the seed file persists.

Example manual validation (from the repo root):

  1) Remove any existing seed file (if you want to observe fresh generation):
     rm -f <base-path>/pq-identity.seed

  2) Start the node once, then stop it after it prints the PQ peer ID.

  3) Confirm the seed file exists and has restrictive permissions:
     ls -l <base-path>/pq-identity.seed
     cat <base-path>/pq-identity.seed

  4) Start the node again and confirm the PQ peer ID log matches the first run.

Acceptance criteria:

- A hex seed file is created at the configured path with mode 0600.
- The PQ peer ID is stable across restarts when the seed file is unchanged.
- No code path derives PQ identity seeds from public peer IDs.

## Idempotence and Recovery

If the seed file exists, the helper must reuse it and never overwrite it. If the seed is invalid, the node should fail fast with a clear error. To recover, operators can delete the seed file and restart to generate a new identity (this will change the peer ID).

## Artifacts and Notes

Expected log snippet (example):

  Generated or loaded PQ identity seed from /path/to/pq-identity.seed
  Generated PQ network keypair (peer_id=...)

Expected file format (hex, no prefix):

  64 hex characters

## Interfaces and Dependencies

In `node/src/substrate/service.rs`, add:

  - A helper `fn load_or_create_pq_identity_seed(config: &Configuration) -> Result<[u8; 32], ServiceError>`.
  - A helper `fn derive_seed(label: &[u8], seed: &[u8; 32]) -> [u8; 32]` using SHA-256.

Update the PQ identity wiring to use:

  - `PqNetworkKeypair::from_seed(&derive_seed(b"pq-network", &seed))`
  - `PqPeerIdentity::new(&derive_seed(b"pq-noise", &seed), pq_transport_config)`

Ensure any new imports are added explicitly (e.g., `std::fs`, `rand::rngs::OsRng`, `sha2::{Digest, Sha256}`), and keep all secrets out of logs.

Plan update note: Initial creation of this ExecPlan for PQ identity seed persistence. Reason: implementing a security-critical fix with documented steps.
Plan update note: Marked implementation/gitignore/docs steps complete and recorded domain-separated seed decision. Reason: reflect work completed and design choices made during implementation.
Plan update note: Recorded build failure in Surprises section. Reason: capture validation blocker encountered during setup.
