# Observe Hegemon testnet swap claims without exposing secrets

This living plan follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

The existing Hegemon preimage observer deliberately accepts only a peerless
development node. Public-testnet swaps need a separate read-only observer that
can recover a hash-matching preimage from a confirmed claim on the pinned v0.11
pre-mainnet chain without weakening that development guard or printing the
preimage. It requires an exact expected action ID but does not establish that
the action spent a particular HTLC; a caller must verify that separately. It
relies on a trusted local full node and trusted public explorer; it does not
independently verify consensus or prove finality.

## Progress

- [x] (2026-11-04 18:38Z) Identified the development-only observer, the pinned
  source relation and the optional trusted public-tip comparison.
- [x] (2026-11-04 18:39Z) Implemented a separate public observer and encrypted-backup CLI.
- [x] (2026-11-04 18:40Z) Tested matching claims, wrong network or source, stale tips, insufficient
  confirmations, reorganizations, malformed carriers and nonmatching hashlocks.
- [x] (2026-11-04 18:40Z) Documented the tests and the untested live-network boundary.
- [ ] Bind an observed action to the intended HTLC note before any public-swap
  driver uses the observation to authorize a counterparty claim.

## Surprises & Discoveries

The development observer explicitly checks for zero peers and a development
manifest. Removing those checks would silently change its trust boundary; the
public path must therefore be additive.

The current wallet verifies an HTLC note internally but does not export its
nullifier through the existing `verify-htlc` command. A matching action ID and
hashlock do not by themselves establish that action consumed that exact note.
The encrypted wallet's `StoredPrivateSpendNote` retains a note's derived
nullifier, and the v0.11 public action carrier includes two nullifiers. A future
wallet-integrated check could compare the appropriate input locally while also
validating the agreed terms and canonical chain. This requires careful slot,
rollback, privacy, and release-mode checks; it is not implemented here. Do not
publish or log a note's nullifier before its corresponding spend is public.

## Decision Log

- Decision: Pin pre-mainnet identity and relation through the existing probe,
  and compare its tip with the public explorer before and after observation.
  Rationale: The node's own `syncing` flag previously masked an 812-block lag.
  Date/Author: 2026-11-04 / Codex.
- Decision: Require the exact submitted action ID and warn that this does not
  itself bind the action to a particular locked note. Rationale: A matching
  hashlock alone does not identify which transaction spent which note.
  Date/Author: 2026-11-04 / Codex.
- Decision: Return a mutable secret only to the caller and provide a CLI that
  writes an encrypted backup without printing the preimage.
  Rationale: Claim preimages are sensitive until disclosed on chain.
  Date/Author: 2026-11-04 / Codex.
- Decision: Fail closed on uncertain node identity, malformed frames or a
  reorganization during scanning. Limit the scanned range and polling time.
  Rationale: A mistaken observation could cause a cross-chain action.
  Date/Author: 2026-11-04 / Codex.

## Outcomes & Retrospective

The observer and encrypted-backup CLI passed 19 synthetic tests, including a
loopback RPC fixture and encrypted-backup round trip. The development observer,
node probe and backup interoperability tests also passed. This is an observer
only: binding a claim to the intended HTLC, a staged public counterparty swap
driver, and funded live tests remain separate.

## Context and Orientation

`scripts/hegemon_preimage_observer.py` provides strict carrier parsing but is
development-only. `scripts/probe_hegemon_testnet.py` pins public network and
relation identity and can compare an explicitly trusted explorer. The helper
`canonical_body` in `scripts/check_native_asset_lifecycle.py` fetches bounded
action bytes from a loopback RPC. `scripts/unlock_swap_backup.py` writes an
encrypted browser-compatible backup. The local node validates actions; these
Python parsers do not verify transaction proofs independently.

## Milestones and Plan of Work

Create `scripts/public_hegemon_preimage_observer.py` with a bounded polling
function that checks node identity, required read methods, sync state and the
public reference. Scan confirmed canonical blocks for the exact expected action
and a source-bound carrier whose released preimage hashes to the expected
hashlock. Recheck the scanned
block and snapshot anchor before returning. Preserve the original development
observer unchanged. Add `scripts/watch_public_hegemon_preimage.py` to save the
observed preimage with the existing encrypted-backup function from an
interactive local terminal. Never print the preimage or wallet material.

Create `scripts/test_public_hegemon_preimage_observer.py` with deterministic
fixtures and negative cases for identity, freshness, confirmation depth,
reorganization, malformed action bytes, incorrect hashlock and empty ranges.
Test with fake local-node and explorer responses; do not broadcast or run a
public Hegemon node in this workspace.

## Concrete Steps

From the repository root run `python3 -m unittest discover -s scripts -p
test_public_hegemon_preimage_observer.py` and the existing development observer
and node probe tests. Run `git diff --check`. Update `DESIGN.md` and
`METHODS.md` with the exact trust boundaries and testing limitations.

## Validation and Acceptance

Only the specified matching, sufficiently confirmed action on the pinned public
chain may produce a secret. This alone does not establish that the action spent
the intended HTLC. Wrong chains, stale explorer data, reorganization and invalid
carriers must not produce a secret. The default development observer continues
to reject public peers. No secret is emitted in CLI output or committed artifacts.

## Idempotence and Recovery

Observation is read-only and can be repeated. Interrupted encrypted-backup
creation must not overwrite an existing backup. A reorganization invalidates
the current observation; the operator must review chain state before retrying.

## Artifacts and Notes

Live public-node validation and an actual confirmed HTLC claim are pending
testnet funding; synthetic fixtures cannot establish production security.

## Interfaces and Dependencies

Use the Python standard library and existing repository helpers. The observer
accepts a loopback HTTP endpoint, expected action ID, hashlock, start height,
confirmation count, and bounded timeout. The encrypted-backup CLI uses the
existing backup format.
