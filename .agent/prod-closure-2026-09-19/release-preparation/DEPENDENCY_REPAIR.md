# rustls dependency repair — RUSTSEC-2026-0285

Scope: the workspace lockfile's reqwest/hyper-rustls/tokio-rustls TLS graph.
The security invariant is TLS 1.3 handshake encryption-level enforcement.
The patch preserves the existing reqwest API and TLS configuration; it changes
`rustls` 0.23.42 to the advisory's patched 0.23.45 and its required
`rustls-webpki` 0.103.13 to 0.103.15. No other lockfile package is changed.

The direct TLS feature entry is `tests/Cargo.toml`. Node's reqwest dependency
is dev-only. Production wallet RPC rejects HTTPS/WSS before connecting;
this patch does not enable TLS RPC or alter that behavior.

The unrelated, now-unused lru RUSTSEC-2026-0253 waiver was removed because the
lockfile already resolves lru 0.18.2. No new advisory waiver was added.

## Verification

- A fresh advisory-database audit before repair reproduced one unwaived
  advisory (rustls) and one unused waiver (lru).
- `./scripts/dependency-audit-gate.sh --offline` against that fresh database
  passes after repair: four pre-existing waived advisories, zero unwaived
  advisories, zero unused waivers. This is the focused dependency-version
  substitute for an upstream TLS protocol exploit test, not a new exploit PoC.
- `git diff --check` passes.
- Independent read-only pre-patch investigation and post-patch review found
  no additional rustls copy, remaining vulnerable resolution, or concrete
  bypass/regression. The reviewer could not complete Cargo graph validation
  without downloading the new crate; that is not a passing compatibility test.
- Luna's serial compiler lane ran
  `cargo check --locked -p security-tests --test multinode_integration`.
  It passes in 23.99 seconds with rustls 0.23.45 / webpki 0.103.15 resolved.
  This checks the affected caller's API/feature compatibility; it is not a
  live TLS handshake regression test. No existing project TLS-specific
  handshake test is available, and no upstream exploit was recreated here.

Primary advisory: https://rustsec.org/advisories/RUSTSEC-2026-0285.html

The blueprint's dependency-waiver content digest is refreshed to identify this
patch. Its independent-review status remains `needs_review`; this update does
not manufacture an independent review or change any production claim.
