# Inactive SmallWood V7/Zeta lifecycle repair red-team

Date: 2026-08-22

Status: source-level repair complete; production and every authority gate remain false.

This report supersedes the initial read-only audit previously stored at this path. The repair lane was deliberately limited to the three inactive V7 Rust modules, their dependency-free source checker/tests, and this report. No README, DESIGN, METHODS, ExecPlan, active router, manifest, family map, version/backend map, consensus type, Cargo file, or production state path was edited. No Cargo, rustc, rustfmt, build, or proof-generation command was run.

## Verdict

The five assigned source-level findings are repaired within the inactive diagnostic seam:

1. Each active ciphertext is now bound byte-for-byte to its statement slot by an exact, conventional RFC 7693 BLAKE2b-448 frame. Same-length mutations of both output slots reject with `CiphertextHashMismatch`; inactive output slots remain uniquely empty/zero.
2. The retained lifecycle test now composes one artifact through wallet preparation, RPC decode, peer wire, mempool staging, durable row, restart decode, restarted-mempool restaging, mining selection, block wire/decode, sync wire/decode, reorg detach/reattach, fresh-node wire/decode, and import validation. It no longer branches the pre-restart staged object into block construction.
3. The diagnostic key is now an exact `InactiveSmallwoodV7ProspectiveActionId56`, derived from a frozen BLAKE2b-448 canonical-public-args frame. The only exposed 48-byte boundary returns `LiveActionId48AliasingForbidden` unconditionally; no truncation, padding, hash-again, `From`, or `TryFrom` adapter exists.
4. Wallet and every node decode boundary take a caller-supplied expected activation context and compare network ID, chain ID, genesis ID, and rules hash exactly against the statement. Route/backend/profile/domain constants remain separately exact.
5. The checker now lexes around Rust comments/string literals, checks exact fail-closed function bodies, exact decode/re-encode paths, numeric as well as symbolic route leaks, action/manifest/family/version isolation, live 48-byte stablecoin boundaries, ciphertext/action-id frames and KATs, the restart-composed stage order, 80 mask/mode cases, and the active builder regression. Sixteen dependency-free tests include counterfeit mutations of every major checked boundary.

This does **not** activate or qualify V7. All production/admission/relay/durable/mining/import/sync/reorg/fresh-node/restart flags remain false, every state-mutating seam still returns one unconditional `ProductionInactive` error, and the verifier still returns one unconditional `VerifierUnavailable` error. Enabled stablecoin statements still reject because the prospective 56-byte fields have no exact live 48-byte authority refinement.

## Frozen hash and wire rules

Ciphertext hash (`protocol/shielded-pool/src/inactive_smallwood_v7.rs:603`):

```text
u16be(56)
|| "hegemon.smallwood.v7-zeta.ciphertext-hash.blake2b-448.v1"
|| u16be(circuit=7) || u16be(suite=6)
|| u16be(family=1) || u16be(action=9)
|| u8(backend=3) || u8(profile=4) || u16be(domain_set=3)
|| u8(output_slot) || u32be(ciphertext_len) || ciphertext
```

The native-output digest is 56 bytes. Retained KATs are:

```text
slot=0, ciphertext=010203
ab43a16e1a4065c19ea17b28c3d11dcf9490d3233d42f6dd84e0e1df3d9ebbc733cced56ef46acbe09cd0bdadd1883048164fd34e89d93fd

slot=1, ciphertext=04050607
05d199e09eb96fa9a7d0faa485bd3d8baabaf762b733e1f77718b223294cf81c6ec0fcb63d155226205f5511a3595c0ec310cb6838a938b2
```

Prospective action ID (`protocol/shielded-pool/src/inactive_smallwood_v7.rs:731`):

```text
u16be(72)
|| "hegemon.smallwood.v7-zeta.prospective-consensus-action-id.blake2b-448.v1"
|| u64be(canonical_scale_public_args_len)
|| canonical_scale_public_args
```

The retained complete-action KAT is:

```text
89f518fd94c52815f6f8a7504718bdc3ee27c77b1361ebbedae2819d2077d70c7c00270a33d8409ef25a88247ee24c8d889023944fe66017
```

Statement width remains exactly 893 bytes. Envelope, SCALE action, lifecycle record, durable key, and RPC base64 boundaries retain exact consumption and canonical re-encoding checks. The diagnostic arithmetic remains:

```text
transport budget             2,097,152 bytes
opaque proof maximum         2,091,807 bytes
envelope maximum             2,092,730 bytes
max SCALE public args        2,097,032 bytes
public-args headroom               120 bytes
max SCALE lifecycle record   2,097,094 bytes
record decoder ceiling       2,097,280 bytes
```

These are transport ceilings, not measured proof sizes or production consensus caps.

## Lifecycle and negative coverage

The typed source-only chain is defined at `node/src/native/inactive_smallwood_v7.rs:212-428`; restart-to-mempool and mining transitions are at `:328-348`, sync/reorg/fresh-node transitions at `:366-428`, and all authority sinks remain unconditional errors at `:441-488`.

The Rust source test at `node/src/native/inactive_smallwood_v7.rs:637` enumerates all 16 activity masks and these five private proof-mode tags: `SingleKey`, `AccumulatorInit`, `ApprovalStep`, `ValueLockCreation`, and `FinalThresholdSpend`. It compares proof bytes at wallet, RPC, peer, staged mempool, restart, restarted mempool, mining, block, sync, reorg detach, reorg reattach, fresh node, and import. These tags exercise opaque-byte transport only; they do not establish authorization-relation semantics because no V7 verifier exists.

Negative Rust source tests retain:

- same-length ciphertext mutation in both output slots (`protocol/shielded-pool/src/inactive_smallwood_v7.rs:983`);
- prospective action-ID mutation and unconditional live-48 rejection (`:1022`);
- all four expected activation-context mismatches (`:1087`);
- durable-key, durable-value, block, sync, and fresh-node mutations (`node/src/native/inactive_smallwood_v7.rs:728`);
- exact-context mismatch at RPC, peer, restart, block, sync, and fresh-node decode (`:797`);
- every state mutator/verifier plus every false flag (`:834`).

The dependency-free Python reference test independently encodes the exact statement, envelope, canonical SCALE action, BLAKE2b-448 action ID, lifecycle record, durable key, and canonical base64 for all 80 mask/mode cases (`scripts/test_check_inactive_smallwood_v7_lifecycle.py:63`). It also verifies the 2 MiB arithmetic and counterfeits production flags, raw-proof builder regression, literal router/manifest/family/version admission, indirect mutation, ciphertext equality removal, context equality removal, SCALE/base64 laxity, action-ID framing drift, a 56-to-48 adapter, a pre-restart block branch, and mask/mode coverage loss.

## Active isolation and builder audit

The hardened gate found no V7 symbol, magic, or literal `(family=1, action=9)` admission in the active router, kernel manifest, family action constants, version/backend dispatch, or admission module. It found no inactive mutator/verifier call site outside the inactive owner and no inactive sidecar, receipt, or cache validity field. Active pending/action/stablecoin types remain 48-byte-owned.

The active `StarkProver::prove_submission_artifact` / `ShieldedTxBuilder::build` change remains statically intact: the exported builder calls the complete native-artifact helper, the helper builds and decodes the artifact, contains the native verifier call, and returns `built.artifact_bytes`; the raw `prove()` API remains raw. No production `ShieldedTxBuilder::new` caller exists outside its own documentation. This lane did not edit either active file and did not compile or run them.

## Source-only verification

Commands and observed results:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_inactive_smallwood_v7_lifecycle.py
PASS

PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts.test_check_inactive_smallwood_v7_lifecycle
Ran 16 tests in 5.909s - OK

dependency-free Rust delimiter-balance check over the three inactive modules
3/3 PASS
```

No Cargo/rustc/build command was run. Consequently, Rust type checking, Rust test execution, real database restart, real mining/block import, network relay/sync, reorg persistence, and fresh-process behavior remain unverified.

## Remaining release blockers

- V7 has no proof verifier, verifier refinement, production relation authorization, composed PQ/QROM certificate, complete-ZK certificate, measured retained proof artifact, release manifest, or fresh-genesis admission authority.
- The lifecycle stages are pure inactive codec simulations, not calls into production RPC, network, sled, miner, block, sync, or reorg machinery.
- The five authorization modes are opaque proof-byte transport cases only.
- Enabled stablecoin is deliberately impossible until an exact prospective 56-byte manifest/action grammar and admission comparison exist; live 48-byte values must never be adapted.
- The prospective action ID is a frozen candidate grammar, not an active `ActionId48` or an admitted consensus index.
- Source checking is a stronger drift/counterfeit gate, not Rust compilation, call-graph proof, or formal refinement.

## Repaired source snapshot (SHA-512)

```text
d5f6d273681730f9b4ab98d38968d265764201c5cf8d869aafa3b7dbf0cc28bedd5f0551af070846d1c28e90997dd032ba76174a89d43e4563c2f2d78538fd36  protocol/shielded-pool/src/inactive_smallwood_v7.rs
19d4afbea3ac624196cb3226d7958c3a9b039b5a1421ec572d6dec696d5fb14d298028baa7d83f60b18db00d0bf9405306524b57c5c49aa87a8c23dd090c28ae  wallet/src/inactive_smallwood_v7.rs
be135c11eedaa732f83e6d876f3ea8ba631208eaec75d37800ae33a5b151a3de7f89a1ddd9022b259f9586bf1e2ed781549bcc692409d01aa4175f9f0042668e  node/src/native/inactive_smallwood_v7.rs
539ced4c7b3151ccdbb24936ee62179ce5ad6429016da3d152ec1bd7d83ef0d66df65a5019b92ca71f44064111af592967b0de74c0851995d98521a68ff5a6b5  scripts/check_inactive_smallwood_v7_lifecycle.py
addf60bbc04cd7dacd7bfac9a80dabdc405736e8d8330cf21a8e4c2c8194dc08789280bb4420ff26f73abc7406c2c300723c3aa3454e1d30dbdc83d123781f62  scripts/test_check_inactive_smallwood_v7_lifecycle.py
```

Audited but not edited in this repair lane:

```text
4f78dce09d10fe8a3faa876a8537200d28882e1992f4a63634989243ab35e7bd50355db1f81721f68ae24a4a2edd6abecd32cbc841a96f74db962c09b794990d  wallet/src/prover.rs
61f8e57ff5e0a90f78511242988509147a399895cbc514dbd64f7f94833e8300aa433ef1a8ef6a076bbabe101efbbac3c6f803b7edd6b756c31e870a41116c64  wallet/src/shielded_tx.rs
```

Because this is a shared dirty checkout, these hashes identify the exact bytes checked in this lane and must be refreshed after any concurrent edit.
