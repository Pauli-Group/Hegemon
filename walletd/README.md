# walletd controlled-asset operator flow

This is the local **Development** recovery profile. It grants no production
capability. HGN and assets without a genesis recovery opt-in keep their existing
routes. No runtime registration, retrofit, archive-key rotation or expansion of
genesis maximum powers is exposed.

Builds from a fresh clone begin with `make setup` and `make node`. The recovery
operator additionally needs a walletd built with `development-assets` and a node
built with `development-candidate` (the coordinator performs resource-bounded
builds). The commands below describe operator use; they are not a claim that a
CLI process or full proof lifecycle has passed qualification.

## Request transport and approval

Use `walletd --store PATH --mode create --request-file request.json` once, then
`walletd --store PATH --mode open --request-file request.json`. Enter the wallet
passphrase as the first stdin line. Each file contains one JSON request:

```json
{"id":1,"method":"recovery.help","params":{}}
```

The same methods work in the persistent JSON-lines daemon. `--help` and
`recovery.help` list them. JSON requests keep the existing 8 MiB bound. Large
published carriers and generated actions use bounded **binary files**, not
hex embedded in a request. Action output uses exclusive creation with Unix mode
0600 and `sync_all`; existing files are never overwritten.

A mutating request needs explicit `confirm:true`. Proving also needs the exact
`expected_parent_hash` and recovery `expected_epoch` just inspected by the
operator. Administration submission needs the exact `expected_action_id`
returned when preparing the file. These fields bind the operator request; they
are not an independent signing device or interactive approval service. The user
must control request creation and the local process. No agent is assigned a key,
auto-approval authority or permission to create further operations.

Secret-bearing request files are local operator inputs. Protect them with 0600
permissions and do not put them in source control or public receipts. Use only
independent disposable keys for the recipes below. Responses contain public
commitments/statements/positions, never archive plaintext, shared-NF seeds,
issuer, administrator or delegate secrets.

## Fresh opt-in before issuance

Keep four roles separate:

| Role | Private input | What it authorizes |
| --- | --- | --- |
| Issuer | seven-field `issuer_secret` | Mint under the existing issuance/accounting rules |
| Policy administrator | seven-field `admin_secret` | Credential/whole-asset controls; proof-backed recovery governance |
| Recovery delegate | seven-field `delegate_secret` | Transfer/burn only while its current commitment, powers and credential permit |
| Archive provider | independent 32-byte `archive_key` | Decrypt recovery material and prove delivery capsules; **no action authority** |

`recovery.roles` accepts either or both `archive_key` (64 lowercase hex digits)
and `delegate_secret` (seven canonical field words), with at least one required.
It returns only `archive_key_commitment`, `delegate_action_commitment` and
`delegate_credential_owner` for the supplied roles. The last two are the **same
seven-word commitment**; do not hash it again when creating its credential.
Archive providers must authenticate that their key matches the immutable public
commitment through a trusted operator channel. The local provider checks this
binding before constructing any output. Holders can use the cooperating process
provider below without obtaining the archive key. Key availability and
confidential, authenticated delivery of recovery material to its custodian remain
operational premises; walletd does not supply a remote key-provisioning service.

1. Obtain full V8 recipient addresses with existing `asset.address {"index":0}`
   for each disposable wallet. The address index is persisted before disclosure.
2. Use existing `asset.credentials` with `asset_id`, `policy_version`, `depth:4`
   and entries `{index,recipient,expires_at,owner?}`. Ordinary holder/output
   credentials use the full address authority by default. The delegate's entry
   uses its chosen receiving address and **explicit** `owner` equal to
   `delegate_credential_owner` from `recovery.roles`.
3. Use existing `asset.row` with `disposable:true`, `asset_id>0`,
   `policy_version`, distinct issuer/admin secrets, the resulting credential
   root, and `credential_depth:4`. Save its public `descriptor` as `assets.json`
   and its canonical public `row` for the next request.
4. Call `recovery.setup` with `rows` containing one to sixteen sorted entries:

```text
asset_row                   canonical 552-byte lowercase hex from asset.row
stable_policy_id            seven canonical, nonzero public field words
archive_key_commitment      seven words from recovery.roles
delegate_action_commitment  seven words from recovery.roles
maximum_transfer            bool (immutable ceiling)
maximum_burn                bool (immutable ceiling)
transfer                    bool (initial current power)
burn                        bool (initial current power)
revoked                     bool (initial current disable flag)
```

Save only its result as `recovery.json`. Setup requires zero issuance/accounting
counters and depth4, rejects HGN and powers outside the maxima. The selected node
manifest performs its own exact source/geometry/old-row checks. The genesis
freeze root is derived by the node after network selection; setup does not
install a mutable root or take an arbitrary caller-supplied freeze root.

Generate the manifest with the actual node CLI:

```sh
hegemon-node --print-development-candidate-manifest \
  --development-funding-address FULL_V8_ADDRESS \
  --development-assets-json assets.json \
  --development-recovery-json recovery.json > manifest.json
hegemon-node --dev --base-path DISPOSABLE_NEW_PATH \
  --network development --network-manifest manifest.json \
  --development-candidate --rpc-methods unsafe
```

Manifest generation must not include `--development-candidate` or
`--network-manifest`. Use an isolated fresh base path and trusted loopback RPC.
For shared mining, all peers must deliberately use the same network manifest and
approved `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`;
otherwise use a fully isolated Development rehearsal. Keep NTP/chrony enabled:
future-skewed PoW timestamps reject. Do not point this fresh Development identity
at an unrelated public network. No recipe changes consensus time, maturity or
retarget validation.

## Pin, sync and inspect current state

Use existing `asset.sync` with `ws_url`, `manifest` and `expected_genesis` (the
operator-verified 32-byte lowercase genesis hash). It authenticates the selected
manifest and replays canonical actions into the encrypted store, including ARN1
holder outputs and native fee change. Repeat after inclusion, restart or reorg.
Do not reset a wallet or discard its pending journal to manufacture a free input.

All online `recovery.*` requests repeat these three fields. They construct the
Development authority from current node configuration/parameters and require it
to match the wallet's pinned context. Readback must have exactly the wallet's
current canonical height, hash and note root.

- `recovery.info` additionally accepts optional `asset_id` and `position`.
  Position requires an asset. It returns selected parameters, current rows,
  epoch/powers/revocation and the exact canonical note's sparse32 freeze witness.
- `recovery.notes {}` returns owned recovery-note summaries plus mature native
  fee-note positions. `recovery.journal {}` returns durable recovery attempts.
- `recovery.inspectInput` adds `asset_id`, `position`, `input_action_file`,
  `input_output` (0 or 1), and `archive_key`. It decrypts locally, checks the full
  material/context/CM against the exact canonical occurrence, and returns only
  public value/CM/common NF/epoch/frozen status. It grants no spending authority.

`input_action_file` is either the exact inner `HGARCV02` spend body exported by
`recovery.export`, or one exact SCALE canonical PendingAction carrying action18.
It is not JSON, a whole block, a SCALE vector of actions, or an arbitrary capsule.
The existing node API can supply canonical bodies using `chain_getBlockHash`
then `chain_getBlockActionsChunk`; `NodeRpcClient::canonical_block_actions`
reassembles them. There is no RPC index mapping `(asset_id,position)` to its
creation carrier. The issuer/archive operator must retain that mapping or supply
a scanned published carrier and its canonical note position. Commitment-only
readback cannot recover the archive ciphertext. This flow deliberately does not
build a general indexer or depend on holder decryption.

## Prepare mint, ordinary holder actions and forced transfer/burn

`recovery.prepare` has these exact fields:

```text
ws_url, manifest, expected_genesis          strings, as above
expected_parent_hash                       32-byte lowercase current parent hash
expected_epoch                             current recovery epoch u64
confirm                                    true (explicit operator authorization)
asset_id                                   nonnative u32 selected at genesis
operation                                  "mint", "transfer" or "burn"
route                                      "mint", "holder" or "delegate"
amount                                     positive integer below 2^56
fee                                        native integer below 2^56
fee_position                               mature owned native note position u64
recipient                                  full V8 payment address (also for zero burn output)
change_recipient                           optional full V8 address; REQUIRED for delegate
native_change_index                        optional u32, default0, issued in this wallet
archive_key                                optional local immutable archive key, 32-byte lowerhex
archive_provider                           optional {executable,args,timeout_seconds}; see below
credentials                                exactly3 {index:u32,expires_at:u64,siblings:[D;4]}
input_position                             required real-input canonical u32 for holder/delegate
input_action_file, input_output             required only for delegate archive lookup
issuer_secret                              required seven-field secret for mint
delegate_secret                            required seven-field secret for delegate
delegate_credential_recipient               required delegate's full V8 address
```

Supply **exactly one** of `archive_key` and `archive_provider`. Mint and holder
transfer/burn support either. The current delegate carrier-decryption flow and
`recovery.inspectInput` require the explicitly privileged local `archive_key`;
provider-assisted input decryption is not implemented.

`D` is exactly seven canonical u64 field words, each below
`18446744069414584321`. The three credential slots are selected actor, payment,
asset change. For mint, slot0 is the canonical dummy
`{"index":0,"expires_at":0,"siblings":[]}`; the builder pads its four zero
siblings. Every active credential must use depth4 and expire at or after H+12.
Payment/change credentials remain mandatory even for zero-valued outputs. Use
`asset.credentials` to obtain exact paths for the currently installed root.

For a forced transfer use `operation:"transfer",route:"delegate"`; the consumed
value becomes `amount` at `recipient` plus the remainder at explicit
`change_recipient`. For forced burn use `operation:"burn",route:"delegate"`;
payment is zero and `input_value-amount` goes to explicit change. The proof's
burn magnitude is `amount`; transfers have zero issuance magnitude. Native HGN
fee accounting is separate. Forced actions require the current delegate secret
and its **current delegate credential**, rather than the original holder's
credential. They do not obtain the holder's ordinary spend key.

The CLI checks current power/revocation, local archive-key commitment when used,
material and canonical position/CM. A process provider's capsule is checked against
the authenticated immutable archive commitment and exact output context. Actual lowering/proofs also enforce shared NF, full owner,
balances, current actor/output credentials, immutable maximums/current powers,
and the empty sparse32 leaf at the consumed note position. Whole-asset freeze
rejects both holder and delegate spends. A targeted frozen note must be
proof-backed unfrozen first; there is no recovery override.

Mint uses `route:"mint",operation:"mint"` and the separate issuer secret.
Holder transfer/burn uses a note recovered into this wallet and its own spend
key. Old `asset.prepare` is preserved for assets using the older route and must
not be used for opted IDs.

Preparation reserves exact common nullifiers and the real owned fee before
capsule/proof generation. Each output has its own real two-component capsule
proof and the spend has a real proof: five components total, each at most2 MiB.
The new finite envelope cap applies only to the typed recovery route; ordinary
caps are unchanged. Output notes use fresh OS entropy and holder ARN1 delivery.
No synthetic proof, hash receipt or RPC boolean can become a retained candidate.

The response is a durable `reservation_id`, public182-word statement and parent.
Use `recovery.export {reservation_id,action_file}` to save the exact retained
public action bytes in a new mode0600 file. This archival read remains available
after inclusion, reference expiry or an orphaned reference, including after a
wallet restart; it does not make those bytes eligible for resubmission. Proving,
abandoned, missing, empty or identity-mismatched records cannot be exported.
After reviewing the public statement, call `recovery.submit` with the online
fields, that ID and `confirm:true`. It marks durable submission uncertainty
before sending exact retained bytes, and records the acknowledgement. All
submission failures preserve the hold. A retry uses the same ID/bytes. Reproof
requires sync plus explicit `recovery.abandon` under the existing stale-reference
rules; rollback can reactivate its tombstone. Keep the local inclusion parent
stable during proving/submission; a stale candidate does not authorize a new row.

## Cooperating archive provider without distributing its key

For a holder or issuer request, replace `archive_key` with this field; retain all
other `recovery.prepare` fields, current credentials and explicit approval:

```json
"archive_provider": {
  "executable": "/absolute/pinned/walletd",
  "args": ["--recovery-archive-worker", "--archive-key-file", "/private/archive/key.bin"],
  "timeout_seconds": 600
}
```

`executable` must be an absolute operator-approved executable. `args` is a vector
of literal arguments, never a shell command. The optional response timeout is
1–1800 seconds, default600, **for each capsule request**. There are two output
capsules. The existing operator/job deadline must also cover the complete spend
proof. This timeout does not make filesystem access or OS process creation
cancellable and does not change a network or proof capability.

The archive operator provisions an independent, uniformly random 32-byte key,
keeps it in its own custody, and supplies only its authenticated commitment for
the genesis descriptor. Worker `--archive-key-file` configuration is a provider
argument, not a field in the protocol request. The current worker requires one
unchanged regular, non-symlink Unix mode0600 file containing **exactly32 raw
bytes**, not hexadecimal text. Protect its directory and backups; never put key
bytes in argv, environment variables, public logs or a holder request. The worker
checks that the actual local key matches the requested immutable commitment
before any proof. The holder independently authenticates that commitment from
the selected manifest/current snapshot and verifies every returned proof.

The bundled worker mode is:

```text
walletd --recovery-archive-worker --archive-key-file /private/archive/key.bin
```

It is available with `development-assets` on Unix. It starts before wallet/store
or passphrase handling and uses no node connection. It accepts exactly one raw
JSON document on private stdin and emits exactly one raw JSON document on
private stdout. Do not send a normal walletd envelope or passphrase. It accepts
no operation or signing request. Normal walletd JSON methods remain unchanged.

Protocol schema is `hegemon.recovery.archive-provider.v1`, method
`recovery.archiveProve`. The holder serializes only:

- `descriptor`: `asset_id`, seven-word `stable_policy_id`,
  `policy_admin_commitment`, `archive_key_commitment`, and booleans
  `maximum_transfer`, `maximum_burn`;
- `context`: 32-byte-array `chain_id`, `asset_id`, seven-word `stable_policy_id`
  and `output_commitment`;
- `material`: exactly30 canonical u64 words from the existing validated recovery
  codec, including the independent shared-nullifier seed.

The top-level fields are `schema`, `method`, `descriptor`, `context`, `material`.
All levels reject unknown fields. No ordinary holder spending key, issuer secret,
policy administrator secret, delegate action secret or wallet passphrase enters
this DTO. The provider intentionally learns the recoverable opening and shared
NF material, including zero-valued output material. That knowledge alone grants
no holder/issuer/delegate authorization.

The response has only `schema`, `public_words` (the exact82-word capsule public
statement), and `proof_hex` (canonical lowercase complete two-component `SMRC`
proof collection). Both actual component verifiers run through
`CapsuleTransportV1::from_untrusted` against the **original** descriptor/context,
including archive commitment and output CM. A worker's success exit, hash,
ciphertext alone, wrong-context statement, synthetic proof or receipt is
insufficient. The output still enters the existing five-component action and
unchanged current-state checks.

The adapter starts one directly owned child per output, preserves the resource
guard's process group, and clears inherited environment except a fixed
`RAYON_NUM_THREADS=2`. It uses private timeout-enabled Unix standard streams,
closes stdin, drains stdout concurrently, caps requests at16 KiB and responses at
`2*MAX_CAPSULE_BUNDLE_BYTES+4096`, and requires successful exit plus EOF. Every
return path kills/reaps the directly owned child and cancels/joins the reader.
Stderr is discarded and errors are fixed public classifications; raw child
output, parameters and secrets are never added to a wallet response or log.
The bounded stream cancellation also handles inherited descriptors; this is not
an arbitrary descendant-process supervisor. Abrupt parent termination does not
run Rust cleanup; the outer supervisor must signal/reap the owned process group,
including the worker. An approved wrapper must own and clean up any descendants
or remote jobs it starts.

A same-UID local test with this key-file path proves that the holder wallet
process does not load the archive key. It provides **no OS isolation from the
operator or other same-UID processes that can read that file**. Actual separate
custody requires an archive-operator security context and authenticated,
confidential transport to that context. The explicit executable may be an
operator-approved wrapper that forwards this protocol there and privately
configures its worker key; walletd does not deploy such a service, configure SSH,
provision credentials, or establish remote identity. The wrapper must work with
the cleared environment and enforce its own peer authentication and availability
policy. The existing key-entropy, custody, availability and cryptographic
assumptions remain in force.

A provider failure occurs before a candidate is retained. Preparation uses the
existing cancellation of its unexported `Proving` reservation; if persistence
fails, inspect the returned reservation ID/journal and keep the hold. Submission
uncertainty handling and exact-byte retries are unchanged. Provider availability
never authorizes fallback to missing capsules or a different archive commitment.

## Target freeze, unfreeze, rotate and revoke

`recovery.adminPrepare` uses online fields, `asset_id`, `expected_parent_hash`,
`expected_epoch`, `confirm:true`, seven-field `admin_secret`, `expires_at`,
seven-field fresh nonzero `action_intent`, and new `action_file`. It always
increments the current recovery epoch by one and preserves the immutable
asset/policy/admin/archive/max-power descriptor.

| `operation` | Additional field | Exact effect |
| --- | --- | --- |
| `freeze` | `position:u32` | Existing canonical note CM at this position becomes frozen |
| `unfreeze` | `position:u32` | Same occurrence becomes unfrozen |
| `rotate` | `new_delegate_commitment:D` | Replace action commitment; preserve revoked flag |
| `revoke` | none | Set revoked=true; preserve commitment |
| `enable` | none | Set revoked=false, requiring valid nonzero commitment |
| `powers` | `powers:{transfer:bool,burn:bool}` | Update current bits within immutable maxima |

The key is the **canonical note position32**, with asset and current note CM
bound into the real sparse32 path and proof. It is not a subject ID or arbitrary
wallet freeze key. No-op freeze/unfreeze rejects. Non-freeze operations use the
required zero path padding and preserve the freeze root. Rotation does not
rotate or erase the immutable archive key, and revoke does not disable holders.

The real administrator proof is self-verified and written to the new binary
file. Review returned public128 words and `administrator_action_id`; then call
`recovery.adminSubmit` with online fields, `action_file`, the exact
`expected_action_id` and `confirm:true`. It checks the actual proof and exact
current parent/row before action19 submission. Expiry does not permit an old row
or epoch to replay. Reorgs restore the canonical state and consumed-action set.

Credential-root replacement, mint enable and whole-asset freeze/unfreeze remain
existing proof-backed `asset.adminPrepare`/`asset.adminSubmit` (or explicit
`asset.admin`) operations. These ordinary policy controls do not rotate recovery
epoch or bypass note freeze. Refresh/sync and obtain new current credential
witnesses after each change.

## Acceptance recipes (coordinator, disposable stores only)

The staged `check_cli_process.py --walletd /absolute/path/to/walletd` performs
bounded offline process/help/dispatcher/schema/role/setup tests in a temporary
wallet, with no network/proofs or real keys. It must be run against the rebuilt
binary; merely reading this README is not acceptance.

The coordinator should additionally run the focused wallet tests with
`--features private-spend-dev-artifacts`:

- `delegate_reservation_api_binds_context_material_position_nf_and_atomic_journal`
- `holder_delegate_reservation_apis_conflict_on_common_nf_in_both_orders`

They call the reservation APIs using a validated canonical mirror and mature
native fee notes. The restart fixture uses explicitly invalid proof framing only
after asserting production retention rejects it; it tests journal uncertainty,
not proof acceptance. Also run the recovery schema/role tests and actual
source-gated native lifecycle coverage. A genuine
CLI proof recipe is: create/pin/sync a funded disposable wallet; install matching
current credentials; mint via `recovery.prepare`/submit; sync; export and inspect
the canonical note; prepare/submit forced transfer and burn with current delegate
credentials; freeze/reject/unfreeze; rotate/reject old key; revoke/reject current
key; restart/reorg/sync and check exact journal holds/state. Capture exact source,
binary, action and receipt pins. Do not turn an interrupted or library-only run
into a passed CLI lifecycle claim.
