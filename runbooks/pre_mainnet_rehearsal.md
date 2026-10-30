# Pre-mainnet network rehearsal

The native binary selects a new network with `--network pre-mainnet --network-manifest PATH`. This is a fresh consensus identity. The public manifest contains the exact genesis parameters and funding recipient. Every peer, wallet and release artifact must agree on its resulting 32-byte chain ID. Network selection alone does not activate a proof family, authorize a release or qualify paid mining and swaps.

## Freeze the public network manifest

For the actual pre-mainnet, use the operator-approved single-key treasury address after an encrypted backup and successful restore/address rehearsal. Keep the wallet and passphrase outside Git, retain the backup checksum independently, and store a copy on separate encrypted storage. Do not generate a replacement key during manifest preparation. Disposable rehearsals may use their separately generated test recipients. Use the canonical V8 address, including the full authorization policy and encryption public key, in a manifest with these fields in this schema:

    {
      "schema": "hegemon.native.network-manifest.v1",
      "profile": "pre-mainnet",
      "genesis_timestamp_ms": <fixed positive integer milliseconds>,
      "pow_bits": <qualified positive canonical Bitcoin compact target as an integer>,
      "rules_hash": "<lowercase 64-hex compiled active rules hash>",
      "launch_reference_rules_hash": "<lowercase 64-hex compiled launch reference rules hash>",
      "funding_address": "<canonical public V8 treasury address>",
      "funding_subsidy_numerator": 1,
      "funding_subsidy_denominator": 5
    }

This is a schema illustration, not an executable manifest. A generated manifest must contain actual values. Finalize the combined reward, HTLC and proof consensus rules before freezing both rules fields. `rules_hash` retains the compiled header rules value. Mandatory `launch_reference_rules_hash` separately commits the base rules, the 12-parent RP06/Claim/Refund window, age-zero HTLC Lock, block-end roots, static stable roots, actual-inclusion source checks and fork-bound receipts. The node rejects unknown fields, either missing or mismatched compiled rules field, invalid target encoding, a non-V8 recipient, missing funding or a fraction other than 1/5. Formatting and JSON field input order have no effect because the decoder reserializes the typed object in a fixed field order before hashing. The identifier is BLAKE3 over the bytes `hegemon.native.network-id.v1`, a zero byte, and that compact typed JSON.

The funding policy's public keys and threshold do not include the resulting network identifier. The manifest already contains that policy's address. Operation intent and proof public context bind the full identifier separately, avoiding a circular address calculation. Private signing keys and wallet secrets must never enter the public manifest.

The new mandatory launch field changes the canonical typed JSON, explicit network ID and manifest digest even when every older field matches. Old explicit manifests reject and must be regenerated with matching wallet/release identities. Omitted-profile legacy identity and existing header rules bytes remain unchanged. Changing the recipient, genesis timestamp, target, either rules field or profile changes the network ID. Use a new base path after such a change. Reopening another network's database is rejected; old testnet state is preserved for rollback rather than migrated or relabeled.

## Start the isolated candidate

Use a qualified, pinned candidate binary. Local and dev deployments use separate release directories and the proposed isolated P2P port 30335/RPC port 19944. Keep clocks synchronized with NTP or chrony; timestamps beyond the future-skew bound are rejected.

At deliberate first-author bootstrap, with a disposable mining payout address:

    HEGEMON_MINE=1 \
    HEGEMON_MINE_THREADS=2 \
    HEGEMON_MINER_ADDRESS='<public qualified V8 mining address>' \
    HEGEMON_BOOTSTRAP_AUTHORING=1 \
    /opt/hegemon/pre-mainnet/bin/hegemon-node \
      --network pre-mainnet \
      --network-manifest /etc/hegemon/pre-mainnet/network-manifest.json \
      --base-path /var/lib/hegemon/pre-mainnet \
      --port 30335 \
      --rpc-port 19944 \
      --rpc-methods safe \
      --name hegemon-pre-mainnet-dev

This first-author setting is deliberate and must not be copied into ordinary joining instructions. New joiners instead set `HEGEMON_SEEDS` to the exact release-approved new-network list and omit `HEGEMON_BOOTSTRAP_AUTHORING`. All miners on one network use the same approved list. Do not reuse the old network's 30333 seed endpoints for pre-mainnet. During steps 1–6, the release coordinator verifies and publishes the local/dev endpoint list; OVH remains on the old network until its separate handover.

`--dev` cannot override the pre-mainnet or mainnet manifest. The selected PoW target comes from the manifest. The native CLI supports `--base-path`, `--port`, `--rpc-port`, `--rpc-methods`, `--name`, `--network` and `--network-manifest` as shown. RPC remains loopback unless `--rpc-external` is selected deliberately.

## Read back identity and qualify behavior

Query the native RPC compatibility interface after startup:

    curl --fail --silent http://127.0.0.1:19944/ \
      -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"hegemon_nodeConfig","params":[]}'

The response includes `networkProfile`, `chainId` and `networkManifest`. Compare the manifest readback and chain ID across every candidate node. Query `chain_getBlockHash` with parameter 0 to compare genesis and inspect advancing canonical heights and hashes. Peer signatures and secure-session keys bind the selected ID, so peers from different manifests fail before admission. Stored chains, block imports and body locators independently check it.

Generate the public wallet context directly from the validated node readback;
do not calculate or hand-copy the manifest digest or genesis hash. Use a new,
nonexistent output path because the helper creates it exclusively with mode 0600:

```sh
python3 scripts/development_wallet_context.py \
  --rpc http://127.0.0.1:19944 --out <NEW_CONTEXT_JSON>
```

The helper accepts only a loopback Development candidate, reads
`hegemon_nodeConfig` and `chain_getBlockHash(0)`, validates the returned chain
ID, manifest digest, candidate window, and stablecoin root, then writes the
matching `launch_wallet_prepare` context. Keep this file with public rehearsal
inputs; it carries no wallet secrets.

An advancing chain of empty blocks proves only network mechanics. Step 6 additionally requires accepted, paid rewards to both miner and treasury, spending those receipts, qualified network-bound transfers, single-key treasury spending, HTLC claim/refund, restarts, reorganization and fresh-node synchronization. The historical 2-of-3 custody fixture remains separate evidence and is not a launch requirement for the selected single-key treasury. Controlled assets, privileged asset recovery and merge mining remain disabled; verify their rejection before opening the network. Preserve unchanged full proof carriers and source-bound lifecycle evidence. Existing V8 transactions and legacy bridge actions reject on explicit profiles until their separately qualified successor routes are integrated. HGN/BTC HTLCs do not require enabling the legacy bridge family.

The integrated source at `d001d80fd` admits RP06, HTLC Claim and Refund only from a canonical block-end reference H to an inclusion parent P with `0 <= P-H <= 12`, giving inclusion heights H+1 through H+13. Reference checkpoints begin at activation minus one. Lock requires P=H. Block-end roots include transaction outputs and both final rewards. The source capability separately gates the exact proof route and actual inclusion height in `[activation, end)`; typed state replay permits empty blocks and trailing reward commitments across that interval's boundaries, while complete native reward actions retain their separate source activation/retirement gates. Typed state fixtures do not authorize reward routes. These are source rules requiring affected qualification. No production proof capability is installed, and this runbook is not release authorization.

## Retained optional 2-of-3 treasury and atomic-swap rehearsal

Run these steps only with an isolated Development manifest, synchronized disposable
wallets, and private scratch directories. Use generic local placeholders below and
resolve them on the operator host; never commit wallet paths, passphrases, private
addresses, openings, preimages, or generated receipts.

1. Inspect signer notes and attempts with `treasury-v8 notes` and
   `treasury-v8 attempts`. Each approving signer needs a positive ordinary
   capability note; set the approval fee as a separate reviewed input. Review the exact plan recipient, amount, fee, source,
   and chain id, then confirm the complete 128-hex SHA-512 digest independently in
   each signer wallet.
2. Use `development_treasury_rehearsal.py` for the sequential two-approval and
   finalization workflow. Keep three encrypted signer stores separate. After each
   approval is canonically included, sync all signers to the same trusted node,
   resolve the accumulator with `treasury-v8 canonical-position`, require one
   unambiguous position and identical canonical tips, then export/import that note
   over the private signer handoff. Re-export each retained attempt with
   `recover-candidate` and compare bytes before submission. Submit with the full
   digest. The explicit `--retained-test --runtime-manifest
   <exact-development-manifest>` path is for the matching isolated Development
   node only.

   The automated disposable form accepts the following operator inputs (use fresh
   passphrase files with mode 0600 and a new private directory):

   ```sh
   python3 .agent/pre-mainnet-multisig/development_treasury_rehearsal.py \
     --binary <treasury-v8> --rpc <loopback-development-rpc> \
     --context <public-context.json> --runtime-manifest <development-manifest.json> \
     --account-id <64-hex-account-id> --private-dir <new-private-directory> \
     --source-commitment <112-hex-commitment> --source-position <canonical-position> \
     --recipient <treasury-recipient-address> --amount 50000 --fee <payment-fee> \
     --approval-fee <approval-fee> \
     --signer1-wallet <signer1-store> --signer1-passfile <signer1-passfile> \
     --signer2-wallet <signer2-store> --signer2-passfile <signer2-passfile> \
     --signer3-wallet <signer3-store> --signer3-passfile <signer3-passfile> \
     --signer1-capability <112-hex-commitment>:<position> \
     --signer2-capability <112-hex-commitment>:<position> \
     --automated-disposable-rehearsal --wallet-cli <launch-wallet-prepare> \
     --recipient-wallet <recipient-store> --recipient-passfile <recipient-passfile> \
     --miner-address <configured-development-payout>
   ```

   This disposable automation syncs all three signer stores against the selected
   node before plan creation and after each submitted approval. Never reuse its
   private directory or copy resolved inputs into this runbook.
3. The normal Submit path requires source-owned launch authority. The current RP06
   registry is empty and production submission must fail closed. A retained-test
   receipt records Development execution only. A completed disposable treasury run
   produced approvals at H20/H21 and a 50,000-base-unit final output at H22 in
   144.734 seconds; this is bounded runtime evidence, not a release gate.
4. For an unattended local run that creates the Hegemon chain, the Bitcoin
   regtest chain, and the wallets itself, use `make htlc-swap-e2e`. It covers
   the successful swap, a Hegemon refund when Bitcoin is never funded, refunds
   on both chains, and a Hegemon claim rejected after that refund. Bitcoin Core
   stays on regtest with no peers. The Hegemon node is started with
   `HEGEMON_SEEDS=""` because this chain is isolated; that empty list must not
   be copied onto a shared network. Shared mining operators set
   `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`
   unless the approved list has been rotated, and they keep NTP or chrony
   enabled because future-skewed PoW timestamps are rejected. A passed run is
   not production authority.

   To exercise both cross-chain branches against an already running Development
   node, prepare separate disposable Claim and
   Refund wallets and run `scripts/development_atomic_swap_rehearsal.py` twice with
   `--scenario claim` and `--scenario timeout`. The helper starts an isolated
   loopback Bitcoin Core regtest instance in a new private root, creates the lock,
   mines actual Bitcoin and Hegemon receipts, and checks exact recipient ownership.
   The Claim branch derives the secret from a confirmed Bitcoin witness before
   importing it into Hegemon. It also rejects a wrong secret, a premature Hegemon
   refund, a wrong Bitcoin secret, and a premature Bitcoin refund. The timeout
   branch mines to each chain's own refund height and checks both returned outputs.
   Keep every private root new and empty; review only sanitized public receipt fields.

   Supply the local tools, Development RPC/context/manifest, disposable stores and
   passphrase files, canonical lock position, payout, amount, timeout and a fresh
   private root as follows; use a different empty private root for the second run:

   ```sh
   python3 scripts/development_atomic_swap_rehearsal.py \
     --bitcoind <bitcoind> --bitcoin-cli <bitcoin-cli> \
     --wallet-cli <launch-wallet-prepare> --public-fixture <public-fixture-executable> \
     --hgn-rpc <loopback-development-rpc> --context <public-context.json> \
     --runtime-manifest <development-manifest.json> \
     --claim-store <claim-wallet> --refund-store <refund-wallet> \
     --claim-passfile <claim-passphrase-file> --refund-passfile <refund-passphrase-file> \
     --lock-input-position <canonical-lock-note-position> \
     --miner-address <configured-development-payout> --value <base-units> \
     --timeout-height <hegemon-refund-parent-height> \
     --private-root <new-empty-private-root> --scenario claim
   ```

   Repeat with `--scenario timeout` and another fresh private root. Both scenario
   invocations create their own private Bitcoin Core regtest chain; the script
   accepts only a Development manifest and loopback Bitcoin RPC.

The local treasury and Bitcoin/Hegemon claim/refund executions have passed for
their recorded disposable inputs. A separate two-node Development run also
matched all 24 block-body bytes at H24; a higher-work fork orphaned the HTLC
Claim, rolled back its input/nullifier state, replayed the unchanged carrier at
H26 for 99,997 base units, and reconverged the original peer. An ordinary RP06
carrier relayed from node B to A's mempool, was mined by A at H27, and appeared
once with its exact bytes (recipient owns 27,182 base units). These are disposable
Development observations only. The transport-guard build passed its focused checks. A fresh third node
started at genesis and converged at H27; all 27 canonical action bodies and
the six retained HTLC/ordinary carriers matched exactly across all three nodes.
A graceful restart preserved the fresh node's canonical roots, work, genesis,
and tip, with the complete bodies rechecked afterward. Preserve canonical height/hash, peer, restart, chunk-integrity and reorg
observations in a separate sanitized receipt before treating that lane as
complete; none of these results grants production authority.

The same candidate binary and manifest must pass on local and dev before OVH deployment. Source changes after qualification require the affected checks again. A temporary dev-node archive, service stop or deployment must follow the coordinator's recorded inventory and backup/readback process. This runbook does not authorize a live-host operation by itself.

## Service packaging

`config/pre-mainnet/hegemon-pre-mainnet.service` provides the isolated service layout. Its environment file contains operator-local seed and mining configuration. Supply the qualified binary, final public manifest and a unique base directory before enabling it. Do not overwrite the legacy service, database, wallet or binary. The coordinator records exact hashes and archive evidence for rollback.
