# Reward-account wallet and desktop UX

The `Rewards & treasury` desktop workspace reads the four bounded, read-only
[account APIs](PROTOCOL_TREASURY_EXPLORER_API.md). This UI and the wallet daemon
can derive public identities, prepare actual claim payout proofs, review public
intents and collect signatures. **Native successor startup/admission and
submission remain unfinished.** A prepared package is not a submitted payment,
a confirmed withdrawal or an activated hard fork. The explorer UI/read-only service changes are separately implemented and tested
on [hegemon-website's new branch](https://github.com/Pauli-Group/hegemon-website/tree/codex/explorer-treasury-rewards);
no deployment or activated-node qualification is implied.

## Receiving, mining and balances

On a configured successor network, Receive copies a network-typed shielded
recipient (`heg_shield` or `heg_shield_test`). The mining profile instead uses a
public reward account (`heg` or `heg_test`). Both the checksum and binary network
class/discriminator must match the selected node. Relabeling an HRP does not
convert an address between networks. Public addresses cannot be used as normal
shielded-payment recipients. Contacts can retain either kind, but payment
selection accepts only shielded recipients. Legacy `shca` entry remains available
in an explicitly detected legacy context; a disconnected node is not a valid
network identity.

The workspace separates available public balance, pending epoch rewards and
claimability in the next block. For E=1,440 at snapshot block 2,880, epoch-zero
rewards remain pending but can be claimed in block 2,881 because release happens
before its transactions. These are public, linkable balances, separate from the
wallet's shielded notes. Claim amount plus its signed fee debits the account and
creates one equal-value shielded note, with no additional reward maturity. No
public account-to-account transfer is available. Epoch boundaries do not provide
finality; reorganizations can change balances and claims. Refresh the labelled
canonical snapshot before preparing an operation.

Amounts use exact integer atom strings and eight decimal places per HGN. Entry
rejects exponent notation, fractional atoms, negative amounts and partial numeric
strings instead of rounding them. Supply views distinguish the original genesis
allocation, original mining budget, current issuance and remaining mining
issuance. Genesis allocations are initial values, not current balances.

For shared mining, set `HEGEMON_SEEDS` to
`hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333` unless the approved
list is deliberately rotated; miners must share the same seeds. Enable NTP or
chrony, since timestamps beyond the future-skew bound are rejected. These UX
changes do not start a successor network or reset existing nodes.

## Treasury, claims and offline approvals

The treasury panel displays its fixed public identity, current quorum, signer
hashes, policy generation and any certified pending replacement. The treasury
receives 20% of subsidy only; including miners receive their fees and tips.
Block-derived credits follow earning epoch + 2. Transparent donations become
available the following block and bypass epoch reward buckets.

`Prepare claim` builds a real encrypted payout proof and one local approval to
the wallet's own shielded recipient. Available amount includes the signed fee;
partial claims are supported. Exported claim packages contain their canonical
intent, proof and approvals. They may become stale if the reference, canonical
chain, sequence or treasury policy changes. The node does not currently provide
a submission route for them.

Donation review has separate amount/fee fields and requires acknowledgement that
the amount and optional memo are public. The memo limit is 256 UTF-8 bytes. This
review exports a public intent only: shielded spend selection/reservation, proof
preparation and donation submission still require the native wallet integration.
Implicit block allocations have no memo.

Offline approvals import public claim or treasury-fork packages. The selected
node supplies the expected chain, genesis, configuration and current treasury
authority independently of imported values. Walletd checks canonical encoding,
policy, exact digest, signer membership, signatures and, for claims, the actual
payout proof and its amount/fee/recipient bindings. Treasury review also matches
current policy hash and generation. Verified existing approvals are retained in
sorted signer order; duplicates, altered packages and signatures from other keys
are rejected. The result indicates whether the required quorum is complete.
Canonical inclusion and compiled adoption still require separate native checks;
this is not an ordinary signer-rotation transaction.

## Backup and key recovery

The default public account's ML-DSA-65 key is derived in walletd from the existing
encrypted wallet root. Version 1 uses BLAKE2b-384 domain
`hegemon.wallet.reward-account-key.v1`, binding network class, its 32-byte
discriminator and little-endian account index zero. The renderer receives public
identity data only. `Copy public signer identity` exports the policy, public key,
key hash and addresses needed to arrange a genesis committee. This public data
is not a private-key backup.

Back up the encrypted wallet file and its passphrase. The Backup & recovery tab
creates a separate encrypted wallet with the same keys and issued-address
registry, a fresh scan and no historical notes/balances/attempts. It leaves the
source unchanged and refuses existing destinations, including links. Use a new
passphrase of at least 12 characters. A wallet bound to another genesis must be
recovered separately; it is never silently reset. Reopening/recovering a full
wallet reproduces the same reward identity on the same network. Different
network discriminators derive different identities. Watch-only wallets can read
public state but cannot derive signing identities, claim, sign or recover private
keys. Locking or switching wallets clears sensitive form/review state and ignores
late results from the previous session.

## Daemon and development checks

`walletd --reward-help` describes the JSON methods. Use the existing walletd
stdin protocol or `--store PATH --mode open --request-file JSON` with the passphrase
on stdin, never in a command argument. Read-only `reward.identity` returns public
identity data after checking `network` and `expectedGenesisHash`. Operations are
`reward.prepareClaim`, `reward.reviewDonation`, `reward.reviewIntent`,
`reward.signIntent` and `reward.recover`. There is no `reward.submit` method.
Status capabilities advertise preparation separately from submission.

From the repository root, after loading the Rust environment:

    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app test
    npm --prefix hegemon-app run check:ui-guards
    npm --prefix hegemon-app run build
    node hegemon-app/scripts/test-reward-browser.mjs
    cargo test -p walletd --release --offline reward_ux -- --include-ignored --nocapture
    cargo test -p wallet --release --no-default-features --lib reward_accounts --offline -- --include-ignored --nocapture
    cargo test -p wallet --release --no-default-features --lib recovery --offline
    cargo test -p wallet --release --no-default-features --lib reward_identity --offline

The optional Chromium check requires a local Chromium binary (`CHROMIUM_PATH`
overrides `/usr/bin/chromium`) and permission to bind a temporary loopback server.
It uses explicit test fixtures, exercises the production hook/component, tests
lock races, errors, public memo rendering and recovery form clearing, and captures
1280px/390px renders without horizontal overflow. `REWARD_UX_ARTIFACTS` selects
its output directory; screenshots are not running-network qualification.
Actual real-proof daemon tests check encrypted payout bindings and local
signatures. Two-node admission, persistence, synchronization and reorganization
qualification remain requirements in the parent execution plan.
