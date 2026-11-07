# Local Hegemon HTLC counterparts

These contracts escrow native ETH and ADA for swaps with the current Hegemon
private-spend HTLC. Alice locks HGN for Bob; Bob locks ETH or ADA for Alice.
Alice claims the counterpart asset with a 32-byte SHA-256 preimage. Bob obtains
that preimage from the confirmed counterpart transaction and claims HGN.
A timed-out leg can be refunded by its original owner.

The implementation uses Solidity on a fresh Anvil execution chain and Aiken /
Plutus V3 on a fresh single-node Cardano network. It does not change Hegemon's
circuit, source identity, wallet, or consensus code. The Cardano validator checks
the transaction's required signers and validity interval; a transaction spanning
expiry cannot use the claim branch. Ledger input consumption prevents repeats.
Ethereum uses an explicit spent flag before any external payment.

## Install and build

Linux x86_64, Python 3.10 or newer and already-built Hegemon Development-capable binaries
are required (every tool version in one place: `docs/SWAP_TOOLCHAIN.md`). From the repository root:

    python3 -m pip install -r scripts/requirements-htlc-local.txt
    python3 scripts/setup_multichain_htlc_tools.py

The installer pins Foundry 1.8.7, solc 0.8.30, Aiken 1.1.24, cardano-node 11.1.3
and its bundled cardano-cli 11.2.3.0. It validates release archive SHA-256 hashes,
extracts only named binaries and builds both contracts. It uses
`$HEGEMON_CHAIN_TOOLS`, else `~/.local/opt/chain-tools`, by default; `--tools /other/path` selects another root. Scripts and tests
find tools through `scripts/swap_engine/tools.py`, so `HEGEMON_TOOL_<NAME>` (for example `HEGEMON_TOOL_ANVIL`) overrides one binary.
Unpack Bitcoin Core 32.1 into `<tools>/bitcoin` yourself; the installer does not download it.
Cardano's stdlib v3.1.0 is pinned in `cardano/aiken.lock`.

For a fresh Hegemon build:

    cargo build --locked --release -p hegemon-node --bin hegemon-node --features development-candidate,wallet/private-spend-dev-artifacts -p wallet --bin private-spend

## Tests

    TOOLS="${HEGEMON_CHAIN_TOOLS:-$HOME/.local/opt/chain-tools}"
    mkdir -p -m 700 "$HOME/hegemon-runs"
    "$TOOLS/foundry/forge" test --root contracts/ethereum --use "$TOOLS/solc" -vv
    "$TOOLS/aiken/aiken-x86_64-unknown-linux-musl/aiken" check contracts/cardano
    python3 scripts/local_multichain_htlc_swap.py --chain ethereum --output "$HOME/hegemon-runs/new-eth-run"
    python3 scripts/local_multichain_htlc_swap.py --chain cardano --output "$HOME/hegemon-runs/new-ada-run"

Output directories must not already exist (their parent must). `--scenario happy`,
`no_counterparty`, `both_refund` or `late_claim` selects a single case; the default
runs all four with separate wallets and chains. `--node`, `--wallet` and `--tools`
select executable paths. Each output directory contains private disposable keys,
passphrase files and diagnostics; keep it private. A failure preserves its
receipt and logs, stops owned nodes, and returns a nonzero exit status.

Tests check exact Hegemon action bytes in canonical blocks, mined wallet attempts,
recipient note values, counterpart payments, negative contract execution and
consumed inputs. Counterpart confirmation uses additional local blocks. Ethereum
extracts the preimage from a canonical receipt event. Cardano extracts it from
the exact submitted signed transaction after observing its outputs in the ledger;
the confirmed body commits the redeemer with its script-data hash. This Cardano
observer is not a historical-block indexer or a public-chain finality client.

All nodes bind loopback. Hegemon has an empty seed list, Cardano has an empty
P2P topology with ledger peer discovery disabled, and Anvil has no P2P network.
The adapters check established TCP connections of their owned processes and
Hegemon reports zero peers. Tests advance local deadlines and do not establish
public-chain timeout margins, confirmation policy, reorg handling or release
security approval. Shared Hegemon mining still uses the approved common seeds
and NTP/chrony guidance in the operator runbooks.

## Experimental Ethereum token escrow

`TokenHTLC.sol` adds a separately funded escrow for ERC-20, ERC-721 and ERC-1155 tokens. The refundee approves and funds the instance before expiry; the claimant supplies the same 32-byte SHA-256 preimage, or the refundee recovers the asset at expiry. Exact sender debits and escrow credits are required when funding ERC-20 and ERC-1155 transfers; payouts must also move the exact amount. Tokens with transfer fees or changed balances may therefore reject funding or payout. Token issuers can freeze, upgrade or otherwise prevent transfers, including after funding. The contract and fixture tests are experimental: the local swap harness and application do not yet support this escrow, and no security review or deployment qualification is implied.

## Local token fixture rehearsals

The local harness can mint disposable Cardano native assets and deploy disposable Ethereum token fixtures. It is not a general wallet transaction builder. From the repository root, after compiling the contracts and installing the tools described above, run:

    python3 scripts/check_ethereum_token_htlc.py --output "$HOME/hegemon-runs/new-ethereum-token-run"
    python3 scripts/check_cardano_token_htlc.py --output "$HOME/hegemon-runs/new-cardano-token-run"
    python3 scripts/check_ethereum_cardano_swap.py --output "$HOME/hegemon-runs/new-eth-cardano-run"
    python3 scripts/local_multichain_htlc_swap.py --chain cardano --cardano-test-tokens --scenario happy --output "$HOME/hegemon-runs/new-hgn-cardano-token-run"
    python3 scripts/local_multichain_htlc_swap.py --chain ethereum --ethereum-test-token erc20 --scenario happy --output "$HOME/hegemon-runs/new-hgn-erc20-run"

Each output path must not exist and contains disposable keys and logs; protect it as private data. The Cardano path must be short enough for a Unix socket. Ethereum token choices are `erc20`, `erc721`, and `erc1155`. These fixtures do not exercise arbitrary issued tokens, public-chain confirmation policy, issuer controls, or security review.

Additional isolated pairing examples:

    python3 scripts/check_bitcoin_ethereum_swap.py --output "$HOME/hegemon-runs/new-btc-eth-run"
    python3 scripts/check_bitcoin_ethereum_swap.py --counterpart cardano --output "$HOME/hegemon-runs/new-btc-cardano-run"
    python3 scripts/check_samechain_ethereum_swap.py --output "$HOME/hegemon-runs/new-same-ethereum-run"
    python3 scripts/check_samechain_cardano_swap.py --output "$HOME/hegemon-runs/new-same-cardano-run"

The recorded results and important limitations are in `MULTIASSET_LOCAL_RESULTS.md` at the repository root. The role of every swap script is in `scripts/SWAP_SCRIPTS.md`; the engine that now plans and runs swaps (loopback Hegemon profiles and a separate public pre-mainnet profile) is described in `DESIGN.md` ("Two-party swap engine", "Hegemon adapter and local fixtures").

The local pairing scripts also exercise read-only verification. `scripts/bitcoin_escrow_verifier.py` reconstructs the expected Bitcoin regtest script and checks its confirmed UTxO through a trusted local Bitcoin Core node. `scripts/cardano_escrow_verifier.py` checks a local UTxO's pinned validator, datum and exact assets. The Cardano UTxO query does not prove confirmation depth, and neither checker independently authenticates the counterparty's terms or the RPC provider.

The current `private-spend verify-htlc` command verifies an unspent HGN note against supplied claim/refund addresses, hashlock, timeout and amount, requires the public secret-release flag, and checks local canonical membership, confirmation count and remaining blocks. It prints a result and heights rather than the decrypted opening. It depends on the configured wallet and trusted synchronized node and does not establish other-chain funding or public-network finality. The local companion adds a terminal approval and terminal-only passphrase prompt around this read.
