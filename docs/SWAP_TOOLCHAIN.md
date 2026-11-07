# Swap toolchain: one place for every version

Everything the swap engine, the hosted swap page, the Worker and the chain fixtures need, with the versions the
repository was last verified against (2026-11-06, Linux x86_64). The fast tier needs only Node 24 and Python
with the packages below. The integration tier also needs the chain tools.

## Runtimes

| Tool | Version | Why it matters |
|---|---|---|
| Node.js | 24 (`.nvmrc`, `engines.node >=24` in `swap-service`, `swap-service/vendor-src` and `swap-service/cloudflare`). Verified 24.22.2 | The local relay and the Worker tests use `node:sqlite` and global `crypto`. Node 22 and older fail. |
| Python | 3.10 or newer (verified 3.10.12) | Engine, drivers, rehearsals and tests. |
| Rust | the toolchain pinned by `rust-toolchain.toml` | Only for the Hegemon node and `private-spend` wallet binaries (Hegemon adapter tier). |
| Chromium | any recent build, verified 156 (snap). Set `CHROMIUM_PATH` | Browser tests only (integration tier). |
| `playwright-core` | 1.56.1 (`swap-service/package.json`, run `npm ci` in `swap-service`) | Drives Chromium and the desktop (Electron) test. |
| Wrangler | 4, run as `npx wrangler@4` (not installed in the repository) | Worker dry runs and deploys only. The Worker unit tests use an in-memory SQLite adapter and need no Wrangler. |

## Chain tools (integration tier)

`python3 scripts/setup_multichain_htlc_tools.py --tools DIR` downloads and checks (by SHA-256) the pinned releases
recorded in `manifest.json`. Without `--tools` it uses `$HEGEMON_CHAIN_TOOLS`, else `~/.local/opt/chain-tools`.

| Tool | Pinned release | Location below the tools directory |
|---|---|---|
| Foundry (`anvil`, `forge`, `cast`) | v1.8.7 | `foundry/` |
| `solc` | v0.8.30 | `solc` |
| Aiken | v1.1.24 | `aiken/aiken-x86_64-unknown-linux-musl/aiken` |
| `cardano-node`, `cardano-cli`, `cardano-testnet` | 11.1.3 in the manifest (the installed `cardano-cli` reports 11.2.3.0) | `cardano/bin/` |
| Ogmios | optional, not downloaded by the script (only the Cardano observer checks); the Python client is `ogmios` from the requirements | `ogmios/bin/ogmios` |
| Bitcoin Core (`bitcoind`, `bitcoin-cli`) | 32.1, not downloaded by the script: unpack it to `DIR/bitcoin` | `bitcoin/bin/` |

Resolution order for one tool (`scripts/swap_engine/tools.py`): the environment variable `HEGEMON_TOOL_<NAME>`
(for example `HEGEMON_TOOL_ANVIL`, `HEGEMON_TOOL_CARDANO_CLI`), then the tools directory, then `PATH`. The legacy
`/workspace/chain-tools` is still found if it exists but nothing writes there. `python3 -m swap_engine.tools`
(from `scripts/`) prints where every tool resolves and exits 3 when a named tool is missing.

Tests that need a tool use `skip_unless_tools(...)`: they report `skipped` with the missing tool names and how to supply
them. They never pass silently.

## Python packages

`scripts/requirements-htlc-local.txt` (Ethereum and Cardano local fixtures) and `scripts/requirements-htlc-public.txt`
(public testnet drivers). The verified install used `pip install --target`, because `python3-venv` is not installed on
the development host:

    python3 -m pip install --target "$HOME/.local/opt/hegemon-swap-python" -r scripts/requirements-htlc-public.txt
    export PYTHONPATH="$PWD/scripts:$HOME/.local/opt/hegemon-swap-python"

A virtual environment works equally well where available. The `Makefile` targets add
`$(HEGEMON_PYTHON_DEPS)` (default `~/.local/opt/hegemon-swap-python`) to `PYTHONPATH` when the directory exists.

## Running the tiers

    make swap-test           # fast tier: no network, no chain tools, no browser. Needs Node 24 and the Python packages.
    make swap-integration    # local chains, browsers: runs what the host supports and prints SKIPPED for the rest
    make swap-hegemon-local  # opt-in: real local Hegemon chain, needs the built node and private-spend binaries

`swap-integration` exits 0 after printing `SKIPPED: ...` lines when tools are missing. Set
`SWAP_INTEGRATION_STRICT=1` to turn any skip into a failure (use it on a host that is supposed to have everything).

## Hegemon nodes used for swap work

A Hegemon node that follows the public network must be started with
`HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless the approved list has been deliberately
rotated; every node and miner on that network must share the same seeds or they can fork. Keep NTP or chrony enabled:
PoW timestamps beyond the future-skew bound are rejected. The local fixture chains used by `swap-hegemon-local` are
private and peerless by design (empty seed list, loopback only, no connection to the public network) and must never be
pointed at a public node or the operator's own node.

## Environment facts that bite

- The public Sepolia RPC prunes history older than about 12,000 blocks. Verifiers and the observer need a block
  range inside that window; `eth_getLogs` over older ranges returns errors, not empty lists.
- Bitcoin refund heights must be at least 145 blocks ahead (`public_bitcoin_driver.policy_limits`). Rehearsal scripts
  with a literal refund distance below that fail by design. The one deliberate exception is
  `public_bitcoin_refund_rehearsal.py`, which passes `rehearsal_short_refund=True` to rehearse the refund path.
- `swap-ui` edits change the Subresource Integrity manifest: run `node scripts/build_client_manifest.mjs` and commit the
  generated `swap-ui/index.html`, `swap-ui/hosted.html`, `swap-ui/client-manifest.json` and
  `swap-service/cloudflare/client-policy.mjs`. CI runs it with `--check`.
- `swap-service/vendor-src` bundles browser libraries: `node build.mjs --check` fails when the committed bundles drift.
- Any edit to `circuits/transaction/src/smallwood_engine.rs` (or another file hashed into the relation digest) is a
  protocol change, not a tool change.
- Test baselines at the end of P7 (2026-11-06): `swap-ui` 161 tests, relay and Worker 19 tests, Python
  `swap_engine` 187 tests (14 skipped for the opt-in local chain suites), `scripts/test_public_*.py` 103 tests.
