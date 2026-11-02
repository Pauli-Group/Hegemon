# Local multi-asset HTLC results

These are Development and local-chain functional rehearsals, not production security qualification. All chains were fresh and isolated. The token implementations used are disposable test fixtures, not USDC, DJED, USDM or any other issued asset. The browser offer board and relay did not drive these tests; the scenarios use scripted wallet and node adapters. Test directories contain disposable private keys and must remain private.

| Scenario | Result | Local receipt |
| --- | --- | --- |
| Hegemon / BTC | Passed in the earlier rehearsal | `LOCAL_PRIVATE_SPEND_SWAP_RESULTS.md` |
| Hegemon / Ethereum ERC-20 fixture | Passed | `/workspace/ehtok1/summary.json` |
| Hegemon / Cardano native fungible and one-of-one fixtures | Passed | `/workspace/chtok1/summary.json` |
| BTC / Ethereum ERC-20 fixture | Passed | `/workspace/beswap1/summary.json` |
| BTC / Cardano native fixtures | Passed | `/workspace/bcswap1/summary.json` |
| Ethereum ERC-20 / Cardano native fixtures | Passed | `/workspace/ecswap1/summary.json` |
| Ethereum ERC-20 / ERC-721 on one chain | Passed | `/workspace/esswap1/summary.json` |
| Cardano fungible / one-of-one native token on one chain | Passed | `/workspace/csswap2/summary.json` |

Separately, ERC-20, ERC-721 and ERC-1155 fixtures each passed claim and refund on fresh local Ethereum chains (`/workspace/etok3/summary.json`). Cardano fixture tokens passed claim and refund on fresh local nodes (`/workspace/ctok2/summary.json`). Foundry reported 22 passing tests (9 native ETH and 13 token escrow). Node.js tests covered the local offer relay, restart persistence, access checks and AES-GCM message authentication. A Chromium test created a private offer, exchanged encrypted messages between two separate browser contexts, and exercised read-only wallet connections using mocked browser providers. No real browser wallet was connected.

The first same-chain Cardano attempt (`/workspace/csswap1/summary.json`) failed because its expiry slots exceeded the fresh network's time horizon. The successful retry used a local epoch length of 5,000 slots so that both deadlines fell within the horizon; this is not a public-network timing policy. Hegemon proof processes in the two token scenarios took 90.781–199.178 seconds and peaked between 1,733,804 and 1,995,796 KiB in per-process samples while the two scenarios shared the machine. These are not controlled performance benchmarks.

No test establishes arbitrary-token compatibility, safe production timeout margins, reliable public-chain observation, reorganization handling, fee estimation, wallet integration, or independent security review. In particular, issuers can prevent transfers or change token behavior after escrow. The browser board is an offer prototype and does not create or verify on-chain swaps. Receipts for the Hegemon-linked runs recorded the then-current commit but the harness was modified in the working tree; they are not source-bound release receipts.

A read-only Ethereum escrow verifier now reconstructs the expected runtime from the pinned compiler artifact and the agreed immutable terms, checks the code and asset holdings at a two-confirmation local snapshot, and rejects spent escrows. ETH, ERC-20, ERC-721 and ERC-1155 checks passed against actual local contracts (`/workspace/everify7/summary.json`), including mismatched terms, chain-change simulation, deadline limits, a real spend at the latest head and post-claim rejection. Chromium also verified actual local ETH and ERC-20 escrows through a test wallet provider and rejected a changed amount. A first browser fixture incorrectly supplied an extra constructor argument; the verifier rejected it, and the corrected test passed. The verification depends on an honest RPC provider and trusted local client code; it is not an audit, issuer guarantee, or public-chain finality policy.

The independent Bitcoin regtest output checker reconstructed the expected script and checked an unspent output with two confirmations in both BTC/ERC-20 and BTC/Cardano-token rehearsals (`/workspace/bveth2/summary.json` and `/workspace/bvada2/summary.json`). It rejected altered terms and spent outputs. Its first negative-key test used the same key in both script branches, which Bitcoin Core rejected at descriptor validation; the checker now rejects duplicate keys explicitly before invoking Core.

The Cardano checker compared a local UTxO with the pinned validator, the full inline datum and exact native-asset value (`/workspace/ecverify1/summary.json`); changed terms and a spent output were rejected. The CLI query supplies no independent inclusion history, so the result deliberately reports no confirmation depth. Both checks depend on an honest local node and independently authenticated expected terms.
