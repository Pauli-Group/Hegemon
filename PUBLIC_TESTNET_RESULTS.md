# Public testnet HTLC rehearsal results

These are disposable test funds and fixture assets. Ethereum data came from a public Sepolia RPC, and Cardano data came from the public Koios preview service. The reported snapshots trust those providers; confirmation depth is not a guarantee of finality or real-fund safety. Hegemon data in the P8 section came from a loopback v0.11 pre-mainnet node compared against `https://hegemonprotocol.com/testnet/status.json`. Hegemon notes are private: only action ids, heights, hashlocks and the other chain's transaction ids are recorded.

## Native ETH and ADA

The staged two-party claim path completed on Ethereum Sepolia and Cardano preview. The long ETH escrow held 0.0001 test ETH, and the short Cardano escrow held 10 test ADA. Both were verified against the expected script, hashlock, recipients, amount and provider-reported confirmations. The Cardano claimant revealed the preimage in the confirmed Cardano transaction; the Ethereum claimant recovered it from the public Cardano transaction and used it to claim the ETH escrow. The Cardano output was independently checked to pay 10 ADA to the intended test recipient; the Ethereum claim receipt succeeded.

| Transaction | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| ETH lock | Sepolia | `5ee61e1a0a96314a6dabe035e833c1a0614468783fd4ff240a953a09de0ae9b2` | Success, block 12051431 |
| ADA lock | Preview | `1d1c7dcabd9a05b590e8ce305a6ceb95cb0649440687d22a7da3ef32f385f374` | 17 confirmations at inspection |
| ADA claim | Preview | `013e52bd4c22499ff148ab67561e3fcd75c4aea5e156b7eed475d16ffe67b420` | 13 confirmations at inspection |
| ETH claim | Sepolia | `21616ed433a988c6bd8838da08be1fb003117d43b00536fe3d26d6154c9aafa9` | Success, block 12051447 |

The setup transaction `f1710647c8dd9510d58a931993cb65a7eb935977c8ea8b87b51abf6ff039cd4a` also minted a disposable Cardano fungible fixture and one-of-one fixture and created fee and collateral outputs. Other token combinations and refund scenarios are reported separately below.

## Sepolia ERC-721 and Cardano preview NFT

A cross-chain NFT fixture swap completed. The ERC-721 funding transaction was `5a6ee5d66282464ef78bbbe174283d1b126c85ce2cbac781f5aca0fbda7f52b3`, and the Cardano NFT funding transaction was `d00b896311757de703272676a851a5353ec63e02f48c2c550612009df6f4270f`. The preimage was observed in the confirmed Cardano claim `b4f11c08612039f99378812d329ebd331002bda81cbe812c99f807bfd1978ac4` and used for the confirmed Sepolia claim `5ff02146020044fe4b229265fe5b62a1e46d51b878fdfce688d63f55a94d1e48`. Both NFT recipients were checked.

## Sepolia ERC-20 and Cardano preview fungible token

A cross-chain fixture swap completed between 10 ERC-20 units and 7 Cardano native-token units. Funding transactions were `85890ec5f17870896a8c4edf9923e9a51fa81defdd319d8d5763c4eece8338dd` on Sepolia and `e3aab9fed4924b1344e6d9c96e15f38afd84ac31655c6d79312dda6aa8198939` on Cardano preview. The preimage from confirmed Cardano claim `b5f48fbec7f7d92a14d23b0252484f3f84a8822fc8c1cf7c28083a172a4778e0` was used in confirmed Ethereum claim `b4effeb82ca30f53cc0aefe6ae2742d5134a0081e4ddd9c6dd3a295ad962c579`. Both token recipients and amounts were checked.

## Sepolia ERC-1155 and Cardano preview fungible token

A cross-chain fixture swap completed between 5 ERC-1155 units and 9 Cardano native-token units. The Sepolia and Cardano funding transactions were `d58675cb2b6539aae86eecb5372c6e9b11f18673c4953deff98fce2d81a987b6` and `e7033fcc9c8cdbbde1c098759d6a7a33f8431289fe7e8e81c84b8abda06e916a`. The secret observed in confirmed Cardano claim `3416ba139a23f1f623b6f7fc346e6ade00f1269e5c32804b7986265a7c29a19b` was used in Sepolia claim `5f0f6fa05d6b750c4ead0a80561f9356776e78ba9e9c722e134530942f9af0d9`. Both recipients and amounts were checked, and the ERC-1155 approval was revoked after funding.

## Sepolia ERC-20 and ERC-721

A same-chain fixture swap completed between 100 ERC-20 units and ERC-721 token 42. The NFT claim `25abafdb49c9a32361b15aa4a1509d6a80f7d32574ffe93f64dd8567a172e02d` exposed the preimage, which was read from the confirmed transaction and used for the ERC-20 claim `003a4c258156b54b83d1d170f04ce37b9bb7af3c207dc8a3a790cc9683d38ac8`. Both fixture balances and the NFT owner matched the expected recipients. The fixture contracts implement the interfaces exercised by this test and are not production tokens.

A second same-chain swap exchanged 30 ERC-1155 units (token ID 7) for 25 ERC-20 units. The short-leg ERC-20 claim `2b814bd2d64a6dfb97f72b18a1b3769e1b24d21379498cc4607a90855e162a9d` revealed the preimage, which was used for the ERC-1155 claim `44d5fc9a4e6b07a25325ebc5599e7d997d2877eaaf980c232a5de4e5f19c1ff5`. Final balances matched, and the ERC-1155 operator approval was revoked after funding.

## Sepolia native ETH refund

The separate native ETH escrow rejected an early refund with the exact `refund premature` contract revert. After expiry, refund transaction `daa0c8cbd453b46fca3e08c2c070f1e5ecf1c29ec7ddd7ffe242a8f89cc0944b` succeeded and was confirmed; the escrow reported `spent` and a zero ETH balance. Its funding transaction was `1b68c49c1ef9224c2f56e043a96c8348a17e91f7dde997453e78e3a456ac3bdc`.

The ERC-721 fixture escrow likewise rejected an early refund and returned the NFT to its owner after expiry. Its funding and refund transactions were `6cfbba1add36695b7fe9371f95515a7850e2d0927055f69268ce60297402e74b` and `583d4e8d26c2b1d1e8013c207d4c4163c358626e6527a155d52293de0bf2d155`. An RPC error interrupted the first refund attempt during gas estimation before signing; the journal, wallet nonce and unspent escrow were checked before resuming.

## Cardano preview fungible token and NFT

A same-chain fixture swap completed between 10 fungible units and the one-of-one test NFT under policy `0a396632a227e19f8aed123cc124ad75139de3c96b897e029c88d77e`. The fungible and NFT escrow funding transactions were `15b70db53c05be3ccbf74203e0315718b9e1d5f43f7ecfa15efe971c1166053c` and `615d30918d74cd0cc348e2b9764e39186fd5b8bd3967aec1f85167301856e7d5`. The NFT claim `04dce10995247b196e548f61d1f7a035656af0e0d906679dc2b95a536b78ebea` revealed the preimage, which was observed in the confirmed Cardano transaction and used for fungible-token claim `1479822e5ea9c9851e69a6016574ab006070abe38d6c96c843bfbfa50583ad57`. The exact token outputs and their intended recipients were checked. The claimant's fee input also contained unrelated fixture tokens; those were preserved in change.

## Cardano preview ADA refund

The ADA escrow funded in transaction `8e3f76a71a0712ff655d3e7a4000dcbc2557f203b07aaadac742aa3e636b0798` was refunded after its deadline in transaction `9250345efe80619223d24e8de6b6fb3b63b16f099163a5132ec6c4415d1cd33e`. Provider-reported confirmation, consumption of the locked output, and the 4 ADA payout to the refund wallet were checked. Early refund rejection was tested on the isolated Cardano chain, not submitted as a public negative test.

The separate NFT escrow funded in transaction `46af5de02bf2fbce66729940b5a6f6415626a88cd60e7a2b308009308d23edc9` was refunded after its deadline in transaction `ad1e014a985b4d637c57ae2aca46d088ae7f94b068ebd872a8a8465d0220e1ac`. Provider-reported confirmations, consumption of the locked output and the NFT's return to the intended wallet were checked.

## Bitcoin testnet4 and Sepolia ETH

The Bitcoin escrow funding transaction `cdeecb1da3ea00b1a7e5e4981eb073a656526073da61fe201c98c1de8e85bd8a` was confirmed. Sepolia funding transaction `f43dfba641d43153113fa029cac5eb1d7012fddf1e6e1c89ea29facbaced3def` and claim `7c9582e9097f4d13a4af789a9dce1e0a78d167e408c2fe61227bde79033e6d63` succeeded, and the observed claim preimage was used for confirmed Bitcoin claim `3ef145568dc1b97d37541c0091a205068be7bf0f95ef2897733c3ff2e5375e11`. The Bitcoin claim paid 1,250 sats to the expected claimant address. Blockstream did not provide a six-block testnet4 fee estimate at funding; the driver falls back to a second, genesis-checked testnet4 service and retains the more conservative available estimate. The reported provider observations remain trusted rather than independently verified.

An additional 50,000 sats arrived in testnet4 transaction `e3d142194ee11244941859ed84282cb4c739571710390ee5f7c2a00f5c0df7eb`. Split transaction `a05df909cec1aaf5f5ba2483882939f2ae653801ee056197d35633d3b8c3e67b` confirmed and produced independent test inputs. The original session-bound runner stopped, so the remaining Bitcoin cases were resumed after checking the inputs; their completed outcomes follow.

Before the claims, the BTC/ADA rehearsal had confirmed unspent escrows in Bitcoin transaction `d15914d8b39854d652a73d73e72b7d5ccaaf6678b1a1ac6c420cf912fcb6248e` and Cardano transaction `fe1d5bd435868b6a0edebde49d1c3ea27d9a530d56ef3270bcbacc9c75cea593`. The hosted browser checked each output and compared both against an offer and common hashlock using public-provider snapshots. The Cardano claim subsequently confirmed; the Bitcoin claim is described below.

The separate Bitcoin refund funding output was confirmed in transaction `1e8a4ff81fdabecb32f5d38627c8a49a6b92a7537002488694800115c4fcfd4d`. The first submission of refund `0bdc031917d9be39cb332ee8ec440e36731353c7dd6ae6f3ecf3a5857d0f2804` received HTTP 429 after the signed bytes had been journaled. The saved transaction ID, exact funding input, lock height and Alice payout were inspected; the primary provider and secondary indexer showed the output unspent, and the transaction was absent from the secondary mempool. The exact journaled transaction was then submitted once to the verified secondary testnet4 service and ultimately confirmed.

The two Bitcoin indexers temporarily reported different chains at height 158793, and the completion runner was paused. By tip 158819 both reported the same height-158793 hash `000000003e9d75209afa6b4d142fcb8202a189efeb00ebf9d6c542a866b27a5c` and placed all four transactions below in the same height-158797 block with 23 confirmations. Each indexer reported the exact escrow input and a 1,250-sat payout to the expected claimant or refund wallet. These remain provider-reported snapshots, not independently validated consensus or a guarantee against future reorganizations.

The BTC/ADA swap completed: Cardano claim `5ef1932af11943d51d47d340c4f9338f5250ef31ecbd887742b8d07afecc35bf` revealed the hash-bound preimage used for Bitcoin claim `5888dafee51038f7b02bcdb268f55cb921c77fd6f8b3bb0dd753f036663e720c`. Koios showed 10 ADA at the intended Cardano recipient.

The BTC/Cardano native-token swap completed: Bitcoin funding was `f08a5eda0161de93a62fb8c6f5a706911c2bcd19d1280589801ff516cf6c4649`, Cardano funding was `b1c66f3569ef624d6660003126a2582b8b8ce60a63402873a1f67a992c7a2f47`, Cardano claim `5761d261aeb8549868cfa93ed188507509dbace429e18e4fdc42d977077bf96d` revealed the preimage, and Bitcoin claim was `9808daeca1ab0742f476803d058afa8b5eeb061271877a4090d763009b67f428`. Koios showed the intended recipient's output held five fixture token units and 4 ADA.

The BTC/ERC-20 swap completed: Bitcoin funding was `5d47702867b5121ef3a509705949164e0973e0b8e6df7690da848f1ad5073160`, Sepolia token funding was `a81e42b5c6fe4fe0b80532e295c07ef732deb69a2167a40debf74824ab48f6b4`, Sepolia claim `04ed607d9e11135d015148cd5cd4024f64549664dcfcb48edaa87f0599afaafc` revealed the preimage, and Bitcoin claim was `7bbadc7425361894bd5311cd91d0ddb9ac710ddec77ac84027b1ab61c297475e`. The Ethereum provider reported the expected ten-unit fixture-token balance changes. The separate Bitcoin refund `0bdc031917d9be39cb332ee8ec440e36731353c7dd6ae6f3ecf3a5857d0f2804` also confirmed and paid the expected refund wallet.

## Hosted Sepolia verification fixture

A temporary native ETH escrow funded in transaction `e982e20a759719a6b8ae05d0fd308e6d0c0ac731599992229bc7cba8687a4380` at `0x2e30a4a829edcd7aae3580b1ed77ed6d009c883f` was matched by the hosted read-only verifier through a Chromium test wallet adapter backed by public Sepolia RPC. The browser made no transaction request. Refund transaction `f32252cecebaf95c5a247c8fe056e193a26c091abeda829c7d5f38b3373d833d` later confirmed, and the escrow balance was zero. This is a verification fixture, not a two-party swap.

The hosted manual-action form subsequently requested one wallet transaction through an injected disposable test signer, which independently checked the terms and submitted confirmed Sepolia funding transaction `fb803ab4b1e9e68ca90804e7f97a1c2036b341b5e8dfb58fe77c11db1cfe6bb8` for escrow `0x25b3e3f95ccd58ba022e6c00271f8a1f7cf4737d`. After expiry, refund `94f5bfa945ab4fbecea24a08b54b5f87c58c98ea00c437d43f892981a03fdca7` confirmed and the escrow balance was zero. This exercised the browser action path, but not a real browser wallet extension or a complete swap.

## Hosted page wallet flows (P3 qualification, 2026-11-06)

This entry records the hosted page's own wallet flows run against the real Sepolia, Cardano preview and Bitcoin testnet4 networks with disposable funds, using `swap-service/qualify/hosted-ui.mjs`. The page's code, the Worker's code and the public providers behind it were real. What stood in for wallet products: Chromium 156.0.8078.47 driving the page under Node v24.22.2; an EIP-1193 provider backed by `eth-account` 0.13.7 for Sepolia; a CIP-30 software wallet signing with the ed25519 key file for Cardano; and an `embit` 0.8.0 PSBT signer for Bitcoin. **No browser-extension wallet (MetaMask, Eternl, Lace or similar) was used**, so wallet-product behaviour (prompts, network switching, hardware wallets) was not qualified. The Worker was `swap-service/cloudflare/worker.mjs` hosted in Node with an in-memory D1 and an identity HTMLRewriter, not the deployed Cloudflare Worker, which has not been redeployed with these routes. Each chain used Alice as funder and refundee and Bob as claimant. Amounts: 1000 wei, 5 ADA and 20,000 sats.

| Case | Chain | Transaction ID | Observation |
| --- | --- | --- | --- |
| Escrow deployed through the page | Sepolia | `0xad0ea224fceda53bc218988e04165aeabee59e85b8fd06cbb454ac21b1fdf94f` | Escrow `0x5cfd039d29771622b48768a456e6fc5949e8fd6c`; confirmed |
| Claim through the page from the encrypted backup (Bob) | Sepolia | `0x8261e82e4d83383e5606be9ce9a7923248a73bd2ed8c8bceb2e96370ed218519` | Succeeded; calldata preimage hashes to the hashlock; escrow balance 0 |
| Escrow deployed with the wallet response lost | Sepolia | `0x236aea9481ab07a8da5f1c4474c74089c2bfcc1746fba5398fb046afe5f553f2` | Page reported "Wallet submission was not confirmed" and left an uncertain record; the transaction was mined; escrow `0xf3654106d22fee4e5c99aaaff3111d7b47fc9106` |
| Refund through the page after expiry (Alice) | Sepolia | `0x61af2e6a9ee42e6ada42de70c5aba5a131f0957b057b0dc54e30c314c315f77d` | Succeeded; escrow balance 0 |
| Fund through the page after review (Alice) | Cardano preview | `2f6dfefa58907c42ba0d971cac2e0c6ebff6fbfd535d8bb4df6bf14ccf982a63` | 5 ADA at the pinned script address with the agreed inline datum |
| Claim through the page from the encrypted backup (Bob) | Cardano preview | `0084f9b807877b84fe811a0735dc78ddec4a5a311286d2a761e77e1b7698f1ef` | Phase-2 valid with the fixed 250000/100000000 budget and the 3600-slot validity clamp; spends the escrow and pays Bob |
| Fund with the submit response lost | Cardano preview | `ae126e0800458fbb783b89789319ec386334acb8bea2e41bb66144fce2233823` | Page reported that the wallet did not confirm submission and left an uncertain record; the transaction was in the chain |
| Refund through the page after expiry (Alice) | Cardano preview | `aed6bca9e1a5186b697e7906b672ed7eef13bf890b21c98ba37ccbe3bb67284b` | Succeeded; spends the escrow and pays Alice |
| Fund through the page (PSBT signed externally, Alice) | Bitcoin testnet4 | `2e156bb302279701d2308f364ef212f54d4a6135a53376564e9a358ba2fbf2b6` | 20,000 sats P2WSH output at index 0, confirmed in block 159451, refund height 159620 |
| Claim through the page from the encrypted backup (Bob) | Bitcoin testnet4 | `8aea86acc29cd6ad29809026a1b1f637b232c5e1ccb99c4d8b43e5c1244be74a` | Confirmed in block 159459; witness has four items, the preimage hashes to the hash in the script, 19,720 sats paid to Bob |
| Fund with the broadcast response lost | Bitcoin testnet4 | `82727aed9c748f0624c364c630ff380871ea4b40f1126aa65125ae7d253327d8` | Page reported "may have been accepted" and named the transaction id; confirmed in block 159459; refund height 159459 |
| Refund through the page at the height (Alice) | Bitcoin testnet4 | `f8b5a2a85f078ccb875710a638ecc8c7b433c624090d1e3e604f9a30c704e8f6` | Confirmed in block 159464; locktime 159459, sequence 0xfffffffe, witness `[signature, empty, script]`, 19,736 sats paid to Alice |

The observer in the page found each counterparty claim with no manual lookup: on Sepolia (Worker `/sepolia/escrow-events`), on Cardano preview (the claim redeemer through `/cardano-preview/spend`) and on Bitcoin testnet4 (the claim witness through `/bitcoin-testnet4/spend`), each reporting that the revealed value hashes to the agreed hashlock. Wrong-network cases were refused with no wallet request: a Sepolia wallet on chain `0x1` ("Wallet is not connected to Ethereum Sepolia."), a Cardano wallet reporting network id 1, and a Bitcoin mainnet address (the form's pattern rejected it and nothing was built). I independently re-read the transactions afterwards: Sepolia receipts succeeded and both fixed-term escrows held zero balance; Koios `utxo_info` showed both Cardano escrow outputs spent and `tx_utxos` showed the claim and refund spending them; mempool.space showed the Bitcoin claim and refund as described above.

Not run on the public chains: declined-signature and stale-head cases (they are covered only by mocked-wallet browser tests and real-software tests on a local Cardano cluster and bitcoind regtest); the Cardano wrong-network check that the wallet's UTxOs exist on preview; Hegemon (no public leg); the guided view with a live engine swap; a real browser-extension wallet; the deployed Cloudflare Worker.

Findings from the runs. The harness first failed with `ETIMEDOUT` on reads that succeed with curl, because Node's default per-address connect attempt is 250 ms; after raising it to 5000 ms the Worker's Bitcoin and Sepolia reads behaved. The first real Sepolia observer lookup failed because the Worker asked publicnode for logs from block 0 and publicnode caps `eth_getLogs` ranges at 50000 blocks; the Worker now scans windows of at most 45000 blocks up to 360000 blocks back. A harness mistake that deployed a Sepolia escrow with one expiry and then claimed with another was refused by the page as `escrow bytecode or terms mismatch`; the message does not say which term differed. Koios returned `tx_info` with empty `inputs` and `plutus_contracts` for confirmed claim and refund transactions, so verification used `tx_utxos` and `utxo_info`. Bitcoin testnet4 block timing was irregular: the tip moved from 159444 to 159464 over roughly two hours of this session (block header times are not reliable on that network, one header here is about 18 minutes ahead of the wall clock), and the refund escrow funded at about 17:15 UTC was refunded at about 18:00 UTC with the refund confirmed in block 159464.

Leftovers from aborted harness runs as found at the end of P3 (disposable; the secrets were lost with the closed browsers). The P4 entry below records what happened to them: the Sepolia and Cardano ones were refunded, and the Bitcoin escrow `05995b8c...` turned out to be unrecoverable because its hashlock was lost, not merely waiting for height 159615: Sepolia escrows of 1000 wei at `0x738a083a13772637723f24357c592fc3807d35e3`, `0xc512cf0ec872d14474f1eb969c0ab92ff0f301ea`, `0x991a478df723ec340b313cde0cb481e198a8bbc1`, `0x26b7643103a0b7577915f425e4a6e6e7cb13a93a`, `0x1b5490d35f62099738ea4f9d99ca5f4d873f1e9c` and `0xc42dc840f13f5f87df1f44e24864728e5c5a3afc` (a seventh, `0xcb986b6c1e07c4be7af273dc499b2c9e58f25bf1`, was claimed in transaction `0x506e420e4bc580677433cdf41ed4bca18287a5f8cf4345e7c5b36dee230451e0` of an earlier run, which also claimed a Cardano escrow funded in `04cc07ed737704a2223e64b43926a565ee6557ad262327a167df4223baa4ca1c` with `fe07985f0bd53c7e97842858c492a69608fe7653dc425da852e8b6048617ca5f`); a 5 ADA Cardano escrow funded in `b9ff41c9c4cdaf3536006a1b0cac1c47ec92b29dc01ead4b0415c73e27431f7c`; and a 20,000 sat Bitcoin escrow in `05995b8cec2d23dff568ae426333003d75aed1310d4eebcef7bfe110e07fcd87` refundable by Alice at height 159615.

## Bitcoin cases: independent verification and stray clean-up (P4, 2026-11-06)

All five Bitcoin cases (BTC/ETH, BTC/Cardano ADA, BTC/Cardano token, BTC/ERC-20 and the Bitcoin refund) and both Sepolia browser fixtures were already complete on chain, so nothing was resumed or rebroadcast. This entry re-reads each from public data with `scripts/verify_public_btc_cases.py`, which reads only the public fields of the scenario state files (never a secret file), and its 208 checks all pass (`scripts/test_verify_public_btc_cases.py` mutates one fact at a time and requires each mutation to fail). What it checks, and from what:

* Bitcoin testnet4, two providers (mempool.space and Blockstream, each confirmed to have the testnet4 genesis hash): each transaction's raw bytes hash to the recorded ID; the claim or refund spends output 0 of the recorded funding transaction; the witness script has the one expected shape and its hashlock, claim key, refund key and refund height equal the recorded terms and equal what the repository builds; the funding output pays the P2WSH of that script and holds the recorded amount; the ECDSA signature verifies against the claim key (or refund key) over a SIGHASH_ALL segwit digest; a claim's 32-byte preimage hashes to the hashlock; a refund has locktime equal to the height, a non-final sequence and an empty selector; the payout script is the key's own P2WPKH; both providers report the same confirmed block hash and height; and the escrow output's spender is the recorded transaction.
* Cardano preview (Koios only): the escrow output sits at the pinned validator address with the recorded lovelace and assets and an inline datum whose hashlock, claimant, refundee and expiry equal the terms; the claim ran only the pinned validator (script hash checked, and the pinned bytes hash to it), the script was valid, it spent that output, its redeemer hashes to the hashlock, the claim address received at least the locked lovelace and every locked asset, and the transaction's validity upper bound is before the datum's expiry slot. Koios returned partial or empty `tx_info` for confirmed transactions on the first attempt, so the verifier asks per transaction and retries.
* Sepolia (Blockscout for history, publicnode for latest state): the escrow's runtime equals the source-pinned runtime rebuilt from the recorded terms, `spent()` is true, lock and claim succeeded from the right senders, the claim calldata preimage hashes to the hashlock, and the exact amount moved (10 fixture-token units for the ERC-20 case, the recorded wei for native). The primary RPC pruned the receipts for the oldest transactions, so those were checked on Blockscout only.

| Case | Bitcoin funding | Bitcoin claim or refund | Paired leg | Hashlock |
| --- | --- | --- | --- | --- |
| BTC/ETH | `cdeecb1da3ea00b1a7e5e4981eb073a656526073da61fe201c98c1de8e85bd8a` (block 158680, refund height 158818) | claim `3ef145568dc1b97d37541c0091a205068be7bf0f95ef2897733c3ff2e5375e11` (block 158686) | Sepolia escrow `0x7f1720396c31e2f66c62164aa9628e707c8982da`, funding `f43dfba641d43153113fa029cac5eb1d7012fddf1e6e1c89ea29facbaced3def`, claim `7c9582e9097f4d13a4af789a9dce1e0a78d167e408c2fe61227bde79033e6d63`, expiry 1793679396 | `9ade4127…0578` |
| BTC/ADA | `d15914d8b39854d652a73d73e72b7d5ccaaf6678b1a1ac6c420cf912fcb6248e` (block 158786, refund height 158927) | claim `5888dafee51038f7b02bcdb268f55cb921c77fd6f8b3bb0dd753f036663e720c` (block 158797) | Cardano lock `fe1d5bd435868b6a0edebde49d1c3ea27d9a530d56ef3270bcbacc9c75cea593` (10 ADA), claim `5ef1932af11943d51d47d340c4f9338f5250ef31ecbd887742b8d07afecc35bf`, expiry 1793738188 s | `8199d491…f8ce` |
| BTC/ADA token | `f08a5eda0161de93a62fb8c6f5a706911c2bcd19d1280589801ff516cf6c4649` (block 158786, refund height 158927) | claim `9808daeca1ab0742f476803d058afa8b5eeb061271877a4090d763009b67f428` (block 158797) | Cardano lock `b1c66f3569ef624d6660003126a2582b8b8ce60a63402873a1f67a992c7a2f47` (5 `FUNG` units plus 4 ADA), claim `5761d261aeb8549868cfa93ed188507509dbace429e18e4fdc42d977077bf96d`, expiry 1793738933 s | `b6c5949c…5655` |
| BTC/ERC-20 | `5d47702867b5121ef3a509705949164e0973e0b8e6df7690da848f1ad5073160` (block 158786, refund height 158927) | claim `7bbadc7425361894bd5311cd91d0ddb9ac710ddec77ac84027b1ab61c297475e` (block 158797) | Sepolia escrow `0xf2fd8e0441a15ee14aa56114c3d759293de4027f` (token `0x801e4398f00f8a3d9a17850ba55bc387d3c57178`), lock `a81e42b5c6fe4fe0b80532e295c07ef732deb69a2167a40debf74824ab48f6b4`, claim `04ed607d9e11135d015148cd5cd4024f64549664dcfcb48edaa87f0599afaafc`, expiry 1793734608 | `f55ac278…8dc6` |
| Bitcoin refund | `1e8a4ff81fdabecb32f5d38627c8a49a6b92a7537002488694800115c4fcfd4d` (block 158786, refund height 158789) | refund `0bdc031917d9be39cb332ee8ec440e36731353c7dd6ae6f3ecf3a5857d0f2804` (block 158797) | none | `23ed1318…02c4` |

Every Bitcoin claim paid 1,250 sats (250 sats fee) to the claimant's own P2WPKH script, and the refund paid 1,250 sats to the refund key's own script. In all four swaps the claim on the other chain, which reveals the preimage, was mined before the Bitcoin claim, and each Bitcoin claim was mined 130 blocks (132 for BTC/ETH) before the Bitcoin refund height. The Cardano claims were mined 6,930 s (ADA) and 6,894 s (token) before their expiry, the ERC-20 claim 2,940 s and the BTC/ETH claim 3,516 s before theirs. The verifier also re-read the Sepolia browser fixtures: `0x2e30a4a829edcd7aae3580b1ed77ed6d009c883f` (funded `e982e20a…`, refunded `f32252cecebaf95c5a247c8fe056e193a26c091abeda829c7d5f38b3373d833d`) and `0x25b3e3f95ccd58ba022e6c00271f8a1f7cf4737d` (funded `fb803ab4…`, refunded `94f5bfa945ab4fbecea24a08b54b5f87c58c98ea00c437d43f892981a03fdca7`, a refund call mined after the expiry that returned the exact wei to the refundee); both escrows have the pinned runtime, `spent()` true and balance zero.

Retroactive verdict of the current P1 timelock policy at the moment each pair's second leg confirmed, with Bitcoin as the long leg and heads taken from block header times (the Bitcoin head height is the highest of the funding height and the block at that time): all four swaps would be rejected today. BTC/ADA and BTC/ADA token fail `insufficient-gap` (8,312 s and 7,567 s between the short leg's last safe claim and the Bitcoin leg's first refund, against 19,211 s required); BTC/ERC-20 fails `insufficient-gap` (11,892 s against 18,767 s); BTC/ETH fails `claim-window-too-short` (1,191 s left to claim the Ethereum leg against 1,380 s required) and `insufficient-gap` (12,671 s against 18,767 s). The Bitcoin legs had 141 blocks (138 for BTC/ETH) to their refund height, and the policy needs at least 145. The Bitcoin refund case used refund height funding+3 against that 145-block floor, which it was meant to (it exercises the refund path). These swaps completed because the real chain behaved better than the policy's pessimistic tables assume, not because the margins were safe; the testnet fixtures were left as they were. Order caveat: by block header times the first claim on the other chain was mined 539 s to 2,265 s before the header time of the block that confirmed the Bitcoin funding, but testnet4 header times are not a reliable clock and the funding's first-seen time was not recorded, so the data cannot show whether the Bitcoin escrow was confirmed before the preimage was revealed. This is why the engine journal records heads and observation times.

Clean-up of leftovers from the P3 qualification runs and a scan for live escrows. Six 1000-wei Sepolia escrows left by aborted runs were refunded by `scripts/sweep_sepolia_escrows.py` (each simulated first, submitted once, balance zero afterwards): `0x738a083a…` in `0x4bf0e31a480093ff87ef8fd01ee2ef6c9181cb911817fe33060ea2004106a68b`, `0xc512cf0e…` in `0xd6e78d50b882d0843abb6dc9f1b4b34b1fd5e450449461cd218834cfe6be6e36`, `0x991a478d…` in `0x37b2dad2e3f8e4814064aafaaf1feac71963c74413bd2a079369a58c89de64eb`, `0x26b76431…` in `0x1ba9c62d4a5aadeeee9c46cc129321aba1fe4f72be696b12ac63349639c4a44a`, `0x1b5490d3…` in `0x9313e95fbf045677c1532c22089df16e88595c663d1b9cfef20d4d4793f1e88f` and `0xc42dc840…` in `0x05c83059d83125c3591369cd1d89d934ce6c616ae869da59d7c1ff8aae117c4c`. The 5 ADA Cardano escrow `b9ff41c9c4cdaf3536006a1b0cac1c47ec92b29dc01ead4b0415c73e27431f7c#0` was refunded through the hosted page (`swap-service/qualify/hosted-ui.mjs --sweep-cardano`, terms read from the datum) in `1f9821430731abdc2e38b4485d9a279b8e321c9950a3708b2cbefd8efa414ac5`; Koios showed a valid script run spending it and the validator address holding no UTxO afterwards. Scans: the 27 Sepolia contracts created by Alice and Bob (the first 600 transactions of each, from Blockscout) all have zero balance and none has `spent()` false; the pinned Cardano validator address holds nothing; every P2WSH output ever paid by the two Bitcoin wallet addresses is spent except two.

**Two Bitcoin escrows remain unspent and cannot be recovered:** `05995b8cec2d23dff568ae426333003d75aed1310d4eebcef7bfe110e07fcd87` (20,000 sats, from an aborted qualification run, refund height 159615) and `cc72202d7ceeda6a9bcf981479953f5f7848e555cda95d199004bce4f99d8ec2` (20,000 sats, block 159459; I could not tell which run broadcast it). A P2WSH output can be spent only with its witness script, which contains the hashlock the page generated for that run, and those hashlocks were lost with the closed browser sessions; I tried the hashlocks and keys of the two runs that left public traces over refund heights 159300 to 159700 and none matched. They are abandoned test funds. The qualification harness now writes each run's hashlock to its results file, so a future aborted run leaves enough to refund its escrows. Wallet balances read afterwards (not consolidated, kept for later runs): Sepolia Alice 0.1478 ETH and Bob 0.0022 ETH; Cardano preview Alice 19,882.8 ADA in 5 UTxOs and Bob 90.7 ADA in 11 UTxOs; Bitcoin testnet4 Alice 32,852 sats and Bob 24,720 sats.

Not done in P4: no new swap was run (nothing remained to finish); no claim was performed from the hosted page for a pre-existing case, because none was left to claim (the page's Bitcoin claim and refund were exercised on fresh escrows in P3); the Bitcoin and Cardano checks have no second independent Cardano provider (Koios only); the escrow outputs were checked at one point in time and a later reorganization is not excluded.

## Engine swap: Sepolia ETH and Cardano preview ADA (P2, 2026-11-06)

The first public swap driven by the swap engine (`scripts/swap_engine_cli.py`, separate initiator and responder stores, swap id `75fabdeba3d82e1f`, 00:45 to 00:52 local time) instead of a per-pair rehearsal script. Sepolia was the long leg and Cardano preview the short leg. Planned expiries came from the timelock policy's `plan_with_margin` on live heads: about 5,700 seconds ahead for Sepolia and about 3,660 seconds for Cardano preview.

| Step | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| Alice funds the escrow | Sepolia | `1b5998c2c89252fc0e64beee2c937ce8d7a920f316cb77a671d27b73ae2c8aa0` | Block 12074590, contract `0x3aeb87e73b88236425829b1f9ab7b7a9f31af84c`, 0.001 test ETH |
| Bob funds the escrow | Cardano preview | `3554254f12e6aaec3ecff4991db8fdd3428315c730945defa2532fbfc06f307d` | 10 test ADA |
| Alice claims | Cardano preview | `37ade18f0cd9bca291d06f901bef048e0ff5d4e397e3e592ea423bc287f5792d` | Reveals the preimage |
| Bob claims | Sepolia | `3998d2dad84aca5e06857457608be68790177abab66a539e63a6e41c76ed9c7f` | Block 12074618 |

Both records ended `done`. Bob learned the preimage from Alice's confirmed Cardano claim through Koios `tx_cbor`. A search of both stores, the run log and the wallet configs found no copy of the preimage outside the two mode-0600 `secret` and `learned-preimage` files. This is a provider-reported testnet snapshot like the entries above, not evidence of real-funds safety. The record of the run is `.agent/SWAP_ENGINE_EXECPLAN.md`.

## Public Hegemon smoke and engine swaps (P8, 2026-11-07)

The operator's v0.11 node on `127.0.0.1:9944` (`hegemon-node --network pre-mainnet`, data `~/.hegemon-node-v0.11`, mining off, wallet RPC on loopback, NTP synchronized, seeds `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`) followed the explorer tip. `private-spend` SHA-256 `0a145c9daef68eab7d4b4c540c4dae1ec49f3f469cacd60cc2fbacac05f7ba7d` (default features, version 0.11.2, includes `verify-htlc`). Hegemon identity statements were not attached; the Hegemon side is unauthenticated. Amounts: 10,000 HGN atoms plus a 1,000-atom fee; 0.001 Sepolia ETH; 10,000 sats; 5 ADA. Timing: Hegemon mean 75.35 s over 3,000 blocks (heights 8274–11273), one 81,258 s stall after height 9831; `proveSeconds` stays 300; a public proof on this host was about 105 s and 1.65 GiB peak RSS. Engine expiries came from `planner.plan_with_margin` on live heads.

### Smoke (labelled outside the swap policy)

Ordinary Alice to Bob transfer, then two locks of 10,000 atoms. The first lock omitted `--release-secret` so Bob could not `verify-htlc`; it expired and refunded. The second lock used `--release-secret`, Bob verified, then Alice refunded after the timeout. These used the relation minimum plus a margin (timeouts 11296 and 11343), not the swap policy's ~1,000-block floor.

| Step | Identifier | Observation |
| --- | --- | --- |
| Ordinary transfer | action `ebbf7558…d4b3fc`, attempt `b22a4711…d663ce` | Height 11278, hash `0x0000000000000211…02aa` |
| Lock 1 (no disclose) | hashlock `f074b502…e771db`, action `28dfb19c…e20d4ca`, attempt `c477762f…57cf04` | Height 11284, timeout 11296 |
| Lock 1 refund | action `0c9e6df4…034b7455`, attempt `7db9c2b9…c598a7f` | Height 11302 |
| Lock 2 (disclose, verified) | hashlock `0bf695e3…f1d030`, action `60a68077…e4f3fa51`, attempt `eb956ada…7056ba` | Height 11307, hash `0x0000000000002368…979a`, timeout 11343 |
| Lock 2 refund | action `b8fb50ff…8fc2cc6d`, attempt `78b7c3cf…adcab33f` | Height 11347, hash `0x00000000000010b3…bdcb` |

A P1 `claim_gate` against lock 2 at height 11318 returned `ok: false`, reasons `["policy-rejects-claim"]`, without revealing a preimage.

### HGN long / ETH short (engine, happy)

Swap id `e9dd9510ee39167b`, hashlock `8cfcf6108cac1d623465f75525cde1f13afdcbb567ce2ea1477b227a41e47cd0`. Hegemon expiry 12360, Sepolia expiry 1794045181. Both roles ended `done`.

| Step | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| Alice funds | Hegemon pre-mainnet | attempt `c8a41e7ef92bb44d2ec469419d6f9d89764d6caa6d001182d457771e2114cc6d` | Mined height 11360 |
| Bob funds | Sepolia | `602ad280f78d38c3d6cd1af158bfba9da9369c9e55963aea3c7007c3c9978f09` | Block 12082045, contract `0x646d947f1d5e33024d66014a1869c14f18099ed9`, 0.001 ETH |
| Alice claims | Sepolia | `34d33982cd45ae9f54fe030d5621cd2b46e1e0421b769a8dcde834fbc4dba280` | Block 12082111 |
| Bob claims | Hegemon pre-mainnet | attempt `67ff879f28298b23b9777fbfd94ae016b12752718eefdc7d64b5643b95f16ed7` | Mined height 11367 |

### ETH long / HGN short (engine, happy, other direction)

Swap id `23115ed45f3df10c`, hashlock `724b4709ad05b7333c2a5223a0080cb5efdb3965e68c4d0e9684ef296424b180`. Sepolia expiry 1794187075, Hegemon expiry 12384. Alice claimed the Hegemon short leg first (preimage disclosed on Hegemon). Both roles ended `done`. Hegemon as the short leg is exposed to a stall longer than the two-hour outage allowance.

| Step | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| Alice funds | Sepolia | `cd79858d2eec47600f3bcc2b11d8ac954fb713815ef4dc6508cf4cd9397c411b` | Block 12082457, contract `0x1a599f12c59cdfb8e403f0d99aacba3308cd263e`, 0.001 ETH |
| Bob funds | Hegemon pre-mainnet | attempt `deec6a894a62f994ddcfbe84ed7751ba51020cb5482d5ee61a3b60179cca4d08` | Mined height 11429 |
| Alice claims | Hegemon pre-mainnet | attempt `f5769ab4d8bfbbd90f0f77452bbfaeda659923a3c0820dc1069d444a6910f998` | Mined height 11442 |
| Bob claims | Sepolia | `333faef2a4daafc641c900d8708801fa0a19e498670a6d473a46372a753f8064` | Block 12082513 |

### HGN long / BTC short (engine, happy)

Swap id `c37bd256d4bea957`, hashlock `add35e40a7f674eca4b0fd7c60a5c4a03449667e23acd46f84c046445766a6c9`. Hegemon expiry 26152, Bitcoin testnet4 expiry 159894. Both roles ended `done`.

| Step | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| Alice funds | Hegemon pre-mainnet | attempt `a58e0277ab0417adca04b2e67ea2e6c00f70bf2ad53e74e93abf95a50fc97dd0` | Mined height 11380 |
| Bob funds | Bitcoin testnet4 | `eb6adffdc5f40e9c73d838d73c1ea801b1ad8442af12cdf10b66724d42580e7a` vout 0 | Height 159607, 10,000 sats |
| Alice claims | Bitcoin testnet4 | `5adc4411132c194865cfe9658dfeba4be66b117214b6eac9dc7bd2da82d4473b` | Height 159612 |
| Bob claims | Hegemon pre-mainnet | attempt `90aee5d2b6a59f7db676cd7efebaa9c46c7b1d813ae1e61ceda087924e63b6c1` | Mined height 11404 |

### HGN long / ADA short (engine, happy, resumed after a mid-submit crash)

Swap id `47409b683c7122fb`, hashlock `9b98d3f7f653e750b6c98b588af40fdffe275344aecc86b06b690dad3646063c`. Hegemon expiry 12415, Cardano preview expiry 1794049338. The initiator lock was journaled, then the runner was killed while `private-spend submit` reported `SubmissionUncertain`. A later submit of the same attempt mined at height 11416; `advance` adopted the journaled transaction. Both roles ended `done`.

| Step | Network | Transaction ID | Observation |
| --- | --- | --- | --- |
| Alice funds | Hegemon pre-mainnet | attempt `3a8fa4e1d92cd0c54ab7bad69ba9139d1f3f171be38321e30a2bb9dc8f8ff4b7` | Mined height 11416 after crash recovery |
| Bob funds | Cardano preview | `5e127a36c2dd932edc53c896dc1e1cc636149c61cc1b95576791d8752b19c0cd` | 5 ADA |
| Alice claims | Cardano preview | `86bda6c28a697a48617f447a236b7cae50a395252b51f22a6c1d099854a66fec` | Reveals the preimage |
| Bob claims | Hegemon pre-mainnet | attempt `535ab97e6c59106a18358d508a9a15fb0abb522b553bbf77465a8404158bd630` | Mined height 11423 |

### Late claim (P1 gate) and spent-lock refuse

Against the refunded smoke lock 2 (timeout 11343) at height 11405, `claim_gate` returned `ok: false` with reasons `claim-closed`, `inside-claim-cutoff`, `policy-rejects-claim`, without a preimage. A second `claim` of the already-spent HGN/ETH Hegemon lock was `ActionRefused` (`the verified escrow is not an unspent note of this wallet`).

Local Hegemon adapter results from P6 remain in `.agent/SWAP_HEGEMON_ADAPTER_RESULTS.json` and say nothing about public timing.

## Reconciliation note (P7)

The sections above were written at different times and use the policy in force then. Two corrections apply to all of them. First, the P1 timelock policy (Bitcoin refund at least 145 blocks ahead, spacing between the legs) postdates the BTC/ETH, BTC/ADA, BTC/ADA-token and BTC/ERC-20 rehearsals, and the retroactive verdict in the P4 section shows each would be rejected today; those swaps completed, but their margins do not satisfy the policy. The rehearsal scripts were left as evidence with their refund distance raised to 150 blocks so they run again (`scripts/SWAP_SCRIPTS.md`). Second, where an earlier entry says a leftover was waiting, the P4 section is the final state: the Sepolia and Cardano leftovers were refunded and two Bitcoin escrows remain unspent and unrecoverable because their hashlocks were lost.
