# Public testnet HTLC rehearsal results

These are disposable test funds and fixture assets. Ethereum data came from a public Sepolia RPC, and Cardano data came from the public Koios preview service. The reported snapshots trust those providers; confirmation depth is not a guarantee of finality or real-fund safety. No public Hegemon node was started or synced.

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

Leftovers from aborted harness runs (disposable; the secrets were lost with the closed browsers, so these can only be refunded): Sepolia escrows of 1000 wei at `0x738a083a13772637723f24357c592fc3807d35e3`, `0xc512cf0ec872d14474f1eb969c0ab92ff0f301ea`, `0x991a478df723ec340b313cde0cb481e198a8bbc1`, `0x26b7643103a0b7577915f425e4a6e6e7cb13a93a`, `0x1b5490d35f62099738ea4f9d99ca5f4d873f1e9c` and `0xc42dc840f13f5f87df1f44e24864728e5c5a3afc` (a seventh, `0xcb986b6c1e07c4be7af273dc499b2c9e58f25bf1`, was claimed in transaction `0x506e420e4bc580677433cdf41ed4bca18287a5f8cf4345e7c5b36dee230451e0` of an earlier run, which also claimed a Cardano escrow funded in `04cc07ed737704a2223e64b43926a565ee6557ad262327a167df4223baa4ca1c` with `fe07985f0bd53c7e97842858c492a69608fe7653dc425da852e8b6048617ca5f`); a 5 ADA Cardano escrow funded in `b9ff41c9c4cdaf3536006a1b0cac1c47ec92b29dc01ead4b0415c73e27431f7c`; and a 20,000 sat Bitcoin escrow in `05995b8cec2d23dff568ae426333003d75aed1310d4eebcef7bfe110e07fcd87` refundable by Alice at height 159615.
