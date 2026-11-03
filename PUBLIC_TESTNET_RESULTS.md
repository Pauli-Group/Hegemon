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

## Bitcoin testnet4 and Sepolia ETH (in progress)

The Bitcoin escrow funding transaction `cdeecb1da3ea00b1a7e5e4981eb073a656526073da61fe201c98c1de8e85bd8a` was submitted. Confirmation and the subsequent swap have not yet been established. Blockstream did not provide a six-block testnet4 fee estimate; the driver falls back to a second, genesis-checked testnet4 service and retains the more conservative available estimate. The reported provider observations remain trusted rather than independently verified.
