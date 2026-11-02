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

The setup transaction `f1710647c8dd9510d58a931993cb65a7eb935977c8ea8b87b51abf6ff039cd4a` also minted a disposable Cardano fungible fixture and one-of-one fixture and created fee and collateral outputs. Other token combinations, refund scenarios and Bitcoin cases are separate tests and are not established by this result.

## Sepolia ERC-20 and ERC-721

A same-chain fixture swap completed between 100 ERC-20 units and ERC-721 token 42. The NFT claim `25abafdb49c9a32361b15aa4a1509d6a80f7d32574ffe93f64dd8567a172e02d` exposed the preimage, which was read from the confirmed transaction and used for the ERC-20 claim `003a4c258156b54b83d1d170f04ce37b9bb7af3c207dc8a3a790cc9683d38ac8`. Both fixture balances and the NFT owner matched the expected recipients. The fixture contracts implement the interfaces exercised by this test and are not production tokens.
