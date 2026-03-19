# Authoring Node Rollout Runbook (`hegemon-ovh` public authoring node)

The filename is historical. The current rollout is not “public builder plus private prover.” It is one public authoring node running the live `InlineTx` lane.

Use this runbook to move from ad hoc local mining to a stable public authoring node.

## 1. Topology

Current production shape:

- `hegemon-ovh` is the only public authoring node and miner.
- wallets or trusted private services produce tx proofs before submission.
- laptops and other participants run as full nodes and wallet clients.

Do **not** provision `hegemon-prover` or `hegemon-prover-worker` as part of this rollout.

Before doing any server work, follow [config/testnet-initialization.md](/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md). The laptop-created `hegemon-boot-wallet` address must be configured as `HEGEMON_MINER_ADDRESS` on the authoring node. Do not copy the wallet store to the server.

## 2. Network invariants

All mining hosts must share the same approved bootstrap seeds:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333"
```

If you are bringing up the first public authoring node after a full reset, do not seed it to itself. Start that first node with `HEGEMON_SEEDS` unset, then use the approved public join seed list on every other miner and relay.

All mining hosts must also keep NTP/chrony time sync healthy. PoW headers beyond the future-skew bound are rejected.

Expose only what is needed:

- P2P listener for the Hegemon network.
- Optional wallet submission surface if the same node serves end users.
- Keep RPC bound to localhost or a trusted tunnel whenever possible.

## 3. Authoring-node responsibilities

The public authoring node should:

- accept proof-ready shielded transactions,
- keep mining enabled locally,
- build the parent-bound commitment proof,
- broadcast final blocks.

The live path is `InlineTx`, so block assembly consumes canonical inline tx proofs. There is no external recursive prover dependency in the normal path.

Recommended operator checks:

- same chainspec hash as the rest of the testnet,
- `HEGEMON_SEEDS` set exactly to the approved list,
- `HEGEMON_MINER_ADDRESS` set to the laptop boot-wallet address,
- retention settings pinned explicitly on testnet if wallets need full ciphertext/proof history.

## 4. Desktop role guidance

For this version, the desktop should expose only:

- **Full node**
- **Authoring node**

Ordinary users should not be pointed at pooled hashing or private prover roles. Those are not part of the current shipped topology.

## 5. Acceptance criteria

The rollout is healthy when:

- the public authoring node mines and imports blocks on the shared chainspec,
- proof-ready txs are accepted and included,
- full nodes sync and verify without custom prover infrastructure,
- no operator is told to deploy `hegemon-prover` just to run the current network.
