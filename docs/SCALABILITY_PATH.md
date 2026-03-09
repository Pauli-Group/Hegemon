# Scalability Path

This document records the intended path from the current small deployment
(one public authoring node, one private proving machine, an intermittent
laptop, and users without dedicated proving hardware) to a wider proving
market. It is a topology and
operations reference, not a consensus specification. The operator-facing
upgrade steps for the immediate topology live in
[runbooks/authoring_pool_upgrade.md](../runbooks/authoring_pool_upgrade.md).

## Design rules

- Separate **authors** from **hashers**. A small number of authoring nodes
  assemble candidate sets and coordinate proving; a larger number of workers
  contribute PoW without each becoming an independent shielded block author.
- Keep transaction proving portable. Wallets should continue submitting
  self-contained transactions by default so pending transfers remain mineable
  even when proof sidecars are unavailable on a given author.
- Keep spend witnesses out of the public market. External block proving should
  consume transaction proof bytes and statement metadata, never private spend
  witnesses.
- Make proving jobs deterministic and reusable. Work identifiers must derive
  from the parent hash, canonical transaction ordering, proof shape, and chunk
  range so completed work can be reused by any author building on that parent.
- Move proving off the block-assembly critical path. Prove-ahead scheduling and
  prepared-bundle caches are mandatory for throughput.

## Phase 0: 0.9.1 authoring pool

This is the immediate target topology.

- one node is the only public authoring node.
- one proving machine remains private with no inbound internet exposure.
- the private proving machine initiates an outbound tunnel to the public
  authoring node over WireGuard, Tailscale, or an SSH reverse tunnel.
- the public authoring node runs the mining/coordinator node with local proving disabled by
  setting `HEGEMON_PROVER_WORKERS=0` (or
  `HEGEMON_AGG_STAGE_LOCAL_PARALLELISM=0`).
- the worker on the private proving machine polls `prover_*` over the private tunnel and
  returns batch results.
- Laptops and app users participate primarily as pooled hashers or full nodes,
  not as independent shielded block authors.

Information flow:

1. Wallets submit portable self-contained transactions.
2. The public authoring node canonicalizes the candidate set and runs
   prove-ahead.
3. The private proving machine pulls deterministic chunk work and returns
   results.
4. The public authoring node assembles a ready `BlockProofBundle`.
5. Many hashers mine on the same prepared template.
6. The winning worker returns the nonce/share and the public authoring node
   broadcasts the block.

Why this is the right first step:

- One prepared bundle is amortized across many hashers.
- Weak miners can participate immediately without proving hardware.
- The private prover can scale independently from public network exposure.
- The operational model is close to what the current code already supports.

Current approved seed list for miners:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:31333,158.69.222.121:31333"
```

All miners in this topology must use the same approved `HEGEMON_SEEDS` list to
avoid forked peer partitions. All mining hosts must also keep NTP/chrony time
sync enabled because PoW headers beyond the future-skew bound are rejected.

## Phase 1: CPU proving fabric behind the author

Once a single private prover becomes the bottleneck, add more CPU provers
behind the authoring pool before changing consensus.

- Keep a small number of authors.
- Publish deterministic leaf/chunk jobs for the largest candidate set.
- Let additional CPU provers pull `leaf_batch_prove` jobs.
- Keep root assembly and final template attachment on the authoring side.
- Use off-chain accounting for prover payouts while the network is still using
  a single public author.

This stage should raise throughput without multiplying duplicate work across
many authors.

## Phase 2: federated authoring pools

After the first pool is stable, grow decentralization by running several
competing authoring pools, each with its own proving backend.

- Each pool exposes a public authoring surface and private proving fabric.
- Hashers can switch pools freely.
- Pools can continue using off-chain share accounting and prover settlement.
- Solo miners with dedicated proving hardware can still coexist, but the normal
  user path remains pooled authorship.

This is the preferred medium-term shape because it improves censorship
resistance without immediately requiring a fully permissionless public prover
market.

## Phase 3: public PQ-authenticated prover market

The final target is a reusable proving fabric available to many authors on the
same parent.

- Authors publish deterministic parent-scoped jobs.
- Provers specialize by stage and hardware class:
  - CPUs for flat/leaf batch proofs
  - high-memory CPUs for commitment and merge staging
  - GPUs later for merge/root recursion
- Prover work travels over a PQ-authenticated protocol layered on the existing
  network transport, not raw public JSON-RPC.
- Accepted work is cached by deterministic job identifier so any author on that
  parent can reuse it instead of reproving it.

This is where the network transitions from “a few pools with private proving
clusters” to “a shared proving market”.

## Consensus impact by phase

### Topology-only phases

These phases should not require consensus changes:

- Phase 0 authoring pool
- Phase 1 CPU proving fabric behind the author
- Phase 2 federated authoring pools
- A brokered public prover market with off-chain accounting

Consensus continues to validate the final `BlockProofBundle`; it does not need
to validate work reservations, bids, queueing, or share accounting.

### Consensus-touching phases

These phases likely do require consensus changes:

- multi-prover on-chain compensation
- on-chain work receipts or escrow
- bonds/slashing for failed or malicious public provers
- richer payout commitments than the current single optional `prover_claim`

Until those changes exist, public prover markets should settle economically
off-chain even if proof work itself is coordinated over the network.

## Immediate next topology upgrade

When upgrading to the 0.9.1 topology:

- Put one node in front as the only public authoring node.
- Keep the proving machine private.
- Establish an outbound-only private tunnel from the proving machine to the
  public authoring node.
- Bind RPC on the public authoring node to localhost or the VPN interface. If any RPC must
  cross the public internet, terminate TLS and IP-filter at the proxy.
- Keep user-facing mining pooled until there is either:
  - a second stable authoring pool, or
  - a real authenticated public prover market with reusable parent-scoped jobs.

This keeps users engaged by letting them hash now while preserving a clean path
to higher-throughput authoring later.
