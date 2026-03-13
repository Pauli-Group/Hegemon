# Template-builder rollout runbook (`hegemon-ovh` public builder + `hegemon-prover` private prover)

Use this runbook to move from the current “single public miner with local
proving assumptions” setup to the first permissionless-template-builder
topology for Hegemon.
The goal is simple:

- `hegemon-ovh` becomes the only public template builder / compact-job endpoint
- `hegemon-prover` contributes proving over an outbound-only tunnel
- users can participate as pooled hashers or full nodes without needing proving
  hardware.

This is the right intermediate step because it increases participation and PoW
security immediately while preserving prover efficiency. A single prepared
artifact-backed template can feed many hashers; weak machines do not need to
become independent shielded block authors.

Before doing any server work, follow
[config/testnet-initialization.md](/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md).
The laptop-created `hegemon-boot-wallet` address must be configured as both
`HEGEMON_MINER_ADDRESS` and `HEGEMON_PROVER_REWARD_ADDRESS` on the laptop,
`hegemon-ovh`, and `hegemon-prover`. Do not copy the wallet store to either
server.

> **Current repository status:** the node already exposes coordinator-side
> `prover_*` RPC methods for external work packages. The repo now also ships
> a standalone private prover worker binary (`hegemon-prover-worker`) plus a
> pooled hash-worker client in the desktop app. Pool share accounting is still
> process-local. The prover worker handles recursive `leaf_batch_prove` and
> `merge_node_prove` stage packages, prewarms its aggregation cache on startup,
> and logs stage start/completion timing, so the core topology is runnable
> rather than aspirational.

## 1. Target topology

Treat the deployment as three roles:

- **Public template-builder node (`hegemon-ovh`)**: public-facing node that
  accepts wallet traffic, canonicalizes candidate sets, schedules proving,
  assembles ready artifacts/templates, and broadcasts final blocks.
- **Private prover backend**: non-public machine that pulls
  `prover_*` work packages from the builder over a private tunnel and returns
  results.
- **Participants (laptop, app users, community miners)**: pooled hashers or
  full nodes. They should not be independent shielded block authors unless they
  bring their own proving capacity and are prepared to operate as a separate
  template-builder / pool.

The intended information flow is:

1. Wallets submit portable self-contained transactions to the public
   template-builder
   node.
2. The public template-builder node canonicalizes the parent-scoped candidate
   set and starts
   prove-ahead scheduling.
3. The private prover backend pulls deterministic proving work over the tunnel
   and submits results.
4. The public template-builder node assembles a ready `CandidateArtifact` and
   compact mining job.
5. Hash workers mine on the same prepared template.
6. The winning share/nonce returns to the public template-builder node, which
   broadcasts the block to the network.

## 2. Network boundaries

### Public template-builder node surface

Expose only what is needed for the public template-builder node:

- P2P listener for the Hegemon network.
- pool/public API surface for pooled miners and app users.
- optional public wallet submission surface if you want the same node to serve
  both end users and the pool.

Do **not** expose the prover RPC broadly to the public internet.

RPC guidance:

- bind JSON-RPC to localhost or the VPN interface whenever possible
- if any RPC must cross the public internet, terminate TLS at the proxy and
  IP-filter aggressively
- prefer an SSH tunnel or VPN rather than direct public RPC exposure

### Private prover backend boundary

The private prover backend should have:

- no inbound public internet exposure
- no public P2P listener requirement
- only outbound connectivity to the public template-builder node through
  WireGuard, Tailscale, or an SSH reverse tunnel

The private prover should never become the first public entry point for users.

### Shared network invariants

All mining hosts must share the same approved bootstrap seeds:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333"
```

If miners use diverging seed lists, peer partitions and forks become much more
likely.

All mining hosts must keep time sync healthy:

- enable NTP/chrony on every mining host
- verify tracking before and after the cutover

PoW headers beyond the future-skew bound are rejected.

## 3. Host responsibilities

### Public authoring node

The public authoring node should run:

- the public `hegemon-node`
- prove-ahead coordinator
- `HEGEMON_AGGREGATION_PROOFS=1`
- `HEGEMON_BATCH_JOB_TIMEOUT_MS=3600000`
- `HEGEMON_PROVER_WORK_PACKAGE_TTL_MS=3600000`
- `HEGEMON_AGG_HOLD_MINING_WHILE_PROVING=1`
- local proving disabled via:

  ```bash
  HEGEMON_PROVER_WORKERS=0
  ```

  or

  ```bash
  HEGEMON_AGG_STAGE_LOCAL_PARALLELISM=0
  ```

- pooled mining coordinator logic outside the node, if you are already running
  a separate share server or template server

The public authoring node is the only host that should construct public templates and
broadcast blocks in this phase.

Those four aggregation env vars are not optional for the current external-prover
cutover. Without them, proof-sidecar transfers are either skipped immediately or
allowed to churn forever against stale parents while the local miner keeps
authoring empty PoW blocks.

### Private prover backend

The private prover backend should run:

- `hegemon-prover-worker`
- no public-facing node role
- no local public mining role

It should poll `prover_*` over the private tunnel, solve the work packages it
is capable of handling, and send the results back to the author.

Example launch:

```bash
HEGEMON_PROVER_RPC_URL=http://127.0.0.1:9944 \
HEGEMON_PROVER_SOURCE=private-prover-01 \
./target/release/hegemon-prover-worker
```

Notes:

- this worker consumes recursive `leaf_batch_prove` and `merge_node_prove`
  stage packages
- it prewarms aggregation cache state on startup unless
  `HEGEMON_AGG_DISABLE_WORKER_PREWARM=1`
- it expects the private tunnel to expose the authoring node RPC securely
- for the current remote deployment, the authoring node should expose
  `package_ttl_ms=3600000` through `HEGEMON_PROVER_WORK_PACKAGE_TTL_MS`

### Laptop / app users

In this phase, laptops and app users should do one of two things:

- run a full node for verification and wallet use
- join the pool as a hasher

They should not be presented as first-class independent shielded block authors.
That would multiply proving work while the network still depends on a small
number of private provers.

## 4. First pooled miner UX in the app

The first public mining experience should be **pooled hashing only**.

The app should make this explicit:

- “Mine with pool” is the primary action for users without proving hardware.
- “Run full node only” is available for users who want to verify the network
  but not contribute hashpower.
- “Author blocks / operate a pool” should stay hidden behind an advanced or
  operator-only path until the proving market is broader.

The first pooled UX should ask for:

- pool endpoint
- worker name
- payout address
- optional local node connection if the user also wants a full node

The app should tell the user what is happening:

- their machine is hashing against pool-provided templates
- the pool handles proving and block assembly
- their reward is based on accepted shares, not solo block wins

The app should also explain what it is **not** doing:

- it is not independently authoring shielded blocks
- it is not uploading spend witnesses to third-party provers
- it does not need local proving hardware to participate

## 5. Criteria for assigning a new participant to a role

Use these rules when onboarding new participants.

### Join as a hasher

Default path for:

- laptops
- desktops
- app users
- anyone with stable internet but no proving hardware
- anyone who wants immediate participation without operating authoring
  infrastructure

They should join as a hasher when:

- they can sustain hashing but not block proving
- they do not want to expose services publicly
- they want the simplest setup and fastest time to contribution

### Join as a prover

Recommended for:

- users with many CPU cores
- high-memory servers
- private machines with stable uptime
- contributors who want to increase throughput rather than just hashpower

They should join as a prover when:

- their machine can solve chunk/batch proving jobs reliably
- they can maintain a private tunnel or authenticated link to an authoring pool
- they accept that, in the short term, payout may be brokered or off-chain

Large machines should become provers **before** they become independent public
authors.

### Join as a second pool operator

This is the next decentralization milestone after the first pool is stable.

A participant should become a second pool operator only when they can provide:

- a public authoring node with good uptime
- a private prover backend (or backend cluster)
- secure networking and monitoring
- a separate pool endpoint for hash workers
- operational capacity to track forks, proofs, templates, and payouts

Do not recruit second pool operators until:

- the first pool topology is stable
- prove-ahead + external proving works reliably
- the participant can add authoring diversity instead of just duplicating the
  same prover bottleneck

## 6. Concrete next steps for the cutover

### Step 1: lock down the topology

- declare one node the only public authoring node for the next release
- declare the proving host private-only
- decide which VPN/tunnel mechanism will be used
- keep the approved `HEGEMON_SEEDS` list identical on all mining hosts
- verify NTP/chrony on every mining host

### Step 2: move proving behind the tunnel

- configure the tunnel from the private prover backend to the public authoring node
- set `HEGEMON_AGGREGATION_PROOFS=1` on the public authoring node
- set `HEGEMON_PROVER_WORKERS=0` on the public authoring node
- set `HEGEMON_BATCH_JOB_TIMEOUT_MS=3600000` and
  `HEGEMON_PROVER_WORK_PACKAGE_TTL_MS=3600000` on the public authoring node
- keep `HEGEMON_AGG_HOLD_MINING_WHILE_PROVING=1` on the public authoring node
- verify the coordinator on the public authoring node still publishes `prover_*` work
  packages over the private path
- launch `hegemon-prover-worker` on the private prover backend and verify it
  can pull stage work packages and return accepted results

### Step 3: freeze the public miner story

- app and docs should say “pool hashing” for normal users
- do not advertise public shielded block authorship from the app yet
- keep full-node-only mode available for users who do not want to hash

### Step 4: classify incoming contributors

When a new participant appears:

- weak/consumer hardware: route them to pooled hashing
- strong private CPU hardware: route them to prover onboarding
- strong infra + public host + private prover backend: consider them for second
  pool operation

## 7. Acceptance checks

Before declaring the cutover complete, verify:

- the public authoring node is the only public authoring endpoint
- the private prover backend has no inbound public exposure
- the private tunnel is required for prover traffic and works reliably
- all mining hosts use the same approved `HEGEMON_SEEDS`
- NTP/chrony is healthy on all mining hosts
- a wallet can submit portable self-contained transactions through
  the public authoring node
- the private prover backend can complete external work packages through
  `hegemon-prover-worker`
- the public authoring node pauses local mining while a strict proofless batch
  waits for a ready proven bundle, then resumes mining after the bundle is ready
- pooled hash workers can fetch author work and submit shares without local
  proving hardware
- pooled miners can hash without local proving

## 8. What comes next

After this cutover is stable, the next decentralization step is **not** broad
public authoring. The next step is either:

- add more CPU provers behind the authoring pool, or
- add a second independent authoring pool with its own prover backend

Only after those are healthy should the network move toward a PQ-authenticated
public prover market and wider authoring.
