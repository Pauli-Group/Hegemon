# Bitcoin ASIC mining on Hegemon

The native node can issue a Bitcoin style 80-byte SHA-256d block header for its
own Hegemon block candidate. `scripts/bitcoin_asic_stratum.py` translates that
work into Stratum V1 jobs for a Bitcoin ASIC. A valid solution is submitted to
the Hegemon node, which remains the authority for consensus and block import.
This does not create Bitcoin transactions, Bitcoin coinbase payouts, or a
Bitcoin ledger.

## Run a local adapter

Use a release and genesis approved for the chosen network before joining it.
Start the native node with its mining authoring mode and unsafe loopback RPC enabled.
For ASIC-only mining, disable the CPU miner but explicitly permit authoring with
`HEGEMON_MINE=0 HEGEMON_BOOTSTRAP_AUTHORING=1`. Set `HEGEMON_MINER_ADDRESS` to
the intended Hegemon reward address; leaving it unset forfeits the reward and
is appropriate only for the disposable PoW smoke test below.
For the shared testnet, use the verified seed list consistently on all miners:

    HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"

Keep NTP or chrony enabled; consensus rejects headers beyond its future time
bound. The node's mining template may be unavailable while syncing or while a
block candidate is waiting for required proof work.

Set one exact worker name and a secret in the adapter's environment, then run:

    export HEGEMON_STRATUM_PASSWORD='choose-a-long-random-secret'
    python3 scripts/bitcoin_asic_stratum.py \
      --rpc-url http://127.0.0.1:9944 \
      --bind 127.0.0.1 --port 3333 \
      --worker miner.1 --share-difficulty 0.001

The native RPC does not authenticate pool tokens. Keep its listener on loopback
and use an authenticated SSH tunnel when the adapter is remote. A nonempty
`HEGEMON_POOL_RPC_TOKEN` is rejected by the adapter. Configure the ASIC's Stratum V1 pool to point to
`stratum+tcp://127.0.0.1:3333`, worker `miner.1`, and the same password. An ASIC
on another host needs a private TCP tunnel or a deliberate public bind with
`--allow-public-bind`; Stratum V1 itself sends credentials and work without
transport encryption. Restrict reachability; a trusted isolated mining LAN or
an appropriately secured external tunnel is required for remote hardware.
Any classical TLS front end has its own non-PQ transport trust boundary and is
not part of the native node's PQ transport. The adapter accepts at most 32 simultaneous clients by
default and reads at most 8192 bytes per newline JSON request. Each connection
has a bounded outbound queue; a miner that stops reading is disconnected when
its queue fills, without delaying work for other miners.

The default split is a 20-byte server extranonce1 plus an 8-byte miner
extranonce2. For firmware requiring the previous 24+4 split, add
`--extranonce2-bytes 4`. Other positive splits can be configured with that
option; the combined extranonce always remains 28 bytes. Configure a separate
adapter listener for devices requiring a different split.

The adapter uses Python's standard library only. No package installation is
needed. Check its command line options with `python3 scripts/bitcoin_asic_stratum.py
--help`.

## Wire contract

The adapter polls `hegemon_poolWork` and requires `available: true`,
`algorithm: "sha256d-bitcoin80"`, `job_id`, `version`, `parent_hash`, `ntime`,
`nbits`, `target`, `coinbase_prefix`, `coinbase_suffix`, `extranonce_bytes: 28`,
`header80`, and `expires_in`. The node also advertises `version_rolling_mask`:
`00000000` before the selected mining-profile activation and `1fffffe0` once
active. An older RPC without the field is treated as fixed version.
`version`, `version_rolling_mask`, `ntime`, and `nbits` are eight numeric
hex characters; `parent_hash` is the `0x`-prefixed 32-byte displayed big endian hash;
`target` is a `0x`-prefixed 32-byte displayed big endian integer;
`header80` is 160 raw hex characters. The adapter checks that `header80`
matches an independently built 80-byte header with zero extranonce and nonce.
For Bitcoin80 work, `nbits` must be the exact canonical positive Bitcoin
compact encoding of a nonzero target no easier than `0x207fffff`. The adapter
rejects a sign bit, overflow, noncanonical encodings, and any disagreement
between `nbits` and the node's expanded target.

Each connection gets a unique extranonce1 and provides the extranonce2 size
returned by `mining.subscribe` (20+8 by default, 24+4 with the compatibility
option). The node provides a serialized Bitcoin-shaped synthetic
coinbase wrapper. Its bytes are
`coinbase_prefix || extranonce1 || extranonce2 || coinbase_suffix`.
Double SHA-256 of those bytes is the sole merkle root, so `mining.notify` has
an empty merkle branch list. The Stratum previous hash reverses the order of
the eight 4-byte words of the displayed parent hash. The resulting header is
`versionLE4 || parentHashReversed32 || merkleRoot32 || ntimeLE4 || nbitsLE4 || nonceLE4`.
Fixed-version clients continue to submit five fields. A client can negotiate
the `version-rolling` extension through [BIP310](https://github.com/bitcoin/bips/blob/master/bip-0310.mediawiki)
with `mining.configure`, providing its eight-character `version-rolling.mask`
(default `ffffffff`) and required integer `version-rolling.min-bit-count`.
The response gives the intersection of the device and current job masks. The
minimum bit count is diagnostic: a device requesting more bits than available
stays connected and can choose degraded operation. A negotiated extension with
zero available bits returns a zero mask; activation and reorganization changes
arrive through `mining.set_version_mask` before the new job notification.

A negotiated client must send the sixth `mining.submit` field, `version_bits`.
The adapter rejects any bit outside the last negotiated mask and constructs
`nVersion = (job_version & ~mask) | version_bits`. Consensus independently
restricts changes to the 24 mining bits `0x1fffffe0` at the active height.
Those bits are reserved for mining; no deployment signaling is encoded there.
Before the v0.11.5 activation at H28,860, submissions must repeat the job's
exact `ntime`. At activation the node advertises `ntime_rolling: true`,
`ntime_activation_height`, `min_ntime`, `max_ntime`, `server_time` and
`max_future_skew_seconds: 90`. Time fields are eight-character numeric hex.
The inclusive minimum is the first whole second strictly after the parent;
the maximum is the node clock plus 90 seconds at the response. Miners may
submit before or after the suggested time inside those bounds. Old RPCs
without range fields retain fixed-time behavior. The adapter advances observed
node time using monotonic elapsed time and refreshes it on polls; final native
admission checks its current clock. Polling never renews the original
120-second job expiry. See [the consensus specification](../consensus/NTIME_ROLLING.md)
for exact commitment and activation semantics. Version and time rolling do
not ease the target or change the 60-second target spacing and parent-driven
ASERT behavior.

The adapter authenticates `mining.authorize` against its configured worker and
password, announces the configured share difficulty or the easier network
difficulty for that job, reconstructs and double hashes
each submitted header, rejects low difficulty and duplicate shares, and forwards
only full network target solutions through `hegemon_submitPoolShare` with
`{job_id, nonce, extranonce, ntime, mining_version}`; `mining_version` is the
complete effective eight-character header version. Duplicate and bounded retry
identities include that version. The node makes the final admission
decision. A locally accepted share below the network target is a measurement
of miner work, not a mined Hegemon block.

## Historical Bitcoin80 genesis reset

The initial Bitcoin80 transition changed consensus and selected rules hash
`a08fc9ec383eec2bff554c64085bed809160241b89cee84cf2c8f27170a7e41f`
with genesis domain `hegemon-native-genesis-bitcoin80-v1`. It is not a
compatible upgrade of a running V2 chain. The new binary refuses to open
an old-rules database rather than reinterpret or overwrite it.

For a coordinated reset, first approve the same release artifact and genesis
on both seed hosts, stop the old services, and preserve their complete node
and wallet data. Configure both services with new empty base paths, the same
verified seeds, and the intended miner addresses. Start the new era together,
then confirm genesis and rules hashes, peer connections, accepted mining work,
and cross-node tip agreement. Keep old data and the previous binary available
for rollback. Do not delete the old databases or expect old testnet notes to
become spendable automatically on the new genesis. The later v0.11.4 and
v0.11.5 height-activated upgrades preserve the existing Bitcoin80 genesis and databases; they do not require this historical reset.

The dev genesis target is CPU-bootstrap difficulty, not a TH/s launch setting.
Before connecting high-throughput miners, select and test a common appropriate
initial target and retarget behavior for the intended hardware. ASIC hashrate
must be measured on this actual work; Bitcoin marketing TH/s is not testnet
security evidence.

New same-parent templates retain preceding jobs until expiry (up to 64 jobs)
and notify miners with `clean_jobs: false`. A new parent or unavailable node
work clears those jobs. Ordinary shares use a bounded duplicate cache separate
from full network-solution reservations. A node RPC failure or rejection
releases a solution reservation so the exact solution can be retried.

## Validation

Run the socket-level tests without hardware:

    python3 -B scripts/test_bitcoin_asic_stratum.py

These use an in-process mock of the node RPC and actual loopback TCP. They
cover subscribe, authorization, notify, share submission, header bytes,
malformed input, stale jobs, wrong passwords, duplicate shares, job retention,
cache saturation, stalled clients, fixed time, fixed-version compatibility,
24+4 compatibility, default 20+8, negotiated device subsets, below-minimum
diagnostics, malformed configuration, out-of-mask rejection, exact rolled
header bytes, version-aware duplicate identity, activation/reorg mask
notifications, solved backward/forward time rolling, refreshed node-clock
bounds, clock rollback and original job expiry.
They do not show that a physical ASIC, a real node,
or the shared testnet accepted a block. Hardware validation still requires an
approved node release and genesis, a connected ASIC, a full-target solution,
node acceptance, and verification that another node imported the block.

For a real software end-to-end check, build the native binary and run:

    CARGO_BUILD_JOBS=2 cargo build --locked --profile retained-proof -p hegemon-node --bin hegemon-node
    python3 -B scripts/test_bitcoin_asic_live.py \
      --node-bin "$(pwd)/target/retained-proof/hegemon-node" --timeout 300

The harness creates two new temporary databases and loopback peers, starts the
actual adapter, independently constructs and solves its 80-byte header, checks
that its hash equals the accepted block hash, verifies second-node sync, rejects
wrong-time and duplicate submissions, and reopens the first database at the same
tip. It stops its owned processes and retains a JSON receipt and logs. It does
not join the shared testnet or touch existing node/wallet data. Neither software
test substitutes for unmodified physical ASIC acceptance.
