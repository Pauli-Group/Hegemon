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

If the node requires an RPC pool token, set `HEGEMON_POOL_RPC_TOKEN` in the
adapter's environment. Configure the ASIC's Stratum V1 pool to point to
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

The adapter uses Python's standard library only. No package installation is
needed. Check its command line options with `python3 scripts/bitcoin_asic_stratum.py
--help`.

## Wire contract

The adapter polls `hegemon_poolWork` and requires `available: true`,
`algorithm: "sha256d-bitcoin80"`, `job_id`, `version`, `parent_hash`, `ntime`,
`nbits`, `target`, `coinbase_prefix`, `coinbase_suffix`, `extranonce_bytes: 28`,
`header80`, and `expires_in`. `version`, `ntime`, and `nbits` are eight numeric
hex characters; `parent_hash` is the `0x`-prefixed 32-byte displayed big endian hash;
`target` is a `0x`-prefixed 32-byte displayed big endian integer;
`header80` is 160 raw hex characters. The adapter checks that `header80`
matches an independently built 80-byte header with zero extranonce and nonce.
For Bitcoin80 work, `nbits` must be the exact canonical positive Bitcoin
compact encoding of a nonzero target no easier than `0x207fffff`. The adapter
rejects a sign bit, overflow, noncanonical encodings, and any disagreement
between `nbits` and the node's expanded target.

Each authorized connection gets a unique 24-byte extranonce1 and provides a
4-byte extranonce2. The node provides a serialized Bitcoin-shaped synthetic
coinbase wrapper. Its bytes are
`coinbase_prefix || extranonce1 || extranonce2 || coinbase_suffix`.
Double SHA-256 of those bytes is the sole merkle root, so `mining.notify` has
an empty merkle branch list. The Stratum previous hash reverses the order of
the eight 4-byte words of the displayed parent hash. The resulting header is
`versionLE4 || parentHashReversed32 || merkleRoot32 || ntimeLE4 || nbitsLE4 || nonceLE4`.
The miner's requested version stays fixed: `mining.configure` reports version
rolling disabled and a zero mask. Time rolling is also disabled, so submissions
must repeat the job's exact `ntime`.

The adapter authenticates `mining.authorize` against its configured worker and
password, announces the configured share difficulty or the easier network
difficulty for that job, reconstructs and double hashes
each submitted header, rejects low difficulty and duplicate shares, and forwards
only full network target solutions through `hegemon_submitPoolShare` with
`{job_id, nonce, extranonce, ntime}`. The node makes the final admission
decision. A locally accepted share below the network target is a measurement
of miner work, not a mined Hegemon block.

## Coordinated testnet reset

This follow-up changes consensus and selects rules hash
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
become spendable automatically on the new genesis. This PR does not perform
that reset or select its release authority.

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
cache saturation, stalled clients, and fixed time and version enforcement.
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
