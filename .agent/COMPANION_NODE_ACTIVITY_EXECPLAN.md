# Show node progress in the companion window

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

A person who starts the local Hegemon node and the swap companion window currently sees a window that only talks about the wallet. Restarting the node spends many minutes rebuilding chain state and rechecking private proofs before it opens its local service port. During that time the window looks idle, and the person can reasonably think the node has stopped. After this change, the companion window shows whether the node is running, which step it is on, how much of that step is done, and a plain estimate of the time left. The hosted website still never receives that progress.

## Progress

- [x] (2026-11-11 18:20Z) Write this ExecPlan before changing product code.
- [x] (2026-11-11 18:24Z) Publish `node-activity.json` from each startup step and cover the writer with a Rust test.
- [x] (2026-11-11 18:25Z) Teach the companion to read that file or the live node service, and to format the step, fraction, and time estimate.
- [x] (2026-11-11 18:26Z) Add the node card to the companion window.
- [x] (2026-11-11 18:27Z) Cover the sentences with Python tests and update DESIGN.md, METHODS.md, and scripts/SWAP_SCRIPTS.md.

## Surprises & Discoveries

- Observation: the long silent period is the node's own startup, and its JSON service on port 9944 is not listening yet. The companion cannot ask the node anything until that port opens.
  Evidence: a restart on 2026-11-11 kept ports 9944 and 30333 closed through "Rebuilding chain state" and "Rechecking private proofs" for the stored 15,818 blocks. The only progress was tracing lines on the node's own output.

## Decision Log

- Decision: the node writes a small JSON file, `node-activity.json`, in its base directory while it is starting. The companion reads that file only when the local service port is closed. Once the service answers, the service is the source of truth.
  Rationale: the file is the only local fact available during the long startup. Parsing the node's log would depend on wherever that process was started. The file contains a phase name, two counters, a timestamp, and the process id. It contains no wallet data.
  Date/Author: 2026-11-11

- Decision: a dead process id means the node stopped. A living process whose file has not changed for two minutes is described as still on that step, with the age of the last update, rather than as stopped.
  Rationale: a slow proof stretch can take the better part of a minute per hundred blocks. Treating silence as a crash would repeat the original confusion. Two minutes is longer than those stretches and short enough that a real exit is still obvious, because the process id is gone.
  Date/Author: 2026-11-11

- Decision: the time estimate uses the last few progress samples, not the average since the step began. A step that suddenly takes at least twice as long per block is described as a slower stretch, and the estimate follows that newer pace. Estimates longer than 90 seconds are rounded to minutes.
  Rationale: one height band during the 2026-11-11 restart was much slower than the rest. An average from the start of the step hid that and produced a misleading short estimate.
  Date/Author: 2026-11-11

- Decision: the progress bar is a filled bar, track `#E1E6EE` and fill `#1BE7FF`. This is an intentional deviation from the BRAND.md rule that determinate loading uses a gray shimmer. A step with no fraction still uses that shimmer. Caught up is the words "Caught up" plus a full bar. Stopped or not running uses `#FF4E4E`. The window does not add a third accent color.
  Rationale: a shimmer cannot answer how much is done, which is the point of the card. Proof Green would be a third accent beside the existing Ionosphere buttons and Guard Rail errors.
  Date/Author: 2026-11-11

- Decision: the card is drawn only for `--gui`. No new HTTP route is added. The hosted page does not see the file or the card.
  Rationale: the page already has its own connection indicator for the companion. This card answers a question about the node process on the same computer.
  Date/Author: 2026-11-11

- Decision: the companion looks for the file in `~/.hegemon-node-v0.11/node-activity.json` unless `--hegemon-node-path` names another base directory. That default is the directory `start.sh` uses.
  Rationale: the window is started separately from the node and otherwise would not know where the node keeps its files.
  Date/Author: 2026-11-11

## Outcomes & Retrospective

The companion window now has a node card. A caught-up service says "Caught up" and "Ready. Height …, … peers." A service that is behind its target says "Catching up with the network", shows the block fraction, and estimates the time to that target. While the service port is closed, the card reads `node-activity.json` and names the startup step. A dead process id says the node stopped during that step. A living process with no update for two minutes says it is still on the step and how long the update has been quiet.

`cargo test -p hegemon-node --lib node_activity::tests -- --test-threads=8` passed the atomic-replace test. `PYTHONPATH=scripts python3 -m unittest scripts.test_local_swap_companion` passed 19 tests. A temporary window on this machine drew the card for a fake catch-up at block 14,850 of 15,818 with "Under a minute to the current target." The already-running companion process was left as it was; it will not show the card until that process is started again. The already-running node will not write the startup file until it is rebuilt and restarted. Connected, catching up, and caught up work against the node that is serving now.

What remains: the filled bar is the recorded brand deviation. A real startup replay was not run, because that requires rebuilding and restarting the live node.

## Context and Orientation

The node binary is `hegemon-node`. `start.sh` starts the v0.11 pre-mainnet node with its files in `~/.hegemon-node-v0.11` and its local service on `127.0.0.1:9944`. That service speaks JSON-RPC, which here means a small HTTP request whose body names a method. Two methods matter. `system_health` says whether the node is still syncing and how many peers it has. `hegemon_consensusStatus` adds the local block height and the height it is trying to reach (`sync_target_height`). A peer is another node it is talking to. Syncing means it is still copying blocks it does not have yet.

Opening the node does not bind that port immediately. `NativeNode::open` in `node/src/native/node_impl.rs` first opens the database, loads saved rows, rebuilds chain state, rechecks Poseidon2 V8 private proofs from the first block, saves any of that check that is not already stored, and checks indexes. Only after `open` returns does the process start listening. Poseidon2 V8 is the private-proof system used by the current chain. The recheck is the slow part.

The companion is `scripts/local_swap_companion.py`. It listens on `127.0.0.1:8788` for the hosted swap page. `--gui` opens a local window (`CompanionWindow`) that shows the pairing token and, in wallet mode, the passphrase field. `describe_companion_status` turns wallet-scan progress into one sentence. That sentence is the only status the window has today. The window runs on the Tk main thread. Tk is the Python window library. Work that talks to the network must not run on that thread, or the window freezes.

The base directory is the node's `--base-path`. The database file lives inside it. The new progress file lives beside that database, in the base directory, not inside the database.

## Plan of Work

Add `node/src/native/node_activity.rs` and declare `mod node_activity;` next to `mod node_impl;` in `node/src/native/mod.rs`. The module writes one JSON object to `{base-path}/node-activity.json`. The object has exactly these meanings: `phase` (one of the names below), `current` and `total` (integers, or null when the step has no fraction), `updated_at_ms` (Unix time in milliseconds), and `pid` (the node process id). The write goes to a temporary file in the same directory, is flushed, and is renamed over the destination. A failure is logged and ignored, so a full disk or a permissions problem cannot abort startup. A record with `current` greater than `total` is refused and does not replace a good file.

The phase names and the words the window uses are:

- `opening_database`: "Opening the chain database"
- `loading_rows`: "Loading saved blocks"
- `rebuilding_state`: "Rebuilding chain state"
- `rechecking_proofs`: "Rechecking private proofs"
- `saving_verified_state`: "Saving the checked chain"
- `checking_indexes`: "Checking chain indexes"
- `ready`: "Starting the network"

Call the writer from `node/src/native/node_impl.rs` at the same moments the existing startup logs fire. After the base directory is created, publish `opening_database`. After the database opens, publish `loading_rows`. In `replay_chain_state_with_mode`, only for startup reconstruction, publish `rebuilding_state` at the start and on each existing progress log (every 100 blocks and the last block). In `reconcile_poseidon2_v8_canonical_history`, publish `rechecking_proofs` when the proof replay starts and on each scratch progress log. Publish `saving_verified_state` only when at least one block still has to be saved, at the start of that loop and on each progress log. In `ensure_ciphertext_archive_index`, publish `checking_indexes` after the proof replay has been accepted and before the index plan is built. At the end of `NativeNode::open`, after the existing "startup verification and reload completed" log, publish `ready`. Counters are the block index and the step's total, which for this chain match the height numbers already printed in the log. Do not publish startup activity for a full non-startup replay.

In `scripts/local_swap_companion.py`, add a reader and a formatter that the window can call without opening a window. `read_node_activity` opens the file with `O_NOFOLLOW`, refuses anything that is not a regular file of at most 4096 bytes, and returns a dictionary only for a known phase and sane counters. Anything else returns nothing. `format_node_eta(remaining_seconds, slowed, network_target)` returns "Under a minute left", "About N minutes left", or the same sentences with "This stretch slowed down." in front. For a network catch-up that has not slowed, the sentence is "About N minutes to the current target." or "Under a minute to the current target." Ninety seconds and below stay "under a minute." `estimate_node_remaining(samples, total)` takes up to the last four `(time, current)` samples. It needs two samples whose counter increased. Three or more samples mark a slow stretch when the last interval is at most half the speed of the earlier samples in that window. The estimate then uses the last interval. Otherwise it uses the whole window.

`describe_node_activity` accepts one dictionary and returns `title`, `fraction`, `progress` (a fraction from 0 to 1, or null when the step has no fraction), `time_line`, `consequence`, and `tone` (`working`, `caught_up`, or `stopped`). A live service result wins over the file. If the service height is behind `sync_target_height`, or the service says it is syncing, the title is "Catching up with the network". If it is not syncing and has at least one peer, the title is "Caught up" and the consequence is "Ready. Height 16,427, 15 peers." with the real numbers and the singular "peer" when there is one. If it is up with zero peers and nothing left to catch, the title is "Waiting for peers". If the service is closed and the file's process is alive, use the phase sentence and, for a fractional step, "Block 14,200 of 15,818". The consequence is "The node is not accepting connections until this finishes." except `ready`, whose consequence is "The node is not accepting connections yet." If that file is quiet for at least two minutes, the time line is "Still on this step. Last update was N minutes ago." and no estimate is shown. If the process is dead, the tone is `stopped`, the title is "Not running", and the consequence names the step and the fraction. If there is no service and no readable file, the title is "Not running" and the consequence is "Nothing is listening on 127.0.0.1:9944." using the configured address.

`NodeActivityMonitor` polls once a second on a background thread. Each attempt uses a one-second timeout and calls only `system_health` and `hegemon_consensusStatus`. The Tk timer only reads the latest snapshot. The first snapshot says "Checking the local node" so the window does not flash "Not running" before the first answer.

`CompanionWindow` gains that monitor. It draws a `#F4F7FB` card at the top of the `#0E1C36` window, above the pairing token. The card has a dot, the title, the fraction in a monospace font, the bar, the time line, and the consequence. The window's minimum size becomes 480 by 560. `--hegemon-node-path` is optional. With `--gui` and without that flag, the file path is `~/.hegemon-node-v0.11/node-activity.json`.

## Concrete Steps

From `/home/william/Hegemon`:

    cargo test -p hegemon-node --lib node_activity::tests -- --test-threads=8

Expect the activity writer tests to pass.

    PYTHONPATH=scripts python3 -m unittest scripts.test_local_swap_companion

Expect the existing companion tests and the new node-activity tests to pass.

A rebuilt node is required before the next startup writes the file. The connected, catching-up, and caught-up lines work against a node that is already serving, without a rebuild. Building and restarting the live node is not part of the unit-test steps.

## Validation and Acceptance

The Rust test writes two records into a temporary directory, checks that the second record fully replaces the first, that no temporary file remains, and that a record with a current counter past its total does not replace a good file.

The Python tests, with no window and no live node, check every phase sentence, the minute rounding, a slowed stretch, a dead process, a quiet living process, a caught-up service response, and a file the reader refuses.

In the window, a caught-up node shows "Caught up" and "Ready. Height …, … peers." A node that is still starting shows the current step, a filled bar when a fraction exists, and a time estimate. A node that is not running shows "Not running" in the warning red.

## Idempotence and Recovery

The writer may run on every startup. Replacing the file is the normal action. A failed write leaves the previous file in place. Tests use temporary directories. The companion change is additive: without `--gui`, the terminal companion is unchanged, and no new request is served to the hosted page.

## Artifacts and Notes

The activity file looks like this while proofs are being rechecked:

    {"phase":"rechecking_proofs","current":14200,"total":15818,"updated_at_ms":1762880000000,"pid":1310773}

The companion ignores every field other than those five, and it ignores a phase name it does not know.

## Interfaces and Dependencies

In `node/src/native/node_activity.rs`:

    pub const NODE_ACTIVITY_FILE: &str = "node-activity.json";
    pub fn publish_node_activity(base_path: &Path, phase: &str, current: Option<u64>, total: Option<u64>)
    pub fn write_node_activity(base_path: &Path, phase: &str, current: Option<u64>, total: Option<u64>) -> std::io::Result<()>

`publish_node_activity` logs and swallows a write error. `write_node_activity` returns it. The node crate already depends on `serde_json` and `tracing`.

In `scripts/local_swap_companion.py`:

    def read_node_activity(path) -> dict | None
    def format_node_eta(remaining_seconds, slowed, network_target) -> str
    def estimate_node_remaining(samples, total) -> tuple
    def describe_node_activity(observation) -> dict
    class NodeActivityMonitor

`CompanionWindow.__init__` accepts `monitor`. `main` passes one when `--gui` is set.

## Revision note

2026-11-11: Created this plan so the companion window can show node startup and sync progress, including the period before the local service port opens. The filled progress bar is recorded as a brand deviation because a shimmer cannot show a fraction.

2026-11-11: Marked the work complete after the Rust writer test, the 19 Python companion tests, and a temporary window that drew a catch-up card. The live companion process and the live node were not restarted.
