# Qualify an isolated Linux source with Darwin relay, restart and fresh nodes

This is a living ExecPlan maintained according to `.agent/PLANS.md`. This development test does not deploy a node, change the active testnet service, install production authority, or establish universal compiler and operating-system refinement.

## Purpose / Big Picture

The retained SMZA socket test can now use a real Linux source node reached through private SSH forwards while its relay, restarted relay and fresh node run on Darwin. Both retained proofs traverse the existing actual HTTP submission, proof rejection, authenticated peer transport, authoring, import, durable restart, fresh synchronization and exact-byte assertions. The source has no seeds, and every listener is on numeric loopback. The separate receipt records the actual Linux node PID and process group, its executable hash, the Darwin executable hash, the exact same manifest bytes, full live inventory checks and independent remote clean-stop observations. SSH transport exit is recorded separately and cannot substitute for the node exit.

## Progress

- [x] (2026-10-02 08:00Z) Read repository instructions, plan rules and independent-proof architecture and method sections.
- [x] (2026-10-02 08:25Z) Implement the SOURCE-only remote broker, restricted launch grammar, remote process ownership, private SSH forwards and separately named Rust test and receipt.
- [x] (2026-10-02 08:35Z) Run nine bounded broker tests: Darwin passed eight and skipped the Linux-specific descendant case; real Linux passed all nine in 2.563 seconds. Run Rust formatting/parser and whitespace checks.
- [ ] Integrate this frozen source with the final verifier change; rebuild Linux and Darwin test executables without concurrent heavy local lanes.
- [ ] Generate the authoritative same-source manifest/proof pair, transfer its unchanged bytes, run the canonical local qualification and separately named cross-host qualification, and retain their receipts.

## Surprises & Discoveries

The original child startup deliberately rejects a fabricated local transport PID: it compares the startup PID to its actual process ID. The remote broker must construct that frame from the actual Linux child and verify its process group before allowing any service startup. The broker launches only that child with a fresh process group; the SSH process remains a separate local process.

Local sandbox restrictions deny even loopback binds. The broker tests passed after automatic approval of their narrowly scoped local loopback operation. Actual Linux fake-process tests also passed all nine cases, including an unexpectedly exited leader whose descendant retained a listener and both control pipes. These tests do not qualify a proof or actual node.

The exact SMZA selection and optional outer process-group guard live in `node/src/native/poseidon2_v8_verifier.rs`, outside the carrier test include. Two scoped selector additions are necessary for the separately named test to retain the same profile and optional containment semantics.

## Decision Log

Use a small Python broker plus an explicit optional remote-source state on `RetainedCarrierProcess`. This keeps every ordinary child and qualification episode on its existing execution path. The separate cross-host selector runs two fixed-proof episodes; it does not repeat expensive wallet proof generation. The canonical local selector still runs both fixed proofs and its existing fresh wallet proof episode. Date/author: 2026-10-02, Codex.

Send launch configuration as exact JSON over SSH stdin. Only a restricted absolute `/tmp/` workspace path appears in the remote shell command; the host is the explicitly authorized alias `hegemon-dev`. No arbitrary shell command, remote seed, role or listener can be supplied. Date/author: 2026-10-02, Codex.

Record a broker SHA512 independently of the proof inventory. Compare the Linux broker bytes to the local broker bytes before accepting readiness. The child verifies its full source inventory before service startup and after lifecycle completion; the broker separately rechecks executable and exact manifest hashes after reaping. Date/author: 2026-10-02, Codex.

Use a Linux PID file descriptor when available to signal the same node even if numeric PIDs could be recycled. Fallback signaling checks the still-owned subprocess and its exact process group. Enable Linux subreaper ownership, which makes orphaned test descendants direct children of this broker, and verify their actual parent, session and start time through `/proc` before signaling and reaping them. Never blindly signal a numeric process group after its leader has been reaped. Failure-only cleanup does not produce a successful exit receipt. Date/author: 2026-10-02, Codex.

## Outcomes & Retrospective

The source implementation and bounded broker checks are complete. Real node evidence still requires final-source builds, authoritative fresh pair generation and the actual separate cross-host test. No successful proof lifecycle or deployment is claimed from source review or fake-process tests.

## Context and Orientation

`node/src/native/poseidon2_v8_carrier_tests.rs` is test-only code included by the native verifier tests when retained-test support is enabled. `RetainedCarrierProcess` exchanges bounded, session-bound JSON control frames with a real child test binary. The ignored child starts the actual native service behind a development-only binding; ordinary builds still deny the production capability. A process group is an operating-system set of related processes that the supervisor can own and clean up. A SHA512 hash pins exact file bytes. An SSH forward listens on local loopback and carries traffic to a remote loopback listener; the network itself continues to run its authenticated post-quantum peer handshake.

`scripts/rp05_crosshost_supervisor.py` launches only the Linux SOURCE child. Its launch and exit records have control IDs `u64::MAX-1` and `u64::MAX-2`; ordinary child frames are forwarded unchanged. A terminate frame signals the actual remote node, waits and reaps it, verifies the owned group no longer exists, checks both remote listeners are closed and emits a remote receipt only if all observations pass. Closing the transport input early triggers failure-only cleanup.

## Plan of Work

Integrate the carrier tests, two selector changes, broker script and its unit tests into one final source tree. Generate the source inventory and fresh pair only after that source is frozen. The remote checkout must live under a dedicated `/tmp/` child and must be the compile-time workspace of its Linux executable. Copy the exact manifest and artifact files to matching repository-relative paths. The full inventory checker must validate both workspaces, and the executable SHA512 values will differ across operating systems by design. The broker hash must match exactly.

## Concrete Steps

From the repository root, run the bounded broker tests and parse/format checks:

    python3 -B -m unittest discover -s scripts/tests -p test_rp05_crosshost_supervisor.py -v
    rustfmt --edition 2021 --check node/src/native/poseidon2_v8_carrier_tests.rs
    git diff --check

Expected broker result:

    Ran 9 tests in 2.563s
    OK

That transcript is from real Linux fake-process testing. Darwin runs eight of these tests and explicitly skips the Linux-specific adopted-descendant case.

Use the already approved isolated Linux build root `/tmp/hegemon-rp05-crosshost-ce6d5d75`, with its checkout in `repo`, build output in `target` and operational scratch in `runtime`. The Linux build uses at most two jobs. Do not stop or change the host's active service or touch its state, configuration, ports 30333 or 9944. Rebuild the frozen source with the same retained-test support as the Darwin test binary.

Set `HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH` to the final canonical repository-relative pair manifest and `HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512` to its exact 128-character lowercase SHA512. Set `HEGEMON_TEST_CROSSHOST_WORKSPACE` to the remote `/tmp/.../repo`, `HEGEMON_TEST_CROSSHOST_EXECUTABLE` to the absolute Linux test executable and `HEGEMON_TEST_CROSSHOST_EXECUTABLE_SHA512` to that executable's SHA512. Then invoke the Darwin test executable with the exact selector:

    <Darwin-test-executable> --ignored --exact native::poseidon2_v8_verifier::tests::retained_smza_crosshost_actual_socket_process_carriers --nocapture --test-threads=1

The manifest must be generated by the existing qualification workflow after the final source is frozen; no historical pair is authoritative for changed source. `<Darwin-test-executable>` denotes that workflow's freshly built library test binary, not the ordinary node executable.

## Validation and Acceptance

The Python tests check exact hash rejection, launch grammar, oversized and partial frames, child early exit, disconnect cleanup, ignored-SIGTERM timeout cleanup, prompt malformed/oversized child-output failure, exited-leader adopted-descendant cleanup and successful independent remote node PID/group/reap/listener observations. They use only fake processes and fresh temporary directories.

The actual cross-host test must pass both fixed-proof episodes. Each records Linux source identity separately from the local SSH PID, source/relay peer authentication, exact unchanged proof/action bytes through actual HTTP and peer import, durable relay restart, fresh-node synchronization and clean stops. The output file is `crosshost-socket-carrier-receipt.json`, schema `hegemon.retained-smza.crosshost-socket-carriers-v1`. Its `pass` field must be true. The canonical local output remains `actual-socket-carrier-receipt.json` and must be retained independently. Source review and Rust parsing do not establish that these real episodes passed.

## Idempotence and Recovery

Every remote source uses a fresh temporary base directory with an empty seed list and a new private port. Every local episode uses a dedicated temporary directory. Failures retain diagnostics and databases. The broker cleans up only the exact child group it created; it never references the active service. Disconnect and forced cleanup are failure evidence only. Remove retained test directories only under separately authorized exact-target cleanup; this implementation does not delete them.

## Artifacts and Notes

The source owns `node/src/native/poseidon2_v8_carrier_tests.rs`, new `scripts/rp05_crosshost_supervisor.py`, new `scripts/tests/test_rp05_crosshost_supervisor.py`, this plan and two small selector hunks in `node/src/native/poseidon2_v8_verifier.rs`. Integration must preserve unrelated runtime optimization changes.

## Interfaces and Dependencies

The broker uses Python standard-library process, signal, socket, select, threading, hashing, JSON and ctypes modules. Linux `prctl` enables subreaper ownership, `/proc` binds adopted-child identity and PID file descriptors bind signals where available. Rust uses its existing serde_json, std process/channel, SHA512 and socket support. It invokes the existing `ssh` binary and authorized host alias. No Cargo metadata or production runtime dependency changes are required.

Revision note, 2026-10-02: Initial implementation and bounded validation are complete; actual qualification remains explicitly pending because only final-source executable and proof-pair evidence can close it.
