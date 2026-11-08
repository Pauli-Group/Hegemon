#!/usr/bin/env python3
"""Actual disposable combined-upgrade acceptance; never production authority.

Use --help for explicit per-operation and total bounds. Outputs are create-only;
an interrupted or failed run keeps NON_PASS with completed gates and owned-PID
closure evidence. No old ASERT simulation environment hooks are used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback

# Explicit sibling loading supports the source-owned producer's python -I.
_io_path = Path(__file__).resolve().with_name("combined_io.py")
_io_spec = importlib.util.spec_from_file_location("combined_io", _io_path)
io = importlib.util.module_from_spec(_io_spec)
_prior_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    _io_spec.loader.exec_module(io)
finally:
    sys.dont_write_bytecode = _prior_bytecode

ROOT = Path("/private/tmp/hegemon-combined-upgrade-20261108")
CHAIN = "0xa6ddd1817d8c6987d584214ea5e393cbd0f96d138acc0aa216db4f7618be30f0"
GENESIS = "0x699b1ae50930ac9f0c37ba9ad3d88804f6300aef21ac16bca6c9196c52688e82"
GENESIS_EXTRINSICS_ROOT = "0x1cf0e5abefb3ee716674ec7a9916033fafcf7f7581ca04f9406daad604f03475"
MANIFEST_SHA = "fe959df819c6d2dfcb086eba4d509e5a973155bbc08a10ffee60fd3ec03c7b61"
COMBINED_RULES = "0xec304529f49e7ddc777e0ca78b189acec753d4fb18aafe15761e686ea3596b7f"
STATE_FIELDS = ("height", "best_hash", "state_root", "nullifier_root", "supply_digest")


def source_inventory(source):
    """Finite runtime source closure; explicitly not a hermetic build attestation."""
    roots = ("node", "wallet", "consensus", "consensus-light-client", "circuits",
        "crypto", "protocol", "protocol-versioning", "transaction-core", "network", ".cargo")
    paths = {source / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml") if (source / name).is_file()}
    for name in roots:
        if (source / name).is_dir():
            paths.update(p for p in (source / name).rglob("*") if p.is_file()
                and "target" not in p.relative_to(source).parts and p.suffix in (".rs", ".toml", ".json", ".lock"))
    records = [{"path": p.relative_to(source).as_posix(), "bytes": p.stat().st_size,
        "sha256": io.sha(p)} for p in sorted(paths)]
    digest = hashlib.sha256(json.dumps(records, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    return {"schema": "hegemon.combined-acceptance.finite-source-inventory.v1",
        "files": records, "entries_sha256": digest, "hermetic_build_claim": False}


class Runner:
    def __init__(self, args):
        self.a = args
        self.out = args.out.resolve()
        io.require(self.out.parent == args.workspace_root / "acceptance" and not self.out.exists(), "--out must be a NEW immediate child of workspace-root/acceptance")
        self.out.mkdir(mode=0o700)
        self.started = time.monotonic()
        self.nodes = {}
        self.owned = []
        self.command_number = 0
        self.wallet_passwords = {}
        self.observed = set()
        self.events = (self.out / "events.jsonl").open("x")
        self.headers = (self.out / "observed-headers.jsonl").open("x")
        self.state = {"schema": "hegemon.combined-upgrade.actual-process-acceptance.v1",
            "status": "NON_PASS", "completed": False, "production_authorized": False,
            "deployment_verified": False, "physical_asic_hardware_qualified": False,
            "physical_asic_qualified": False, "mainnet_authorized": False,
            "activation_authorized": False, "public_cutover_authorized": False,
            "started_unix": time.time(), "gates": {},
            "proofs": {}, "actions": {}, "negatives": {}, "owned_processes": [],
            "bounds": {k: v for k, v in vars(args).items() if isinstance(v, (int, float, bool, str))},
            "identity": {"chain_id": CHAIN, "genesis": GENESIS,
                "manifest_sha256": MANIFEST_SHA, "activation_height": 120,
                "first_batch_height": 179, "first_batch_maturity_inclusion_height": 299},
            "actual_invocation": [sys.executable, *sys.argv],
            "runtime_paths": {"workspace_root": str(args.workspace_root), "source": str(args.source),
                "fixture": str(args.fixture), "manifest": str(args.manifest), "output": str(self.out)},
            "rehearsal_features": {"hegemon-node": ["development-candidate", "combined-upgrade-rehearsal"],
                "private-spend": ["rpc-client", "private-spend-dev-artifacts"],
                "metadata_kind": "declared build features; runtime activation and CLI paths independently checked"},
            "limitations": ["Default-off Development candidate and source-pinned disposable chain only.",
                "All nodes share one machine and clock; this is local integration evidence.",
                "Single-thread software Bitcoin80 nonce solving does not qualify physical ASIC hardware.",
                "Same-owner HTLC claim/refund and cloned encrypted wallet journal exercise branch/race enforcement, not independent refund custody.",
                "Finite source inventory and supplied binary hashes are recorded; no claim of hermetic compiler/build-input closure.",
                "Serial proving freezes the tip; this does not measure sustained transaction throughput.",
                "No production activation, release qualification, public network, or real custody authority is inferred."]}
        self.save()

    def save(self):
        io.atomic_json(self.out / "receipt.json", self.state)

    def budget(self):
        io.require(time.monotonic() - self.started < self.a.total_timeout, "total acceptance time budget exhausted")
        io.require(shutil.disk_usage(self.out).free > self.a.disk_reserve_gib * 2**30, "disk reserve reached")

    def event(self, event_name, **fields):
        row = {"event": event_name, "elapsed_seconds": time.monotonic() - self.started,
            "observed_unix": time.time(), **fields}
        self.events.write(json.dumps(row, sort_keys=True) + "\n")
        self.events.flush()
        # Only public identifiers and metrics reach coordinator output.
        print(json.dumps(row, sort_keys=True), flush=True)

    def gate(self, name, evidence):
        self.state["gates"][name] = {"passed": True, "evidence": evidence}
        self.save()
        self.event("gate_pass", gate=name)

    def wait(self, predicate, label, timeout=None):
        deadline = min(time.monotonic() + (timeout or self.a.sync_timeout), self.started + self.a.total_timeout)
        last = None
        while time.monotonic() < deadline:
            self.budget()
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, RuntimeError) as exc:
                last = str(exc)
            for node in self.nodes.values():
                io.require(node["process"].poll() is None, "owned node exited during " + label)
            time.sleep(.2)
        raise TimeoutError(f"{label} timed out; last={last}")

    def start(self, name, index, restart=False, seeds=None):
        self.budget()
        base = self.out / name
        base.mkdir(mode=0o700, exist_ok=restart)
        rpc_port = self.a.rpc_base + index
        p2p_port = self.a.p2p_base + index
        seeds = ("" if name == "A" else f"127.0.0.1:{self.a.p2p_base}") if seeds is None else seeds
        env = io.clean_env()
        env.update(HEGEMON_SEEDS=seeds, HEGEMON_MINER_ADDRESS=self.address,
            HEGEMON_MINE="0", HEGEMON_MINE_THREADS="1", HEGEMON_MAX_PEERS="4",
            HEGEMON_BOOTSTRAP_AUTHORING="1")
        if name == "F":
            env["HEGEMON_PQ_IDENTITY_SEED_PATH"] = str(self.out / "F-fresh-peer-identity.seed")
        argv = [str(self.a.node_binary), "--network", "development", "--development-candidate",
            "--network-manifest", str(self.a.manifest), "--base-path", str(base),
            "--listen-addr", f"127.0.0.1:{p2p_port}", "--port", str(p2p_port),
            "--rpc-port", str(rpc_port), "--rpc-methods", "unsafe", "--name", "combined-acceptance-" + name]
        logfile = self.out / f"{name}-{time.time_ns()}.log"
        with logfile.open("xb") as stream:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                stderr=subprocess.STDOUT, env=env, start_new_session=True)
        record = {"name": name, "process": process, "rpc": rpc_port, "p2p": p2p_port,
            "log": logfile, "argv": argv, "env": {k: v for k, v in env.items() if k.startswith("HEGEMON_")}}
        self.owned.append(record)
        self.nodes[name] = record
        config = self.wait(lambda: io.rpc(rpc_port, "hegemon_nodeConfig", timeout=2), "startup " + name, self.a.start_timeout)
        io.require(config["networkProfile"] == "development" and config["chainId"] == CHAIN,
            "node did not select pinned disposable Development identity")
        io.require(config["networkManifest"] == self.manifest, "node manifest readback differs")
        io.require(config["bootstrapNodes"] == ([] if not seeds else seeds.split(",")), "unexpected seed topology")
        io.require(io.rpc(rpc_port, "chain_getBlockHash", [0]) == GENESIS, "genesis mismatch")
        parameters = io.rpc(rpc_port, "hegemon_privateSpendParameters")
        io.require(parameters["production_authorized"] is False, "Development evidence gained production flag")
        io.require(parameters["relation_digest"] == self.manifest["development_candidate"]["private_spend_source"]["relation_digest"], "node relation differs")
        if "proof_parameters" in self.state:
            io.require(parameters == self.state["proof_parameters"], "node proof parameters differ")
        self.state["proof_parameters"] = parameters
        self.state.setdefault("launches", []).append({"name": name, "pid": process.pid,
            "argv": argv, "environment": record["env"], "config": config,
            "log": logfile.name, "restart": restart})
        self.save()
        self.event("node_ready", node=name, pid=process.pid)
        return record

    def stop(self, name):
        node = self.nodes.pop(name)
        closure = io.stop_process(node["process"])
        closure.update(name=name, log=node["log"].name)
        self.state["owned_processes"].append(closure)
        self.save()
        io.require(closure["exit_code"] == 0 and not closure["forced"], "node did not close cleanly")

    def snapshot(self, name):
        port = self.nodes[name]["rpc"]
        clock_ms = time.time_ns() // 1_000_000
        status = io.rpc(port, "hegemon_consensusStatus")
        latest = io.rpc(port, "hegemon_latestBlock")
        io.require(latest["hash"] == status["best_hash"] and latest["height"] == status["height"], "head moved during paused snapshot")
        io.require(latest["timestamp"] <= clock_ms + 90_000, "head exceeds observed clock +90 seconds")
        header = io.rpc(port, "chain_getHeader", [status["best_hash"]])
        row = {"node": name, "observed_clock_ms": clock_ms, "status": status,
            "header": header, "latest": latest}
        key = (name, status["height"], status["best_hash"])
        if key not in self.observed:
            self.headers.write(json.dumps(row, sort_keys=True) + "\n")
            self.headers.flush()
            self.observed.add(key)
        return row

    def agree(self, names=None):
        names = names or list(self.nodes)
        def ready():
            rows = [self.snapshot(name) for name in names]
            signatures = {json.dumps({key: row["status"][key] for key in STATE_FIELDS}, sort_keys=True) for row in rows}
            if len(signatures) != 1:
                return False
            io.require(len({json.dumps(row["header"], sort_keys=True) for row in rows}) == 1, "header divergence at agreed state")
            return {"nodes": names, "status": {key: rows[0]["status"][key] for key in STATE_FIELDS},
                "header": rows[0]["header"], "observed_clock_ms": [row["observed_clock_ms"] for row in rows]}
        return self.wait(ready, "canonical state agreement")

    def mine_one(self, author="A", agreement_names=None):
        self.budget()
        port = self.nodes[author]["rpc"]
        job = self.wait(lambda: (lambda j: j if j.get("available") else False)(io.rpc(port, "hegemon_poolWork")), "exact pool job")
        height = job["height"]
        io.require(height <= self.a.max_height, "maximum chain height reached")
        parent = self.snapshot(author)
        io.require(job["parent_hash"] == parent["status"]["best_hash"], "job parent mismatch")
        io.require(job["version_rolling_mask"] == ("00000000" if height < 120 else "1fffffe0"), "version mask activation mismatch")
        version = 0x20000020 if height >= 120 and height % 2 == 0 else 0x20000000
        if height >= 120:
            if "asert_anchor" not in self.state:
                anchor_hash = io.rpc(port, "chain_getBlockHash", [119])
                anchor = io.rpc(port, "chain_getHeader", [anchor_hash])
                anchor_parent = io.rpc(port, "hegemon_blockTimestamps", [118, 118])[0]["timestamp_ms"]
                self.state["asert_anchor"] = {"height": 119, "hash": anchor_hash,
                    "parent_timestamp_ms": anchor_parent, "pow_bits": anchor["powBits"]}
            anchor = self.state["asert_anchor"]
            expected_bits = io.asert_bits(119, anchor["parent_timestamp_ms"], anchor["pow_bits"],
                parent["status"]["height"], parent["latest"]["timestamp"])
            io.require(int(job["nbits"], 16) == expected_bits, "job target differs from independent bigint fixed-anchor ASERT oracle")
        remaining = max(.1, self.a.total_timeout - (time.monotonic() - self.started))
        self.event("pool_work_issued", author=author, height=height, job=job, selected_mining_version=f"{version:08x}",
            parent=parent["status"], observed_clock_ms=parent["observed_clock_ms"])
        solution, measurement = io.solve_job(job, version, self.a.max_nonce_attempts,
            min(self.a.solve_timeout, remaining), self.a.pow_solver)
        if height in (119, 120):
            invalid = dict(solution, mining_version="20000020" if height == 119 else "20000021")
            try:
                io.rpc(port, "hegemon_submitPoolShare", [invalid])
            except RuntimeError as exc:
                io.require("version" in str(exc).lower(), "version-negative rejected for another reason")
                self.state["negatives"][f"mining_version_H{height}"] = {"rejected": True, "error": str(exc), "request": invalid}
            else:
                raise RuntimeError("invalid mining version accepted")
        accepted = io.rpc(port, "hegemon_submitPoolShare", [solution], timeout=self.a.import_timeout)
        io.require(accepted.get("accepted") is True and accepted["height"] == height, "exact solved pool job not accepted")
        agreement = self.agree(agreement_names)
        io.require(agreement["status"]["height"] == height and agreement["status"]["best_hash"] == measurement["work_hash"], "accepted work hash differs")
        io.require(agreement["header"]["miningVersion"] == version, "import lost exact mining version")
        if height >= 120:
            io.require(agreement["header"]["rulesHash"] == COMBINED_RULES, "combined rules absent after activation")
        self.event("block_accepted", author=author, height=height, job=job, solution=solution,
            solve=measurement, acceptance=accepted, state=agreement["status"])
        return agreement

    def mine_to(self, height, author="A", agreement_names=None):
        while self.snapshot(author)["status"]["height"] < height:
            self.mine_one(author, agreement_names)
        return self.agree(agreement_names)

    def native_cpu_author_catchup(self, gate_name, require_asert=False):
        before = self.agree()
        initial_height = before["status"]["height"]
        io.require(initial_height >= 120 if require_asert else initial_height == 0,
            "CPU author phase begins outside its intended schedule")
        port = self.nodes["A"]["rpc"]
        start = io.rpc(port, "hegemon_startMining", [{"threads": 1}])
        observations = []
        deadline = min(time.monotonic() + self.a.cpu_timeout, self.started + self.a.total_timeout)
        try:
            io.require(start.get("success") is True, "native CPU author did not start")
            while time.monotonic() < deadline:
                self.budget()
                now = time.time_ns() // 1_000_000
                head = io.rpc(port, "hegemon_latestBlock", timeout=2)
                follower = io.rpc(self.nodes["B"]["rpc"], "hegemon_latestBlock", timeout=2)
                io.require(head["timestamp"] <= now + 90000 and follower["timestamp"] <= now + 90000,
                    "live CPU author/import head exceeds observed clock +90s")
                row = {"observed_clock_ms": now, "author": head, "follower": follower}
                observations.append(row)
                self.event("native_cpu_head", **row)
                io.require(head["height"] < initial_height + 12, "native CPU author exceeded bounded height overshoot")
                if head["height"] >= initial_height + 3:
                    break
                time.sleep(.005)
            else:
                raise TimeoutError("native CPU author did not produce three bounded blocks")
        finally:
            stopped = io.rpc(port, "hegemon_stopMining", timeout=5)
        io.require(stopped.get("success") is True, "native CPU author did not stop")
        # Stop aborts author tasks; allow the owned blocking importer to settle.
        stable = None
        count = 0
        settle_deadline = time.monotonic() + 10
        while time.monotonic() < settle_deadline and count < 3:
            self.budget()
            current = io.rpc(port, "hegemon_consensusStatus")["best_hash"]
            count = count + 1 if current == stable else 0
            stable = current
            time.sleep(.2)
        io.require(count >= 3, "native CPU author did not reach stable paused tip")
        after = self.agree()
        end = after["status"]["height"]
        io.require(initial_height + 3 <= end < initial_height + 12, "native CPU authored height outside bounded phase")
        io.require(io.rpc(port, "hegemon_miningStatus")["is_mining"] is False, "CPU author remains active")
        rows = []
        for height in range(initial_height + 1, end + 1):
            self.budget()
            observed_ms = time.time_ns() // 1_000_000
            hashes = [io.rpc(node["rpc"], "chain_getBlockHash", [height]) for node in self.nodes.values()]
            io.require(len(set(hashes)) == 1, "CPU-authored block not independently imported")
            headers = [io.rpc(node["rpc"], "chain_getHeader", [hashes[0]]) for node in self.nodes.values()]
            timestamps = [io.rpc(node["rpc"], "hegemon_blockTimestamps", [height, height])[0]["timestamp_ms"] for node in self.nodes.values()]
            io.require(all(header == headers[0] for header in headers) and len(set(timestamps)) == 1
                and timestamps[0] <= observed_ms + 90000, "CPU import header/timestamp disagreement")
            if require_asert:
                anchor = self.state["asert_anchor"]
                parent_ms = io.rpc(port, "hegemon_blockTimestamps", [height - 1, height - 1])[0]["timestamp_ms"]
                expected = io.asert_bits(119, anchor["parent_timestamp_ms"], anchor["pow_bits"], height - 1, parent_ms)
                io.require(headers[0]["powBits"] == expected and headers[0]["rulesHash"] == COMBINED_RULES,
                    "native CPU-authored block differs from independent fixed-anchor ASERT/rules oracle")
            rows.append({"height": height, "hash": hashes[0], "header": headers[0],
                "timestamp_ms": timestamps[0], "observed_clock_ms": observed_ms,
                "independent_asert_checked": require_asert})
        evidence = {"before": before, "start_rpc": start, "stop_rpc": stopped,
            "threads_requested": 1, "start_height": initial_height, "end_height": end,
            "native_cpu_blocks": end - initial_height, "asert_active_phase": require_asert,
            "observations": observations,
            "independent_imported_headers": rows, "after": after,
            "manual_pool_solver_used_in_phase": False, "stable_tip_after_stop": True}
        filename = gate_name.replace("_", "-") + ".json"
        io.atomic_json(self.out / filename, evidence)
        evidence["transcript"] = {"path": filename, "sha256": io.sha(self.out / filename)}
        self.gate(gate_name, evidence)

    def encrypted_recovery(self, treasury_position):
        before = self.agree()
        backup = self.out / "encrypted-key-backup.wallet"
        io.private(backup, self.wallet.read_bytes())
        backup_hash = io.sha(backup)
        original_hash = io.sha(self.wallet)
        recovered = self.out / "recovered.wallet"
        password = os.urandom(32).hex().encode()
        argv = ["--wallet", str(recovered), "bootstrap-recover", "--source", str(backup)]
        self.command_number += 1
        log = self.out / f"cli-{self.command_number:03d}-encrypted-bootstrap-recover.log"
        text, metrics = io.wallet_cli(self.a.private_spend_binary, argv, [
            (b"Source encrypted wallet passphrase: ", self.password),
            (b"New encrypted wallet passphrase: ", password),
            (b"Confirm new encrypted wallet passphrase: ", password)], log,
            min(self.a.cli_timeout, self.a.total_timeout - (time.monotonic() - self.started)))
        public = None
        for line in text.splitlines():
            if "{" in line:
                try:
                    value = json.loads(line[line.index("{"):])
                except ValueError:
                    continue
                if isinstance(value, dict) and value.get("recovered_same_keys") is True:
                    public = value
        io.require(public is not None and public["address"] == self.address
            and public["requires_network_rescan"] is True, "encrypted key recovery public identity differs")
        io.require(io.sha(backup) == backup_hash and io.sha(self.wallet) == original_hash,
            "recovery changed original encrypted source")
        io.require(io.sha(recovered) != backup_hash, "recovery did not create separately encrypted destination")
        self.wallet_passwords[str(recovered)] = password
        self.recovered_wallet = recovered
        self.state.setdefault("cli_commands", []).append({"name": "encrypted-bootstrap-recover",
            "command": argv, "metrics": metrics, "log": log.name, "expected_success": True})
        notes = self.notes(recovered)
        io.require(("ordinary", treasury_position, 6000000000) in notes,
            "fresh recovered-wallet rescan did not discover matured exact treasury batch")
        attempts, _ = self.cli(["attempts"], "recovered-empty-attempt-journal", recovered, timeout=self.a.cli_timeout)
        io.require(not re.search(r"^[0-9a-f]{64} ", attempts, re.M), "key-only recovery unexpectedly restored proof attempts")
        io.require(self.agree()["status"] == before["status"], "chain changed during encrypted recovery")
        self.state["encrypted_recovery"] = {"method": "current private-spend bootstrap-recover",
            "source_backup": {"path": backup.name, "sha256": backup_hash},
            "source_preserved": True, "new_encrypted_wallet": {"path": recovered.name, "sha256": io.sha(recovered)},
            "recovered_same_keys": True, "new_password_distinct": password != self.password,
            "fresh_rescan_mature_treasury_position": treasury_position,
            "fresh_rescan_mature_treasury_atoms": 6000000000,
            "proof_journal_restored": False, "keys_accounts_and_issued_addresses_only": True,
            "cli_log": {"path": log.name, "sha256": io.sha(log)}, "metrics": metrics,
            "before": before, "after": self.agree(), "deadline_note_discovery_checked": False}
        self.save()

    def retain_candidate_restart(self, candidate):
        before = self.agree()
        active = [(name, self.nodes[name]["rpc"] - self.a.rpc_base) for name in list(self.nodes)]
        for name, _ in active:
            self.stop(name)
        for name, index in active:
            self.start(name, index, restart=True)
        io.require(self.agree()["status"] == before["status"], "retained proof restart moved frozen parent")
        again = self.out / (candidate["name"] + "-after-restart.action")
        text, _ = self.cli(["attempts"], candidate["name"] + "-retained-attempt", candidate["wallet"], timeout=self.a.cli_timeout)
        io.require(candidate["attempt"] in text, "retained proof attempt vanished at restart")
        self.cli(["export", candidate["attempt"], again], candidate["name"] + "-reexport-after-restart", candidate["wallet"], timeout=self.a.cli_timeout)
        io.require(again.read_bytes() == candidate["raw"], "retained proof/action bytes changed across restart")
        self.gate("retained_smzl_candidate_across_restart", {"attempt_id": candidate["attempt"],
            "reference": before["status"], "original_action_sha256": candidate["row"]["action_sha256"],
            "reexported_action": again.name, "reexported_action_sha256": io.sha(again),
            "same_exact_action_carrier_proof": True})

    def prepare_fork_prefix(self, candidate):
        before = self.agree()
        io.require(before["status"]["height"] == candidate["row"]["reference_height"], "fork prefix must be exact retained action reference")
        for name in list(self.nodes):
            self.stop(name)
        source = self.out / "A/native-chain.sled"
        destination = self.out / "F/native-chain.sled"
        io.require(source.is_dir() and not source.is_symlink() and not destination.exists(), "fork database copy must be owned, cold and create-only")
        records = []
        for path in sorted(source.rglob("*")):
            io.require(not path.is_symlink(), "fork database symlink rejected")
            if path.is_file():
                records.append({"path": path.relative_to(source).as_posix(), "bytes": path.stat().st_size, "sha256": io.sha(path)})
        size = sum(row["bytes"] for row in records)
        io.require(records and size <= 2**30 and shutil.disk_usage(self.out).free > self.a.disk_reserve_gib * 2**30 + size,
            "fork prefix copy exceeds bounded storage/reserve")
        destination.parent.mkdir(mode=0o700)
        shutil.copytree(source, destination)
        copied = [{"path": path.relative_to(destination).as_posix(), "bytes": path.stat().st_size, "sha256": io.sha(path)}
            for path in sorted(destination.rglob("*")) if path.is_file()]
        io.require(copied == records, "cold owned prefix database copy changed bytes")
        evidence = {"reference": before, "source": "A/native-chain.sled", "destination": "F/native-chain.sled",
            "files": records, "logical_bytes": size, "all_nodes_stopped_for_copy": True,
            "fresh_fork_peer_identity_path": "F-fresh-peer-identity.seed"}
        io.atomic_json(self.out / "owned-cold-fork-prefix.json", evidence)
        self.state["reorg_prefix"] = {"path": "owned-cold-fork-prefix.json",
            "sha256": io.sha(self.out / "owned-cold-fork-prefix.json"), "reference": before["status"]}
        # C remains cold; A/B plus isolated F never exceed three live nodes.
        self.start("A", 0, restart=True)
        self.start("B", 1, restart=True)
        io.require(self.agree()["status"] == before["status"], "main prefix restart changed state")
        self.save()

    def reorg_and_resubmit(self, candidate, old_inclusion):
        original = self.agree()
        reference = candidate["row"]["reference_height"]
        io.require(original["status"]["height"] == reference + 1, "reorg must begin immediately after original inclusion")
        old_work = int(original["header"]["cumulativeWork"], 16)
        self.start("F", 2, restart=True, seeds="")
        io.require(self.snapshot("F")["status"]["height"] == reference, "isolated fork did not open common prefix")
        fork = self.mine_to(reference + 3, author="F", agreement_names=["F"])
        while int(fork["header"]["cumulativeWork"], 16) <= old_work:
            io.require(fork["status"]["height"] < reference + 6, "winning fork exceeds bounded proof reference budget")
            fork = self.mine_one("F", ["F"])
        fork_height = fork["status"]["height"]
        fork_hash = fork["status"]["best_hash"]
        io.require(io.rpc(self.nodes["F"]["rpc"], "chain_getBlockHash", [reference]) == candidate["row"]["reference_hash"], "fork changed retained action's canonical reference")
        for height in range(reference + 1, fork_height + 1):
            bh = io.rpc(self.nodes["F"]["rpc"], "chain_getBlockHash", [height])
            io.require(candidate["raw"] not in io.chunks(self.nodes["F"]["rpc"], bh)[0], "winning fork unexpectedly contains orphan target")
        self.stop("F")
        self.start("F", 2, restart=True, seeds=f"127.0.0.1:{self.a.p2p_base}")
        self.wait(lambda: all(io.rpc(node["rpc"], "chain_getBlockHash", [fork_height]) == fork_hash for node in self.nodes.values()),
            "actual higher-work branch adoption")
        adopted = self.agree()
        io.require(adopted["status"]["height"] == fork_height, "higher-work fork adoption moved unexpected height")
        io.require(io.rpc(self.nodes["A"]["rpc"], "chain_getBlockHash", [old_inclusion["height"]]) != old_inclusion["block_hash"], "target inclusion was not detached")
        text, _ = self.cli(["status"], "claim-wallet-canonical-reorg-rollback", candidate["wallet"], timeout=self.a.cli_timeout)
        line = next((line for line in text.splitlines() if candidate["attempt"] in line), "")
        io.require("mined=None" in line, "wallet did not roll back orphaned mined receipt")
        reexport = self.out / (candidate["name"] + "-after-reorg.action")
        self.cli(["export", candidate["attempt"], reexport], "claim-reexport-after-reorg", candidate["wallet"], timeout=self.a.cli_timeout)
        io.require(reexport.read_bytes() == candidate["raw"] and io.sha(candidate["path"]) == candidate["row"]["action_sha256"], "orphaned proof/action bytes changed")
        tx = "0x" + candidate["raw"][:48].hex()
        io.require(all(tx not in io.rpc(node["rpc"], "author_pendingExtrinsics") for node in self.nodes.values()), "orphan target unexpectedly restaged; cannot claim fresh resubmission")
        reinclusion = self.include(candidate)
        io.require(reinclusion["height"] <= reference + 13 and reinclusion["action_sha256"] == old_inclusion["action_sha256"], "unchanged resubmission escaped reference/byte binding")
        attempts, _ = self.cli(["attempts"], "claim-reminded-journal", candidate["wallet"], timeout=self.a.cli_timeout)
        line = next((line for line in attempts.splitlines() if candidate["attempt"] in line), "")
        io.require("mined=Some" in line, "unchanged reinclusion mined receipt absent")
        evidence = {"candidate": candidate["name"], "attempt_id": candidate["attempt"],
            "action_sha256": candidate["row"]["action_sha256"], "carrier_sha256": candidate["row"]["carrier_sha256"],
            "proof_sha256": candidate["row"]["proof_sha256"], "canonical_reference_height": reference,
            "canonical_reference_hash": candidate["row"]["reference_hash"], "cold_prefix": self.state["reorg_prefix"],
            "old_inclusion": old_inclusion, "old_tip": original, "higher_work_fork": fork,
            "fork_work_exceeds_old": int(fork["header"]["cumulativeWork"], 16) > old_work,
            "actual_independent_adoption": adopted, "original_inclusion_detached": True,
            "wallet_mined_receipt_rolled_back": True, "reexport_after_reorg": {"path": reexport.name, "sha256": io.sha(reexport)},
            "identical_action_resubmitted": True, "reinclusion": reinclusion,
            "all_reference_and_nullifier_checks_unchanged": True}
        io.atomic_json(self.out / "unchanged-action-reorg-resubmission.json", evidence)
        evidence["transcript"] = {"path": "unchanged-action-reorg-resubmission.json", "sha256": io.sha(self.out / "unchanged-action-reorg-resubmission.json")}
        self.gate("unchanged_action_reorg_resubmission", evidence)
        self.stop("F")
        self.start("C", 2, restart=True)
        self.agree()
        return reinclusion

    def cli(self, command, name, wallet=None, extra=(), check=True, timeout=None):
        self.budget()
        self.command_number += 1
        wallet = wallet or self.wallet
        argv = ["--wallet", str(wallet), "--manifest", str(self.a.manifest), "--genesis", GENESIS,
            "--rpc", f"http://127.0.0.1:{self.nodes['A']['rpc']}", "--development-local-candidate", *map(str, command)]
        log = self.out / f"cli-{self.command_number:03d}-{name}.log"
        operation_timeout = min(timeout or self.a.proof_timeout,
            max(.1, self.a.total_timeout - (time.monotonic() - self.started)))
        text, metrics = io.wallet_cli(self.a.private_spend_binary, argv,
            [(io.PASS_PROMPT, self.wallet_passwords.get(str(wallet), self.password)), *extra], log, operation_timeout, check)
        self.state.setdefault("cli_commands", []).append({"name": name, "command": argv,
            "metrics": metrics, "log": log.name, "expected_success": check})
        self.save()
        return text, metrics

    def notes(self, wallet=None):
        text, _ = self.cli(["status"], "status", wallet, timeout=self.a.cli_timeout)
        return [(kind, int(position), int(value)) for kind, position, value in
            re.findall(r"(ordinary|htlc|policy|accumulator|treasury-value) position=(\d+) value=(\d+)", text)]

    def ordinary_position(self, excluded=(), minimum=1001000, wallet=None):
        return next(position for kind, position, value in self.notes(wallet)
            if kind == "ordinary" and position not in excluded and value >= minimum)

    def candidate(self, name, command, wallet=None, preimage=None):
        before = self.agree()
        extra = [] if preimage is None else [(io.PREIMAGE_PROMPT, preimage.hex().encode())]
        text, metrics = self.cli(command, name, wallet, extra)
        ids = re.findall(r"candidate ([0-9a-f]{64})", text)
        io.require(len(ids) == 1, "fresh candidate identifier missing")
        attempt = ids[0]
        path = self.out / (name + ".action")
        self.cli(["export", attempt, path], name + "-export", wallet, timeout=self.a.cli_timeout)
        raw = path.read_bytes()
        carrier = io.public_args(raw)
        io.require(carrier[72:104].hex() == CHAIN[2:] and carrier[24:72].hex() == self.state["proof_parameters"]["relation_digest"][:96], "proof source/network binding differs")
        reference = int.from_bytes(carrier[136:144], "little")
        io.require(reference == before["status"]["height"] and "0x" + carrier[104:136].hex() == before["status"]["best_hash"], "proof reference not frozen canonical parent")
        io.require(self.agree()["status"] == before["status"], "tip moved during proof generation")
        proof = carrier[io.FIXED_BYTES:]
        io.private(self.out / (name + ".carrier.hgps"), carrier)
        io.private(self.out / (name + ".proof.smzl"), proof)
        row = {"attempt_id": attempt, "action": path.name, "action_sha256": io.sha(path),
            "carrier_sha256": hashlib.sha256(carrier).hexdigest(), "carrier_sha512": hashlib.sha512(carrier).hexdigest(),
            "proof_sha256": hashlib.sha256(proof).hexdigest(), "proof_sha512": hashlib.sha512(proof).hexdigest(),
            "action_bytes": len(raw), "carrier_bytes": len(carrier), "proof_bytes": len(proof),
            "reference_height": reference, "reference_hash": before["status"]["best_hash"],
            "nullifier_0": carrier[208:264].hex(), "nullifier_1": carrier[264:320].hex(),
            "wallet_local_verify_completed": True, "command_metrics": metrics,
            "fixed_relation_input_slots": 2}
        self.state["proofs"][name] = row
        self.save()
        self.event("proof_prepared", name=name, proof_bytes=len(proof), elapsed_seconds=metrics["elapsed_seconds"])
        return {"name": name, "attempt": attempt, "path": path, "raw": raw,
            "carrier": carrier, "wallet": wallet or self.wallet, "row": row}

    def include(self, candidate):
        name = candidate["name"]
        self.cli(["submit", candidate["attempt"]], name + "-submit", candidate["wallet"], timeout=self.a.import_timeout)
        tx = "0x" + candidate["raw"][:48].hex()
        self.wait(lambda: all(io.pending(node["rpc"], tx) == candidate["raw"] for node in self.nodes.values()), "unchanged pending relay")
        agreement = self.mine_one()
        height = agreement["status"]["height"]
        bodies = [io.chunks(node["rpc"], agreement["status"]["best_hash"]) for node in self.nodes.values()]
        io.require(all(body == bodies[0] for body in bodies), "canonical proof body divergence")
        io.require(bodies[0][0].count(candidate["raw"]) == 1, "exact candidate missing or duplicated")
        reference = candidate["row"]["reference_height"]
        io.require(height == reference + 1 if "lock" in name else reference + 1 <= height <= reference + 13, "actual proof reference window violated")
        row = {"height": height, "block_hash": agreement["status"]["best_hash"],
            "action_sha256": hashlib.sha256(candidate["raw"]).hexdigest(),
            "canonical_body_sha256": hashlib.sha256(bodies[0][2]).hexdigest(),
            "action_body_hash": bodies[0][1]["action_body_hash"], "exact_pending_and_mined_bytes": True,
            "node_agreement": agreement}
        self.state["actions"][name] = row
        self.save()
        self.notes(candidate["wallet"])
        return row

    def rejected_cli(self, name, command, preimage=None, wallet=None):
        before = self.agree()["status"]
        attempts, _ = self.cli(["attempts"], name + "-attempts-before", wallet, timeout=self.a.cli_timeout)
        extra = [] if preimage is None else [(io.PREIMAGE_PROMPT, preimage.hex().encode())]
        text, metrics = self.cli(command, name, wallet, extra=extra, check=False, timeout=self.a.cli_timeout)
        io.require(metrics["exit_code"] != 0 and "private spend relation rejected material" in text,
            "negative did not fail through relation rejection")
        after, _ = self.cli(["attempts"], name + "-attempts-after", wallet, timeout=self.a.cli_timeout)
        journal_rows = lambda text: sorted(line for line in text.splitlines() if re.match(r"^[0-9a-f]{64} .*mined=", line))
        io.require(journal_rows(attempts) == journal_rows(after) and self.agree()["status"] == before, "rejected command changed attempts/tip")
        self.state["negatives"][name] = {"rejected": True, "before_heavy_proving": True,
            "unchanged_attempts": True, "unchanged_tip": True, "metrics": metrics}
        self.save()
        self.event("relation_negative_rejected", name=name, wallet=(wallet or self.wallet).name,
            canonical_parent=before, diagnostic="private spend relation rejected material", metrics=metrics)

    def rejected_carrier(self, candidate, name, expected):
        port = self.nodes["A"]["rpc"]
        before = self.agree()["status"]
        io.require(before["height"] - candidate["row"]["reference_height"] <= 12, "competing proof reference expired")
        reply = io.rpc(port, "hegemon_submitAction", [io.request(candidate["carrier"])], timeout=self.a.import_timeout)
        io.require(reply.get("success") is False and re.search(expected, reply.get("error", ""), re.I), "competing proof rejection had wrong cause: " + str(reply))
        tx = "0x" + candidate["raw"][:48].hex()
        io.require(all(tx not in io.rpc(node["rpc"], "author_pendingExtrinsics") for node in self.nodes.values()), "rejected competitor entered mempool")
        io.require(self.agree()["status"] == before, "negative submission changed chain")
        self.state["negatives"][name] = {"rejected": True, "reply": reply,
            "unchanged_carrier_sha256": hashlib.sha256(candidate["carrier"]).hexdigest(),
            "reference_still_eligible": True, "absent_from_all_pending_pools": True,
            "canonical_parent": before}
        self.save()
        self.event("unchanged_carrier_negative_rejected", name=name, canonical_parent=before,
            carrier_sha256=hashlib.sha256(candidate["carrier"]).hexdigest(), reply=reply)

    def rewards(self):
        rows = []
        for height in range(1, 180):
            self.budget()
            block_hash = io.rpc(self.nodes["A"]["rpc"], "chain_getBlockHash", [height])
            records = [io.rpc(node["rpc"], "hegemon_blockReward", [block_hash]) for node in self.nodes.values()]
            io.require(all(record == records[0] for record in records), "reward readback differs between nodes")
            row = records[0]
            treasury = int(row["treasury_amount_atoms"])
            io.require(int(row["miner_amount_atoms"]) == 400000000 and int(row["fees_atoms"]) == 0,
                "unexpected early miner/fee value")
            io.require(treasury == (100000000 if height < 120 else 6000000000 if height == 179 else 0), "treasury cadence/value mismatch")
            io.require(row["treasury_cadence_active"] == (height >= 120), "treasury policy activation mismatch")
            if height >= 120:
                io.require(int(row["treasury_entitlement_atoms"]) == 100000000, "per-height entitlement mismatch")
                io.require(int(row["treasury_pending_after_atoms"]) == (0 if height == 179 else (height - 119) * 100000000), "pending entitlement mismatch")
            rows.append(row)
        io.atomic_json(self.out / "reward-cadence-H1-H179.json", rows)
        # Reward outer commitments are intentionally empty. The V8 note tree
        # appends the validated payload's primary then optional funding note.
        # Count those exact physical notes and bind the public 56-byte digest.
        position = 0
        treasury_position = None
        for height in range(1, 180):
            self.budget()
            block_hash = io.rpc(self.nodes["A"]["rpc"], "chain_getBlockHash", [height])
            actions, _, _ = io.chunks(self.nodes["A"]["rpc"], block_hash)
            for raw in actions:
                io.require(int.from_bytes(raw[54:56], "little") == 12, "pre-proof history contains nonreward action")
                payload, fee = io.action_payload(raw)
                io.require(fee == 0 and len(payload) in (2350, 4699), "reward payload framing differs")
                count = 2 if len(payload) == 4699 else 1
                io.require(payload[2349] == (1 if count == 2 else 0), "reward optional-note framing differs")
                if height == 179:
                    io.require(count == 2, "batch reward must contain miner and treasury notes")
                    treasury_position = position + 1
                    commitment = payload[2350 + 144:2350 + 200]
                    io.require(rows[-1]["treasury"]["commitment_hex"] == "0x" + commitment.hex(), "public treasury digest differs from exact reward payload")
                    self.state["treasury_batch"] = {"height": 179, "position": treasury_position,
                        "amount_atoms": 6000000000, "relation_commitment_56": "0x" + commitment.hex(),
                        "reward_readback": rows[-1], "global_leaf_order_checked": True}
                position += count
        io.require(treasury_position is not None, "batch treasury output absent")
        self.gate("cadence_and_public_treasury_batch", self.state["treasury_batch"])
        return treasury_position

    def genesis_action_body(self, audit_header=None):
        """Read the exact empty H0 body under its pinned genesis root convention."""
        self.budget()
        expected = self.state["gates"]["initial_native_cpu_author_catchup"]["evidence"]["before"]["header"]
        io.require(expected["number"] == "0x0" and expected["parentHash"] == "0x" + "00" * 32
            and expected["extrinsicsRoot"] == GENESIS_EXTRINSICS_ROOT and expected["chainId"] == CHAIN,
            "initial genesis header does not match pinned empty-body convention")
        io.require(audit_header is None or audit_header == expected,
            "genesis audit header differs from initial CPU observation")
        io.require(bool(self.nodes), "genesis body requires independently observed nodes")
        for node in self.nodes.values():
            block_hash = io.rpc(node["rpc"], "chain_getBlockHash", [0])
            io.require(block_hash == GENESIS, "genesis body identity differs")
            header = io.rpc(node["rpc"], "chain_getHeader", [block_hash])
            io.require(header == expected, "current genesis header differs from initial CPU observation")
            response = io.rpc(node["rpc"], "chain_getBlock", [block_hash])
            io.require(isinstance(response, dict) and isinstance(response.get("block"), dict),
                "genesis body response malformed")
            block = response["block"]
            io.require(block.get("header") == header and block.get("extrinsics") == [],
                "genesis body/header is not the independently observed exact empty body")
        # SCALE Vec<Vec<u8>> has one zero compact-count byte for an empty body.
        return b"\x00"

    def canonical_audit(self):
        agreement = self.agree()
        end = agreement["status"]["height"]
        timestamp_maps = []
        for node in self.nodes.values():
            self.budget()
            entries = []
            for start in range(0, end + 1, 128):
                self.budget()
                entries += io.rpc(node["rpc"], "hegemon_blockTimestamps", [start, min(end, start + 127)])
            timestamp_maps.append(entries)
        io.require(all(rows == timestamp_maps[0] for rows in timestamp_maps), "canonical timestamps differ")
        timestamp = {row["height"]: row["timestamp_ms"] for row in timestamp_maps[0]}
        previous = None
        rows = []
        observed = time.time_ns() // 1_000_000
        for height in range(end + 1):
            self.budget()
            hashes = [io.rpc(node["rpc"], "chain_getBlockHash", [height]) for node in self.nodes.values()]
            io.require(len(set(hashes)) == 1, "canonical hash divergence")
            headers = [io.rpc(node["rpc"], "chain_getHeader", [hashes[0]]) for node in self.nodes.values()]
            io.require(all(header == headers[0] for header in headers), "historical header divergence")
            if height == 0:
                body_bytes = self.genesis_action_body(headers[0])
                action_hashes = []
            else:
                bodies = [io.chunks(node["rpc"], hashes[0]) for node in self.nodes.values()]
                io.require(all(body == bodies[0] for body in bodies), "historical canonical body divergence")
                body_bytes = bodies[0][2]
                action_hashes = [hashlib.sha256(action).hexdigest() for action in bodies[0][0]]
            io.require(type(timestamp[height]) is int and timestamp[height] <= observed + 90000, "historical timestamp exceeds observed clock +90s")
            if previous is not None:
                io.require(headers[0]["parentHash"] == previous and timestamp[height] > timestamp[height - 1], "noncontiguous header/timestamp history")
            if height >= 120:
                expected = io.asert_bits(119, timestamp[118], rows[119]["header"]["powBits"],
                    height - 1, timestamp[height - 1])
                io.require(headers[0]["powBits"] == expected, "historical target differs from independent bigint ASERT oracle")
            rows.append({"height": height, "hash": hashes[0], "timestamp_ms": timestamp[height],
                "observed_clock_ms": observed, "header": headers[0],
                "canonical_body_sha256": hashlib.sha256(body_bytes).hexdigest(),
                "action_sha256": action_hashes})
            previous = hashes[0]
        path = self.out / "canonical-audit.json"
        io.atomic_json(path, {"nodes": list(self.nodes), "rows": rows})
        self.gate("final_exact_canonical_history_and_timestamps", {"height": end,
            "audit_sha256": io.sha(path), "agreement": agreement})
        if end >= 120:
            self.gate("independent_bigint_fixed_anchor_asert", {"checked_heights": [120, end],
                "anchor": self.state["asert_anchor"], "half_life_ms": 3600000,
                "spacing_ms": 60000, "audit_sha256": io.sha(path)})

    def run(self):
        for port in [self.a.rpc_base + i for i in range(3)] + [self.a.p2p_base + i for i in range(3)]:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
        io.require((self.a.fixture / "FRESH_DISPOSABLE_ONLY").is_file(), "fixture lacks fresh disposable marker")
        io.require(io.sha(self.a.manifest) == MANIFEST_SHA, "pinned public manifest changed")
        self.manifest = json.loads(self.a.manifest.read_text())
        self.address = self.manifest["funding_address"]
        io.require((self.a.fixture / "public-address.txt").read_text().strip() == self.address, "fixture does not own pinned funding recipient")
        self.password = (self.a.fixture / "passphrase").read_bytes().strip()
        io.require(len(self.password) >= 20, "fresh fixture passphrase malformed")
        self.wallet = self.out / "disposable.wallet"
        io.private(self.wallet, (self.a.fixture / "disposable.wallet").read_bytes())
        self.state["binaries"] = {"hegemon-node": {"path": str(self.a.node_binary), "sha256": io.sha(self.a.node_binary)},
            "private-spend": {"path": str(self.a.private_spend_binary), "sha256": io.sha(self.a.private_spend_binary)}}
        if self.a.pow_solver is not None:
            self.state["binaries"]["exact80-software-solver"] = {"path": str(self.a.pow_solver), "sha256": io.sha(self.a.pow_solver)}
        inventory = source_inventory(self.a.source)
        io.atomic_json(self.out / "source-inventory.json", inventory)
        self.state["source"] = {"path": str(self.a.source), "inventory_sha256": io.sha(self.out / "source-inventory.json"), "entries_sha256": inventory["entries_sha256"]}
        checker_path = self.a.source / "scripts/check_combined_upgrade_candidate.py"
        io.require(checker_path.is_file(), "source-owned candidate inventory checker missing")
        spec = importlib.util.spec_from_file_location("combined_candidate_inventory", checker_path)
        checker = importlib.util.module_from_spec(spec)
        previous_bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(checker)
        finally:
            sys.dont_write_bytecode = previous_bytecode
        complete_inventory = checker.inventory(self.a.source)
        io.atomic_json(self.out / "complete-candidate-inventory.json", complete_inventory)
        self.state["source"]["complete_candidate_inventory"] = {"path": "complete-candidate-inventory.json",
            "sha256": io.sha(self.out / "complete-candidate-inventory.json"),
            "canonical_records_sha256": hashlib.sha256(checker.canonical(complete_inventory)).hexdigest(),
            "producer": "scripts/check_combined_upgrade_candidate.py:inventory/canonical",
            "producer_sha256": io.sha(checker_path)}
        self.state["harness"] = {p.name: io.sha(p) for p in (Path(__file__), Path(io.__file__), Path(__file__).with_name("exact80_solver.rs"))}
        self.save()
        self.start("A", 0)
        self.start("B", 1)
        self.wait(lambda: io.rpc(self.nodes["A"]["rpc"], "system_health")["peers"] >= 1, "A/B secure peers")
        self.agree()
        self.native_cpu_author_catchup("initial_native_cpu_author_catchup")
        self.genesis_action_body()
        self.mine_to(119)
        self.stop("B")
        self.start("B", 1, restart=True)
        self.gate("restart_before_activation", self.agree())
        self.mine_to(120)
        self.gate("actual_activation_import", self.agree())
        self.native_cpu_author_catchup("live_cpu_author_catchup", require_asert=True)
        self.mine_to(179)
        treasury_position = self.rewards()
        self.stop("B")
        self.start("B", 1, restart=True)
        self.start("C", 2)
        self.gate("payout_restart_and_fresh_sync_across_activation", self.agree())
        if self.a.runtime_only:
            self.canonical_audit()
            self.state["status"] = "RUNTIME_ONLY_PASS_PROOFS_NOT_RUN"
            self.state["uncompleted"] = ["treasury maturity/spend", "current SMZL ordinary", "HTLC lock/claim/refund", "negative race", "proof restart/fresh verification"]
            return
        self.mine_to(297)
        self.notes()
        io.require(not any(kind == "ordinary" and position == treasury_position for kind, position, _ in self.notes()), "treasury matured one block early")
        # The balance readback explicitly identifies maturity in inclusion H299.
        batch_hash = io.rpc(self.nodes["A"]["rpc"], "chain_getBlockHash", [179])
        observation = io.rpc(self.nodes["A"]["rpc"], "hegemon_blockReward", [batch_hash])
        io.require(observation["maturity_height"] == 299 and observation["height_eligible_for_next_block"] is False, "early batch maturity flags wrong")
        self.gate("batch_immature_at_parent_H297", observation)
        self.mine_to(298)
        rows = self.notes()
        io.require(("ordinary", treasury_position, 6000000000) in rows, "mature treasury batch not owned/available")
        self.encrypted_recovery(treasury_position)
        ordinary = self.candidate("treasury-ordinary", ["ordinary", "--inputs", treasury_position,
            "--recipient", self.address, "--amount", "3000000000", "--fee", "1000"])
        self.retain_candidate_restart(ordinary)
        treasury_action = self.include(ordinary)
        io.require(treasury_action["height"] == 299, "first batch not spent at first maturity inclusion H299")
        io.require(any(kind == "ordinary" and value == 3000000000 for kind, _, value in self.notes()), "ordinary treasury payout missing")
        self.gate("mature_batch_actual_current_smzl_ordinary", treasury_action)

        source = self.ordinary_position(minimum=1001000)
        preimage = os.urandom(32)
        timeout = self.snapshot("A")["status"]["height"] + 16
        lock = self.candidate("claim-lock", ["lock", "--inputs", source, "--claim", self.address,
            "--refund", self.address, "--hashlock", hashlib.sha256(preimage).hexdigest(),
            "--timeout", timeout, "--amount", "1000000", "--fee", "1000"])
        self.include(lock)
        locked = next(position for kind, position, _ in self.notes() if kind == "htlc")
        fee_a = self.ordinary_position()
        fee_b = self.ordinary_position(excluded=(fee_a,))
        self.rejected_cli("wrong-preimage", ["claim", "--locked", locked, "--fee-input", fee_a,
            "--recipient", self.address, "--fee", "1000"], preimage=bytes(32))
        self.rejected_cli("early-refund", ["refund", "--locked", locked, "--fee-input", fee_b,
            "--recipient", self.address, "--fee", "1000"], wallet=self.recovered_wallet)
        recovered_notes = self.notes(self.recovered_wallet)
        io.require(("htlc", locked, 1000000) in recovered_notes, "fresh recovered-wallet rescan did not discover exact HTLC deadline note")
        self.state["encrypted_recovery"].update(deadline_note_discovery_checked=True,
            recovered_htlc_position=locked, recovered_htlc_atoms=1000000,
            recovered_deadline_negative="early-refund", original_lock=self.state["actions"]["claim-lock"],
            retained_original_proof_after_restart=self.state["gates"]["retained_smzl_candidate_across_restart"]["evidence"])
        self.gate("encrypted_wallet_recovery", self.state["encrypted_recovery"])
        self.mine_to(timeout)
        self.notes()
        competitor_wallet = self.out / "competitor.wallet"
        io.private(competitor_wallet, self.wallet.read_bytes())
        claim = self.candidate("claim", ["claim", "--locked", locked, "--fee-input", fee_a,
            "--recipient", self.address, "--fee", "1000"], preimage=preimage)
        competing = self.candidate("competing-refund", ["refund", "--locked", locked,
            "--fee-input", fee_b, "--recipient", self.address, "--fee", "1000"], wallet=competitor_wallet)
        io.require(claim["carrier"][208:264] == competing["carrier"][208:264] and claim["carrier"][264:320] != competing["carrier"][264:320], "competing selectors do not share locked nullifier with distinct fee nullifiers")
        self.prepare_fork_prefix(claim)
        # Submit once, observe real pending propagation, then test pending conflict.
        self.cli(["submit", claim["attempt"]], "claim-first-submit", timeout=self.a.import_timeout)
        tx = "0x" + claim["raw"][:48].hex()
        self.wait(lambda: all(io.pending(node["rpc"], tx) == claim["raw"] for node in self.nodes.values()), "claim exact pending relay")
        self.rejected_carrier(competing, "pending-competing-refund", r"(?:nullifier.*already.*(?:pending|spent)|duplicate.*nullifier)")
        # include() must not resubmit an already acknowledged action.
        claim_row = self.include_pending(claim)
        self.rejected_carrier(competing, "spent-competing-refund", r"nullifier.*already.*spent")
        self.gate("actual_claim_and_competing_negative", claim_row)
        claim_row = self.reorg_and_resubmit(claim, claim_row)
        self.rejected_carrier(competing, "spent-competing-refund", r"nullifier.*already.*spent")
        self.gate("actual_claim_and_competing_negative", claim_row)

        before_locks = {position for kind, position, _ in self.notes() if kind == "htlc"}
        source = self.ordinary_position()
        timeout = self.snapshot("A")["status"]["height"] + 16
        lock2 = self.candidate("refund-lock", ["lock", "--inputs", source, "--claim", self.address,
            "--refund", self.address, "--hashlock", "11" * 32, "--timeout", timeout,
            "--amount", "1000000", "--fee", "1000"])
        self.include(lock2)
        locked2 = next(position for kind, position, _ in self.notes() if kind == "htlc" and position not in before_locks)
        self.mine_to(timeout)
        refund = self.candidate("refund", ["refund", "--locked", locked2, "--fee-input",
            self.ordinary_position(), "--recipient", self.address, "--fee", "1000"])
        self.gate("actual_refund", self.include(refund))
        final = self.agree()
        for name in list(self.nodes):
            self.stop(name)
        self.start("A", 0, restart=True)
        self.start("B", 1, restart=True)
        # C is deliberately replaced with a new distinct directory and keys.
        self.start("D", 2)
        io.require(self.agree()["status"] == final["status"], "restart/fresh proof state changed")
        self.gate("final_restart_and_independent_fresh_proof_sync", self.agree())
        recovered_notes = self.notes(self.recovered_wallet)
        io.require(any(kind == "ordinary" and value == 1000000 for kind, _, value in recovered_notes),
            "fresh recovered-wallet rescan after proof restart did not discover canonical HTLC payout")
        self.state["encrypted_recovery"]["post_restart_canonical_payout_discovered"] = True
        self.state["encrypted_recovery"]["post_restart_state"] = self.agree()
        self.gate("encrypted_wallet_recovery", self.state["encrypted_recovery"])
        self.canonical_audit()
        current_inventory = source_inventory(self.a.source)
        io.require(current_inventory == inventory, "source changed during actual acceptance")
        io.require(checker.inventory(self.a.source) == complete_inventory, "complete frozen candidate source changed during actual acceptance")
        for item in self.state["binaries"].values():
            io.require(io.sha(item["path"]) == item["sha256"], "binary changed during actual acceptance")
        self.state["status"] = "PASS_LOCAL_COMBINED_CANDIDATE"
        self.state["completed"] = True

    def include_pending(self, candidate):
        """Same exact-byte inclusion check without replaying an acknowledged submit."""
        agreement = self.mine_one()
        io.require(candidate["row"]["reference_height"] + 1 <= agreement["status"]["height"] <= candidate["row"]["reference_height"] + 13,
            "pending winner actual reference window violated")
        bodies = [io.chunks(node["rpc"], agreement["status"]["best_hash"]) for node in self.nodes.values()]
        io.require(all(body == bodies[0] for body in bodies) and bodies[0][0].count(candidate["raw"]) == 1, "pending winner exact body mismatch")
        row = {"height": agreement["status"]["height"], "block_hash": agreement["status"]["best_hash"],
            "action_sha256": hashlib.sha256(candidate["raw"]).hexdigest(),
            "canonical_body_sha256": hashlib.sha256(bodies[0][2]).hexdigest(),
            "exact_pending_and_mined_bytes": True, "node_agreement": agreement}
        self.state["actions"][candidate["name"]] = row
        self.save()
        self.notes(candidate["wallet"])
        return row

    def close(self):
        for name in list(self.nodes):
            try:
                self.stop(name)
            except BaseException as exc:
                self.state.setdefault("cleanup_errors", []).append(str(exc))
        self.state["all_owned_reaped"] = all(row["process"].poll() is not None for row in self.owned)
        self.state["all_owned_exit0"] = all(row["process"].returncode == 0 for row in self.owned)
        ports = [self.a.rpc_base + i for i in range(3)]
        closed = []
        for port in ports:
            with socket.socket() as sock:
                sock.settimeout(.3)
                closed.append(sock.connect_ex(("127.0.0.1", port)) != 0)
        self.state["rpc_closed"] = all(closed)
        if not (self.state["all_owned_reaped"] and self.state["all_owned_exit0"] and self.state["rpc_closed"]):
            self.state["completed"] = False
            self.state["status"] = "NON_PASS"
        self.state["elapsed_seconds"] = time.monotonic() - self.started
        self.state["finished_unix"] = time.time()
        self.save()
        self.events.close()
        self.headers.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-binary", type=Path, required=True)
    parser.add_argument("--private-spend-binary", type=Path, required=True)
    parser.add_argument("--pow-solver", type=Path, help="optional precompiled single-thread exact80_solver.rs helper; every result independently rehashed in Python")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, default=ROOT, help="private workspace whose acceptance/ directory owns create-only outputs")
    script = Path(__file__).resolve()
    default_source = script.parents[2] if script.parent.name == "combined_upgrade_acceptance" and script.parent.parent.name == "scripts" else ROOT / "source"
    parser.add_argument("--source", type=Path, default=default_source)
    parser.add_argument("--manifest", type=Path, help="defaults to source/node/testdata/combined-upgrade-rehearsal/manifest.json")
    parser.add_argument("--fixture", type=Path, default=ROOT / "rehearsal-fixture")
    parser.add_argument("--runtime-only", action="store_true", help="stop at H179 with explicit incomplete proof gates")
    parser.add_argument("--rpc-base", type=int, default=24600)
    parser.add_argument("--p2p-base", type=int, default=24610)
    parser.add_argument("--start-timeout", type=int, default=120)
    parser.add_argument("--sync-timeout", type=int, default=180)
    parser.add_argument("--import-timeout", type=int, default=120)
    parser.add_argument("--proof-timeout", type=int, default=1800)
    parser.add_argument("--cli-timeout", type=int, default=180)
    parser.add_argument("--cpu-timeout", type=int, default=180)
    parser.add_argument("--solve-timeout", type=int, default=120)
    parser.add_argument("--max-nonce-attempts", type=int, default=64000000)
    parser.add_argument("--total-timeout", type=int, default=14400)
    parser.add_argument("--max-height", type=int, default=400)
    parser.add_argument("--disk-reserve-gib", type=int, default=5)
    args = parser.parse_args()
    if args.manifest is None:
        args.manifest = args.source / "node/testdata/combined-upgrade-rehearsal/manifest.json"
    for name in ("node_binary", "private_spend_binary", "source", "manifest", "fixture", "workspace_root"):
        setattr(args, name, getattr(args, name).resolve())
    for name in ("node_binary", "private_spend_binary", "manifest"):
        io.require(getattr(args, name).is_file(), name + " missing")
    if args.pow_solver is not None:
        args.pow_solver = args.pow_solver.resolve()
        io.require(args.pow_solver.is_file(), "pow solver missing")
    io.require(args.max_nonce_attempts <= 1 << 32, "nonce attempts exceed u32 nonce space")
    io.require(1 <= args.rpc_base < 65533 and 1 <= args.p2p_base < 65533, "port bounds")
    io.require(all(getattr(args, name) > 0 for name in ("start_timeout", "sync_timeout", "import_timeout", "proof_timeout", "cli_timeout", "cpu_timeout", "solve_timeout", "max_nonce_attempts", "total_timeout", "max_height")), "all runtime bounds must be positive")
    return args


def main():
    os.umask(0o077)
    args = parse_args()
    runner = Runner(args)
    def interrupted(signum, frame):
        raise RuntimeError("acceptance interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        runner.run()
    except BaseException as exc:
        runner.state["failure"] = str(exc)
        runner.state["traceback"] = traceback.format_exc()
        runner.state["status"] = "NON_PASS"
        runner.state["completed"] = False
    finally:
        runner.close()
    print(json.dumps({"status": runner.state["status"], "completed": runner.state["completed"],
        "receipt": str(runner.out / "receipt.json")}), flush=True)
    return 0 if runner.state["status"] in ("PASS_LOCAL_COMBINED_CANDIDATE", "RUNTIME_ONLY_PASS_PROOFS_NOT_RUN") else 1


if __name__ == "__main__":
    sys.exit(main())
