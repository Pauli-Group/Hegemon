#!/usr/bin/env python3
"""Run the packaged solo payout rotation rehearsal on disposable loopback nodes.

Provide the candidate archive, its platform’s published v0.11.5 node, and
the release-mode hegemon-node library test executable built with solo-payout-rehearsal.
The output directory must be fresh. It contains disposable encrypted wallets,
private operator logs, and a machine-readable compatibility receipt.
"""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tarfile
import time
import zipfile

# CI runs this script with isolated Python, which omits the script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from combined_upgrade_acceptance import combined_io as io
from package_v011_release import native as verify_native_header

if os.name == "nt":
    import v0116_rotation_windows_io as windows_io

# SHA-256 of each raw hegemon-node release asset published for v0.11.5.
PREVIOUS_SHA = {
    "linux-x86_64": "5230ea81befe3913b123c4a48e6328a2211ff160f0bcf45a1a1c5bbc2d60ae0b",
    "macos-arm64": "d27e6be9eeb057de7f31bb5799d6f4584e80a9ec5ed7a950f283c6e512b40c23",
    "macos-x86_64": "0904bb7ad5bbec89bac0da495b7c76a2a7f7fb5c7aec9a1f2b823ef26ced8315",
    "windows-x86_64": "87dc56d22b1266a2706c3cd2fab3c6ca48278199d0aa0a5678f07db64d7ff81d",
}
MANIFEST_SHA = "386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754"
CHAIN = "0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49"
GENESIS = "0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3"
FIXTURE_TEST = "native::treasury_lifecycle_tests::solo_payout_rotation::issue_public_profile_rotation_fixture"
MANIFEST_PATH = "config/testnet/0.11/network-manifest.json"


def host_platform():
    os_label = {"darwin": "macos", "linux": "linux", "win32": "windows"}.get(sys.platform)
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{os_label}-{arch}"


def executable_name(name, selected):
    return name + ".exe" if selected == "windows-x86_64" else name


def unpack(archive, out, expected_sha, selected):
    io.require(io.sha(archive) == expected_sha, "candidate archive SHA-256 mismatch")
    prefix = f"hegemon-v0.11.6-local-candidate-{selected}"
    binaries = ["bin/" + executable_name(name, selected) for name in ["hegemon-node", "private-spend", "wallet"]]
    names = [*binaries, MANIFEST_PATH, "bundle.json"]
    with ExitStack() as stack:
        if selected == "windows-x86_64":
            bundle = stack.enter_context(zipfile.ZipFile(archive))
            members = bundle.namelist()

            def read(name):
                member = bundle.getinfo(f"{prefix}/{name}")
                io.require(not member.is_dir() and member.file_size <= 160 * 1024 * 1024, "invalid package member")
                return bundle.read(member)
        else:
            bundle = stack.enter_context(tarfile.open(archive, "r:gz"))
            members = bundle.getnames()

            def read(name):
                member = bundle.getmember(f"{prefix}/{name}")
                io.require(member.isfile() and member.size <= 160 * 1024 * 1024, "invalid package member")
                return bundle.extractfile(member).read()

        io.require(len(set(members)) == len(members), "duplicate archive member")
        sums = {}
        for line in read("SHA256SUMS").decode("ascii").splitlines():
            digest, name = line.split("  ", 1)
            io.require(name not in sums, "duplicate package checksum")
            sums[name] = digest
        for name in names:
            data = read(name)
            io.require(hashlib.sha256(data).hexdigest() == sums[name], f"package checksum mismatch: {name}")
            if name in binaries:
                verify_native_header(data, selected)
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            io.private(path, data)
            if name in binaries:
                path.chmod(0o700)
    io.require(sums[MANIFEST_PATH] == MANIFEST_SHA, "package network manifest differs from release")
    record = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    io.require(record["platform"] == selected and record["software_version"] == "0.11.6"
               and record["build_channel"] == "local-candidate", "unexpected candidate bundle identity")
    io.require(all(record["binaries"][name]["sha256"] == sums[name] for name in binaries),
               "candidate binary inventory mismatch")
    return {name: sums[name] for name in names}, record["binary_build_source_head"]


def ports():
    with ExitStack() as stack:
        socks = [stack.enter_context(socket.socket()) for _ in range(4)]
        for sock in socks:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in socks]


def wait_for(check, what, processes, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        for proc in processes:
            io.require(proc.poll() is None, f"node exited during {what}; inspect its log")
        try:
            value = check()
        except (ConnectionError, TimeoutError) as exc:
            last = str(exc)
        else:
            if value:
                return value
        time.sleep(.15)
    raise TimeoutError(f"{what} timed out ({last})")


@contextmanager
def pair(out, manifest, candidate, previous, donor_base, payout_env, previous_address):
    candidate_rpc, previous_rpc, donor_p2p, peer_p2p = ports()
    processes = []
    try:
        for name, exe, base, rpc, p2p, seed, mining in [
            ("candidate", candidate, donor_base, candidate_rpc, donor_p2p, None, payout_env),
            ("previous", previous, out / "previous-base", previous_rpc, peer_p2p, donor_p2p,
             {"HEGEMON_MINER_ADDRESS": previous_address}),
        ]:
            env = io.clean_env()
            env.update(HEGEMON_SEEDS=f"127.0.0.1:{seed}" if seed else "",
                       HEGEMON_MINE="0", HEGEMON_MAX_PEERS="1", HEGEMON_BOOTSTRAP_AUTHORING="1",
                       HEGEMON_PQ_IDENTITY_SEED_PATH=str(out / (name + "-p2p.seed")), **mining)
            cmd = [str(exe), "--network", "pre-mainnet", "--network-manifest", str(manifest),
                   "--base-path", str(base), "--listen-addr", f"127.0.0.1:{p2p}", "--port", str(p2p),
                   "--rpc-port", str(rpc), "--rpc-methods", "unsafe", "--name", f"rotation-{name}"]
            with (out / (name + ".log")).open("xb") as log:
                if os.name == "nt":
                    proc = windows_io.start_node(cmd, env, log)
                else:
                    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                            stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(proc)
            wait_for(lambda: io.rpc(rpc, "hegemon_nodeConfig"), name + " start", processes)
            io.require(io.rpc(rpc, "chain_getBlockHash", [0]) == GENESIS
                       and io.rpc(rpc, "hegemon_nodeConfig")["chainId"] == CHAIN, "wrong chain identity")
        def connected():
            for rpc in (candidate_rpc, previous_rpc):
                peers = io.rpc(rpc, "system_peers")
                if not peers:
                    return False
                io.require(len(peers) == 1 and peers[0]["endpoint"].startswith("127.0.0.1:"),
                           "unexpected peer on loopback rehearsal")
            return True
        wait_for(connected, "loopback peering", processes)
        yield candidate_rpc, previous_rpc, processes
    finally:
        with ExitStack() as cleanup:
            for proc in processes:
                cleanup.callback(windows_io.stop_node if os.name == "nt" else io.stop_process, proc)


def equal_tip(rpcs, height, processes):
    def agreed():
        heads = [io.rpc(rpc, "hegemon_latestBlock") for rpc in rpcs]
        io.require(all(head["height"] <= height for head in heads), "unexpected higher block")
        return heads[0]["hash"] if all(head == heads[0] for head in heads) and heads[0]["height"] == height else None
    return wait_for(agreed, f"independent import of H{height}", processes, 420)


def mine_one(rpc, expected_height, processes):
    def available():
        job = io.rpc(rpc, "hegemon_poolWork")
        return job if job.get("available") else None
    job = wait_for(available, "local block template", processes)
    io.require(job["height"] == expected_height, "unexpected template height")
    version = int.from_bytes(bytes.fromhex(job["header80"])[:4], "little")
    share, _ = io.solve_job(job, version, 0x100000000, 120)
    accepted = io.rpc(rpc, "hegemon_submitPoolShare", [share], timeout=180)
    io.require(accepted["accepted"] is True and accepted["height"] == expected_height, "block rejected")


def address_keys(encoded):
    # The package's schedule exporter emits canonical Bech32m V8 addresses.
    hrp, data = encoded.rsplit("1", 1)
    io.require(hrp == "shca", "unexpected address prefix")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bits = "".join(f"{alphabet.index(c):05b}" for c in data[:-6])
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    io.require(raw[:7] == bytes.fromhex("05070000000000"), "unexpected payout address profile")
    return {"recipient_key_hex": "0x" + raw[7:39].hex(), "authorization_key_hex": "0x" + raw[39:71].hex(),
            "authorization_extension_hex": "0x" + raw[71:95].hex()}


def compare_rewards(rpcs, schedule, eligible):
    result = []
    for height, address in enumerate(schedule, 1):
        hashes = [io.rpc(rpc, "chain_getBlockHash", [height]) for rpc in rpcs]
        io.require(hashes[0] == hashes[1] and hashes[0], "payout block hash differs")
        rewards = [io.rpc(rpc, "hegemon_blockReward", [hashes[0]]) for rpc in rpcs]
        row = rewards[0]
        io.require(row == rewards[1] and row["canonical"] and row["reward_present"], "reward readback differs")
        io.require(row["height"] == height and row["maturity_height"] == height + 120
                   and row["height_eligible_for_next_block"] == eligible, "incorrect reward maturity")
        io.require(all(row["miner"][k] == v for k, v in address_keys(address).items()),
                   "reward does not pay scheduled spending authority")
        io.require(int(row["miner_amount_atoms"]) == 400000000, "unexpected miner reward")
        result.append({"height": height, "block_hash": hashes[0], "miner": row["miner"],
                       "maturity_height": row["maturity_height"]})
    io.require(len({r["miner"]["authorization_key_hex"] for r in result}) == 2
               and len({r["miner"]["recipient_key_hex"] for r in result}) == 2, "payout keys reused")
    return result


def json_line(output):
    for line in output.splitlines():
        if "{" in line:
            try:
                return json.loads(line[line.index("{"):])
            except ValueError:
                pass
    raise RuntimeError("missing wallet JSON result")


def run(a):
    os.umask(0o077)
    out = a.out.resolve()
    out.mkdir(mode=0o700)
    candidate_dir = out / "package"
    archive_sha = a.package_sha256.lower()
    selected = a.platform or host_platform()
    io.require(selected in PREVIOUS_SHA and selected == host_platform(), "test needs a matching host OS and architecture")
    artifacts, build_source = unpack(a.package, candidate_dir, archive_sha, selected)
    candidate = candidate_dir / "bin" / executable_name("hegemon-node", selected)
    previous = a.previous_node.resolve()
    manifest = candidate_dir / MANIFEST_PATH
    io.require(io.sha(previous) == PREVIOUS_SHA[selected], f"previous node differs from published {selected} binary")
    for path in [previous, a.fixture_binary]:
        with path.open("rb") as executable:
            verify_native_header(executable.read(1024 * 1024 + 6), selected)
    for binary, version in [(candidate, "0.11.6"), (previous, "0.11.5")]:
        io.require(subprocess.check_output([binary, "--version"], text=True).strip() == f"hegemon-node {version}",
                   "node version mismatch")
    report = {"candidate_archive_sha256": archive_sha, "candidate_members": artifacts,
              "published_previous_node_sha256": PREVIOUS_SHA[selected], "platform": selected,
              "candidate_build_source": build_source, "os_version": platform.platform(),
              "execution_machine": platform.machine(),
              "chain_id": CHAIN, "genesis_hash": GENESIS, "cli": {}, "passed": False}
    if sys.platform == "darwin":
        translated = subprocess.run(["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"],
                                    text=True, capture_output=True)
        report["rosetta_translated"] = translated.stdout.strip() == "1" if translated.returncode == 0 else None
    def save():
        io.atomic_json(out / "receipt.json", report)
    def cli(name, args, prompts, binary="private-spend", timeout=180):
        wallet_cli = windows_io.wallet_cli if os.name == "nt" else io.wallet_cli
        path = candidate_dir / "bin" / executable_name(binary, selected)
        text, metrics = wallet_cli(path, args, prompts, out / (name + ".log"), timeout)
        report["cli"][name] = metrics
        save()
        return text
    source, backup, restored = (out / name for name in ("source.wallet", "pre-rotation.backup", "restored.wallet"))
    passphrase = os.urandom(24).hex().encode()
    replacement = os.urandom(24).hex().encode()
    prompts = [(io.PASS_PROMPT, passphrase), (b"Confirm encrypted wallet passphrase: ", passphrase)]
    address = json_line(cli("bootstrap", ["--wallet", source, "bootstrap-new"], prompts))["address"]
    io.private(backup, source.read_bytes())
    report["backup_sha256"] = io.sha(backup)
    io.require(report["backup_sha256"] == io.sha(source), "encrypted wallet snapshot differs")
    other = json_line(cli("unrelated-miner", ["--wallet", out / "other.wallet", "bootstrap-new"], prompts))["address"]
    io.require(other != address, "disposable fixed miner must be unrelated")
    schedule_path = out / "schedule.json"
    cli("export-schedule", ["solo-payout-schedule", "--store", source, "--first-height", "1", "--count", "2",
                            "--chain-id", CHAIN[2:], "--output", schedule_path],
        [(b"Enter wallet passphrase: ", passphrase)], binary="wallet")
    schedule = json.loads(schedule_path.read_text())["addresses"]
    io.require(len(schedule) == len(set(schedule)) == 2, "invalid two-height schedule")
    smoke = out / "packaged-authorship"
    smoke.mkdir()
    with pair(smoke, manifest, candidate, previous, smoke / "candidate-base",
              {"HEGEMON_SOLO_PAYOUT_SCHEDULE": str(schedule_path)}, other) as (new, old, procs):
        equal_tip([new, old], 0, procs)
        for height in (1, 2):
            mine_one(new, height, procs)
            equal_tip([new, old], height, procs)
        report["packaged_authorship"] = compare_rewards([new, old], schedule, eligible=False)
        save()
    historical = out / "historical-lifecycle"
    historical.mkdir()
    donor = historical / "fixture-base"
    env = io.clean_env()
    env.update(HEGEMON_ROTATION_FIXTURE_SCHEDULE=str(schedule_path), HEGEMON_ROTATION_FIXTURE_BASE=str(donor))
    io.require(FIXTURE_TEST + ": test" in subprocess.check_output([a.fixture_binary, "--list"], text=True, env=env),
               "historical fixture test missing")
    with (historical / "issuance.log").open("xb") as log:
        subprocess.run([a.fixture_binary, FIXTURE_TEST, "--exact", "--ignored", "--nocapture"], env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
    fixture = json.loads((donor / "rotation-fixture.json").read_text())
    io.require(fixture["height"] == 121 and fixture["chain_id"] == CHAIN and fixture["genesis_hash"] == GENESIS,
               "unexpected historical prefix")
    report["historical_fixture"] = {"receipt": fixture, "test_binary_sha256": io.sha(a.fixture_binary)}
    with pair(historical, manifest, candidate, previous, donor, {}, other) as (new, old, procs):
        rpcs = [new, old]
        io.require(equal_tip(rpcs, 121, procs) == fixture["tip_hash"], "wrong historical tip")
        rewards = compare_rewards(rpcs, schedule, eligible=True)
        io.require([r["block_hash"] for r in rewards] == [fixture["first_reward_hash"], fixture["second_reward_hash"]],
                   "historical rewards differ from imported fixture")
        report["mature_rewards"] = rewards
        recovery = json_line(cli("restore", ["--wallet", restored, "bootstrap-recover", "--source", backup],
                                 [(b"Source encrypted wallet passphrase: ", passphrase),
                                  (b"New encrypted wallet passphrase: ", replacement),
                                  (b"Confirm new encrypted wallet passphrase: ", replacement)]))
        io.require(recovery["address"] == address and recovery["recovered_same_keys"]
                   and recovery["requires_network_rescan"] and io.sha(restored) != report["backup_sha256"],
                   "fresh separately encrypted recovery failed")
        network = ["--wallet", restored, "--manifest", manifest, "--genesis", GENESIS,
                   "--rpc", f"http://127.0.0.1:{old}"]
        unlock = [(io.PASS_PROMPT, replacement)]
        def wallet(name, command, timeout=240):
            return cli(name, [*network, *command], unlock, timeout=timeout)
        status = wallet("restored-rescan", ["status"])
        notes = [(int(pos), int(atoms)) for pos, atoms in re.findall(r"ordinary position=(\d+) value=(\d+)", status)]
        io.require(sorted(notes) == [(0, 400000000), (2, 400000000)]
                   and "synced_height=121 available_atoms=800000000 available_notes=2" in status,
                   "restored wallet did not discover the two expected mature rewards")
        fee, amount = 1000, 500000000
        output = wallet("two-input-proof", ["ordinary", "--inputs", "0", "2", "--recipient", address,
                                           "--amount", str(amount), "--fee", str(fee)], timeout=900)
        ids = re.findall(r"candidate ([0-9a-f]{64})", output)
        io.require(len(ids) == 1, "missing unique proof attempt")
        artifact = historical / "recovered-spend.action"
        wallet("export-proof", ["export", ids[0], artifact])
        raw = artifact.read_bytes()
        carrier = io.public_args(raw)
        nullifiers = [carrier[208:264], carrier[264:320]]
        io.require(len(set(nullifiers)) == 2 and all(any(n) for n in nullifiers)
                   and int.from_bytes(carrier[136:144], "little") == 121
                   and "0x" + carrier[104:136].hex() == fixture["tip_hash"], "incorrect proof inputs or anchor")
        wallet("submit-to-v0115", ["submit", ids[0]])
        tx = "0x" + raw[:48].hex()
        io.require(tx in io.rpc(old, "author_pendingExtrinsics"), "old node did not accept the exact transaction")
        mine_one(old, 122, procs)
        block = equal_tip(rpcs, 122, procs)
        bodies = [io.chunks(rpc, block) for rpc in rpcs]
        io.require(bodies[0] == bodies[1] and bodies[0][0].count(raw) == 1, "exact spend missing from independent bodies")
        status = wallet("rescan-after-spend", ["status"])
        final_notes = [(int(pos), int(atoms)) for pos, atoms in re.findall(r"ordinary position=(\d+) value=(\d+)", status)]
        io.require(len(final_notes) == 2 and all(pos > 2 for pos, _ in final_notes)
                   and sorted(v for _, v in final_notes) == sorted([amount, 800000000 - amount - fee])
                   and "synced_height=122 available_atoms=799999000 available_notes=2" in status,
                   "recovered wallet did not consume both inputs and credit payment and change")
        report["confirmed_spend"] = {"height": 122, "hash": block, "inputs": sorted(notes), "outputs": sorted(final_notes),
                                     "fee_atoms": fee, "nullifiers": [n.hex() for n in nullifiers],
                                     "attempt_id": ids[0], "action_sha256": io.sha(artifact),
                                     "canonical_body_sha256": hashlib.sha256(bodies[0][2]).hexdigest()}
    io.require(io.sha(backup) == report["backup_sha256"], "backup changed during rehearsal")
    report["passed"] = True
    save()
    print(f"PASS {out / 'receipt.json'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=PREVIOUS_SHA, help="target platform (defaults to this host)")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--previous-node", type=Path, required=True)
    parser.add_argument("--fixture-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args())
