#!/usr/bin/env python3
"""Read-only SMZA artifact/lifecycle evidence adapter, never release authority.

This module deliberately leaves the historical q20 checker and the complete
q38 release-security gate unchanged. Hash checks are not proof verification:
the top-level entry point also runs the explicitly pinned source verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, NamedTuple

import check_smallwood_poseidon2_v8_retained_artifacts as legacy
import check_transaction_proof_successor_authorization as policy

SCHEMA = "hegemon-smallwood-poseidon2-v8-smza-retained-artifact-v1"
REPORT_SCHEMA = "hegemon.smallwood.poseidon2-v8.smza.software-evidence.v1"

class RelationIdentity(NamedTuple):
    """Exact program identity only; RP03 geometry must not describe RP04."""
    magic: bytes
    program_bytes: int
    program_sha512: str

    @property
    def digest_hex(self) -> str:
        return self.program_sha512[:96]


# Keep the historical evidence identity distinct from the repaired RP04 subject.
# This is software-evidence recognition, not production/security authorization.
HISTORICAL_PROFILE = RelationIdentity(
    b"HGV8RP03",
    legacy.METADATA_CORRECTED_RELATION_PROFILE.program_bytes,
    legacy.METADATA_CORRECTED_RELATION_PROFILE.program_sha512,
)
PROFILE = RelationIdentity(
    b"HGV8RP04", 843715,
    "580ee045ad26fe3f385185717107b7d669ef024a710f0525530d7c600b3dcecdc9696"
    "3a01f327166dea78e9b93edb2097efb62adb101c6ce0518f6e7169848e6",
)
SUPPORTED_PROFILES = (HISTORICAL_PROFILE, PROFILE)
NETWORK = 0x48474D38
LIMITS = {"inner_proof":164113, "rpc_envelope":169543, "inline_args":169547, "pending_action":169772}
ROLE_FILES = {"proof.bin","context.bin","kernel-binding.bin","public-inputs.bin","native-leaf.bin","rpc-envelope.bin","inline-args.bin"}
FILES = {"manifest.json","readback.json","relation-program.bin","coinbase-height1.bin","coinbase-height2.bin"} | {role+"/"+name for role in ("primary","independent") for name in ROLE_FILES}
TESTS = {
    "inprocess":"native::poseidon2_v8_verifier::tests::retained_smza_pair_survives_native_pending_mining_reorg_restart_and_fresh_import",
    "socket":"native::poseidon2_v8_verifier::tests::retained_smza_actual_socket_process_carriers",
}


class EvidenceError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise EvidenceError(message)


def same(left: Any, right: Any) -> bool:
    """JSON equality must not identify booleans or floats with integers."""
    if type(left) is not type(right):
        return False
    if isinstance(left,dict):
        return left.keys() == right.keys() and all(same(left[k],right[k]) for k in left)
    if isinstance(left,list):
        return len(left) == len(right) and all(same(a,b) for a,b in zip(left,right))
    return left == right


def relation_identity(profile: RelationIdentity) -> dict[str, Any]:
    return {"inner_magic":"SMZA","native_leaf_magic":"HGV8TX03","rpc_envelope_magic":"SWP8LC03","network_id":NETWORK,"profile_id":9,"domain_set":5,"relation_program_profile_lineage":6,"relation_digest_hex":profile.digest_hex,"relation_program":{"bytes":profile.program_bytes,"sha512":profile.program_sha512}}


def select_relation_profile(identity: dict[str, Any]) -> RelationIdentity:
    for profile in SUPPORTED_PROFILES:
        if same(identity, relation_identity(profile)):
            return profile
    raise EvidenceError("exact SMZA/repaired relation identity")


def validate_fixture_authority(fixture: dict, profile: RelationIdentity) -> None:
    source = ("fresh_repaired_v5_openings_requiring_action_11_lifecycle"
              if profile == PROFILE else "v8_coinbase_action_11")
    require(fixture["kind"] == "two_input_two_output_coinbase_spend" and fixture["economic_value_source"] == source and fixture["artifact_alone_authorizes_production"] is False, "fixture identity/authority")
    if profile == PROFILE:
        require(fixture["requires_live_coinbase_carrier_lifecycle"] is True and fixture["economic_production_evidence"] is False, "RP04 fixture requires actual coinbase lifecycle")


def integer(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{label}: integer required")
    return value


def number(value: Any, label: str) -> int | float:
    require(type(value) in (int,float) and value >= 0, f"{label}: nonnegative number required")
    return value


def digest(data: bytes, algorithm: str = "sha512") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def read(path: Path, cap: int = 32 * 1024**2) -> bytes:
    path = path.absolute()
    require(".." not in path.parts, "parent traversal")
    for node in (path, *path.parents):
        require(not node.is_symlink(), f"symlink forbidden: {node}")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, "not a capped regular file")
        data = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size <= cap, "file size changed")
    require((before.st_ino,before.st_size,before.st_mtime_ns) == (after.st_ino,after.st_size,after.st_mtime_ns), "file changed during read")
    return data


def object_json(data: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key,value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(value):
        raise EvidenceError(f"nonstandard JSON constant: {value}")
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError,UnicodeError) as error:
        raise EvidenceError(f"invalid JSON: {error}") from error
    require(isinstance(value,dict), "JSON object required")
    return value


def canonical_manifest(data: bytes) -> dict[str,Any]:
    value = object_json(data)
    expected = json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False).encode("utf-8")
    require(data == expected, "manifest must equal serde_json sorted pretty bytes without a trailing newline")
    return value


def u(data: bytes, offset: int, width: int) -> int:
    require(offset + width <= len(data), "truncated integer")
    return int.from_bytes(data[offset:offset+width], "little")


def compact(data: bytes, offset: int = 0) -> tuple[int,int]:
    try:
        return legacy.decode_compact_u32(data, offset, "SMZA SCALE")
    except (ValueError,RuntimeError) as error:
        raise EvidenceError(str(error)) from error


def route(data: bytes) -> None:
    require(tuple(u(data,offset,2) for offset in (8,10,12,14,16)) == (1,8,7,1,10), "SMZA grammar/route")
    require(u(data,18,1) == 2 and u(data,19,1) == 9 and u(data,20,2) == 5, "SMZA profile/domain; q20 is forbidden")


def validate_carriers(files: dict[str,bytes], *, profile: RelationIdentity = PROFILE) -> dict[str,Any]:
    require(profile in SUPPORTED_PROFILES, "unsupported relation profile")
    require(set(files) == ROLE_FILES, "role file set")
    proof,leaf = files["proof.bin"],files["native-leaf.bin"]
    public,binding = files["public-inputs.bin"],files["kernel-binding.bin"]
    envelope,args = files["rpc-envelope.bin"],files["inline-args.bin"]
    require(4 <= len(proof) <= LIMITS["inner_proof"] and proof[:4] == b"SMZA", "SMZA proof magic/cap")
    require(len(public) == 960 and len(binding) == 56, "public/binding geometry")
    require(all(u(part,i,8) < legacy.GOLDILOCKS_MODULUS for part in (public,binding) for i in range(0,len(part),8)), "noncanonical Goldilocks word")
    require([u(public,i*8,8) for i in range(4)] == [1,1,1,1], "positive maximum-shape activity flags")
    require(len(leaf) == len(proof)+5398 and leaf[:8] == b"HGV8TX03", "native leaf length/magic")
    route(leaf)
    require((u(leaf,22,2),u(leaf,24,2),u(leaf,26,2)) == (120,7,0), "native leaf counts/reserved")
    require(u(leaf,28,4) == NETWORK and u(leaf,32,4) == len(proof), "native network/proof length")
    require(leaf[36:84] == bytes.fromhex(profile.digest_hex) and u(leaf,84,4) == len(leaf), "native relation/total")
    require(leaf[88:1048] == public and leaf[1048:1104] == binding and leaf[5398:] == proof, "unchanged leaf fields")
    require(len(envelope) == len(proof)+5430 <= LIMITS["rpc_envelope"] and envelope[:8] == b"SWP8LC03", "RPC length/magic")
    route(envelope)
    require(envelope[22:24] == b"\x01\x00" and u(envelope,24,4) == len(proof) and u(envelope,28,4) == len(leaf), "RPC counts/mode")
    require(envelope[32:] == leaf, "unchanged envelope leaf")
    length,cursor = compact(args)
    require(cursor == 4 and length == len(envelope) and args[cursor:] == envelope, "exact canonical inline args")
    require(len(args) == len(proof)+5434 <= LIMITS["inline_args"], "inline cap")
    return {"proof_bytes":len(proof),"proof_sha512":digest(proof),"native_leaf_sha512":digest(leaf),"inline_args_sha512":digest(args),"pending_action_bytes":len(args)+225}


def domain_hash(domain: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(b"hegemon.blake2b-384.frame-v1"+len(domain).to_bytes(8,"little")+domain+len(data).to_bytes(8,"little")+data,digest_size=48).digest()


def ciphertext_hash(data: bytes) -> bytes:
    raw=domain_hash(b"hegemon.transaction.ciphertext-hash.v2",data)
    return b"".join((int.from_bytes(raw[i:i+8],"big") % legacy.GOLDILOCKS_MODULUS).to_bytes(8,"big") for i in range(0,48,8))


def validate_pending(pending: bytes, files: dict[str,bytes]) -> None:
    args = files["inline-args.bin"]
    require(len(pending) == len(args)+225 <= LIMITS["pending_action"], "SMZA complete PendingAction cap")
    require(pending[:48] != bytes(48) and tuple(u(pending,i,2) for i in (48,50,52,54)) == (8,7,1,10), "pending identity/hash")
    require(pending[56:104] == bytes(48), "pending legacy anchor")
    cursor = 104
    for expected in (0,0,2):
        value,cursor = compact(pending,cursor)
        require(value == expected, "pending legacy lists/ciphertext count")
    leaf=files["native-leaf.bin"]
    expected_hashes=b"".join(ciphertext_hash(leaf[1104+i*2147:1104+(i+1)*2147]) for i in range(2))
    require(pending[cursor:cursor+96] == expected_hashes,"pending ciphertext hashes differ from actual leaf")
    cursor += 96
    count,cursor = compact(pending,cursor)
    require(count == 2 and [u(pending,cursor+i*4,4) for i in range(2)] == [2147,2147], "pending ciphertext sizes")
    cursor += 8
    length,cursor = compact(pending,cursor)
    end = cursor+length
    require(pending[cursor:end] == args and end+9 == len(pending), "pending args exact consumption")
    require(pending[end:] == bytes(9), "pending fee/candidate must be zero/None")
    require(pending[:48] == domain_hash(b"hegemon.native.action-id.v3",pending[48:]),"pending transaction identity hash")


def validate_refresh(manifest: dict, original: dict, original_bytes: bytes) -> None:
    refresh = manifest["provenance_refresh"]
    require(refresh["schema"] == "hegemon-smallwood-poseidon2-v8-smza-provenance-refresh-v1", "refresh schema")
    require(refresh["kind"] in {"native_source_only_refresh_preserving_proof_and_generation_metadata","native_and_release_validator_source_only_refresh"}, "refresh scope")
    require(refresh["original_manifest_sha512"] == digest(original_bytes), "original manifest pin")
    require(refresh["original_source_root_sha512"] == original["proof_source_inventory"]["root_sha512"], "original source root")
    require(refresh["refreshed_source_root_sha512"] == manifest["proof_source_inventory"]["root_sha512"], "refreshed source root")
    for key in ("original_generation_metadata_preserved","proof_bytes_and_entropy_preserved"):
        require(refresh[key] is True, "refresh preservation assertion")
    require(refresh["generation_at_refreshed_source_root_claim"] is False and refresh["production_eligible"] is False, "refresh claims authority/generation")
    allowed = {"node/src/native/"+name for name in ("admission.rs","node_impl.rs","poseidon2_v8_carrier_tests.rs","poseidon2_v8_smza_tests.rs","poseidon2_v8_state.rs","poseidon2_v8_verifier.rs")}
    old_entries=original["proof_source_inventory"]["entries"]
    new_entries=manifest["proof_source_inventory"]["entries"]
    old_map={entry["path"]:entry for entry in old_entries}
    new_map={entry["path"]:entry for entry in new_entries}
    require(len(old_map)==len(old_entries) and len(new_map)==len(new_entries), "duplicate source inventory entries")
    require(old_map.keys()==new_map.keys(), "refresh cannot add or remove inventory source files")
    changed={name for name in old_map if not same(old_map[name],new_map[name])}
    require(bool(changed) and changed <= allowed, "refresh changed non-native proof/relation source")
    if refresh["kind"] == "native_and_release_validator_source_only_refresh":
        require(changed == allowed, "R8 refresh must bind exactly six native source deltas")
    old = {k:v for k,v in original.items() if k != "proof_source_inventory"}
    new = {k:v for k,v in manifest.items() if k not in {"proof_source_inventory","provenance_refresh"}}
    require(same(old,new), "refresh changed original generation/proof metadata")


def validate_bundle(repo: Path, directory: Path, *, current_inventory: dict) -> tuple[dict,dict]:
    require(directory.parent == repo/".agent/artifacts/smallwood-poseidon2-v8-smza", "distinct SMZA artifact parent required")
    actual = set()
    for parent,dirs,files in os.walk(directory,followlinks=False):
        for name in dirs:
            require(not (Path(parent)/name).is_symlink(), "symlink artifact directory")
        for name in files:
            actual.add(str((Path(parent)/name).relative_to(directory)))
    require(actual == FILES, "exact SMZA 19-file bundle required")
    manifest = canonical_manifest(read(directory/"manifest.json"))
    require(manifest["schema"] == SCHEMA and manifest["production_eligible"] is False, "SMZA manifest schema/authority")
    require(same(manifest["proof_source_inventory"],current_inventory), "current full v5 source inventory")
    profile = select_relation_profile(manifest["identity"])
    expected_identity = relation_identity(profile)
    projection = manifest["projection"]
    require(same(projection["identity"],expected_identity) and same(projection["projected_bytes"],LIMITS) and projection["production_eligible"] is False, "q38 byte projection")
    fixture = manifest["fixture"]
    require(same(projection["fixture"],fixture) and same(fixture["input_values"],[499429223,499429223]) and same(fixture["input_positions"],[0,1]), "positive two-coinbase fixture")
    validate_fixture_authority(fixture, profile)
    program = read(directory/"relation-program.bin")
    require(program[:8] == profile.magic and len(program) == profile.program_bytes and digest(program) == profile.program_sha512, "exact repaired relation program")
    pair = {}
    for role in ("primary","independent"):
        files = {name:read(directory/role/name,200000) for name in ROLE_FILES}
        report = manifest["artifacts"][role]
        require(same(report["files"],{name:{"bytes":len(data),"sha512":digest(data)} for name,data in files.items()}), "role hash inventory")
        validate_carriers(files, profile=profile)
        local = report["proof_evidence"]["local_audit"]
        require(local["schema"] == "hegemon.smallwood.poseidon2-v8.smza.accepted-proof-local-audit.v1", "SMZA local audit schema")
        require(all(local[key] is False for key in ("full_privacy_claim","pq128_claim","production_eligible")), "local audit cannot claim complete security")
        require(all(local[key] is True for key in ("candidate_verifier_accepts","canonical_decode_reencode_exact","verifier_trace_replay_exact")), "local acceptance audit")
        require(local["proof_sha512_hex"] == digest(files["proof.bin"]) and local["proof_bytes"] == len(files["proof.bin"]), "local proof binding")
        pair[role] = files
    for name in ("public-inputs.bin","kernel-binding.bin","context.bin"):
        require(pair["primary"][name] == pair["independent"][name], "proof pair statement/context mismatch")
    require(pair["primary"]["proof.bin"] != pair["independent"]["proof.bin"], "duplicate proof")
    for key in ("wire_salt_hex","decs_transcript_root_hex"):
        values=[manifest["artifacts"][role]["proof_evidence"][key] for role in pair]
        require(values[0] != values[1] and all(isinstance(v,str) and set(v) != {"0"} for v in values), "separate entropy binding")
    if "provenance_refresh" in manifest:
        original_path = Path(manifest["provenance_refresh"]["original_manifest_path"])
        require(original_path.parent.parent == directory.parent and original_path.name == "manifest.json", "original bundle location")
        raw = read(original_path)
        validate_refresh(manifest,canonical_manifest(raw),raw)
        refresh = manifest["provenance_refresh"]
        if refresh["kind"] == "native_and_release_validator_source_only_refresh":
            sources=refresh["release_validator_sources"]
            require(set(sources) == {"scripts/check_transaction_proof_successor_authorization.py","scripts/test_check_transaction_proof_smza_identity.py"}, "release validator source set")
            require(refresh["release_validator_inventory_scope"] == "separate_guard_pins_not_members_of_release_source_inventory_v2", "validator inventory scope")
            for name,descriptor in sources.items():
                content=read(repo/name)
                require(type(descriptor["bytes"]) is int and descriptor["bytes"] == len(content) and descriptor["sha256"] == digest(content,"sha256") and descriptor["sha512"] == digest(content), "release validator source pin")
        for name in FILES-{"manifest.json"}:
            require(read(directory/name) == read(original_path.parent/name), "refresh changed retained payload")
    return manifest,pair


def verify_source_owned(repo: Path, directory: Path, generator: Path, expected_sha512: str, manifest: dict) -> dict:
    binary = read(generator,160*1024**2)
    require(digest(binary) == expected_sha512 == manifest["generator"]["executable"]["sha512"], "trusted generator pin")
    source = repo/manifest["generator"]["source_path"]
    require(digest(read(source)) == manifest["generator"]["source"]["sha512"], "generator source changed")
    before = digest(read(directory/"manifest.json"))
    result = subprocess.run([str(generator),"verify",str(directory)],cwd=repo,env=legacy.verifier_environment(),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240,check=False)
    require(result.returncode == 0, "source-owned SMZA cryptographic verification failed")
    report = object_json(result.stdout)
    require(report["schema"] == "hegemon-smallwood-poseidon2-v8-smza-readback-v1" and report["production_eligible"] is False, "source readback schema")
    require(report["distinct_proofs"] is True and report["distinct_salts_and_roots"] is True, "source pair verification")
    for role in ("primary","independent"):
        record=report["artifacts"][role]
        require(record["source_owned_verification"] is True and record["unchanged_carriers"] is True, "source role verification")
        require(record["proof_sha512"] == manifest["artifacts"][role]["files"]["proof.bin"]["sha512"], "source readback proof pin")
    require(digest(read(directory/"manifest.json")) == before and digest(read(generator,160*1024**2)) == expected_sha512, "verifier inputs changed")
    return report


def validate_guard(config: dict, guard: dict, log: bytes, *, mode: str, config_sha256: str, manifest_path: Path, manifest_sha512: str) -> None:
    require(mode in TESTS and config["test_binding"]["full_name"] == TESTS[mode] and config["test_binding"]["mode"] == mode, "exact SMZA lifecycle test required")
    require(guard["status"] == "PASS_DEVELOPMENT_ONLY" and integer(guard["exit_code"],"guard exit code") == 0 and guard["production_authorized"] is False, "guard did not pass")
    require(guard["config_sha256"] == config_sha256 and len(config["commands"]) == 1 and guard["command"] == config["commands"][0], "guard command/config binding")
    require(same(guard["preflight_inputs"],config["inputs"]) and same(guard["postflight_inputs"],config["inputs"]), "guard source input mismatch")
    require(config["inputs"].get(str(manifest_path)) == digest(read(manifest_path),"sha256"), "lifecycle manifest not pinned")
    binding=config["socket_binding"]
    require(binding["candidate"] == str(manifest_path) and binding["candidate_sha512"] == manifest_sha512, "lifecycle candidate mismatch")
    require(config["inputs"].get(binding["native_binary"]) == binding["native_sha256"], "lifecycle native binary not pinned")
    require(binding["guard_sha256"] == "d136760ee4c8f701df347f11aa58d3ab037d514625d33af556cda90d3275f4ce" and config["inputs"].get(binding["guard"]) == binding["guard_sha256"], "reviewed process guard pin required")
    argv=config["commands"][0]["argv"]
    require(argv[:2] == ["/usr/bin/sandbox-exec","-f"] and argv[2] in config["inputs"], "pinned sandbox profile required")
    if mode == "inprocess":
        require(argv[3:] == [binding["native_binary"],"--ignored","--exact",TESTS[mode],"--nocapture","--test-threads=1"], "in-process command must run exact native test")
    else:
        require(len(argv) == 7 and argv[4:6] == ["-I","-B"] and argv[3] in config["inputs"] and argv[6] in config["inputs"], "socket isolated wrapper must be pinned")
    execution=guard["execution"]
    require(execution["group_extinct"] is True and execution["leader_reaped_after_group_cleanup"] is True and execution["group_signals"] == [] and guard["active_reservations"] == [], "guard cleanup failed")
    require(not guard.get("watchdog_stop") and not execution.get("watchdog_errors"), "guard watchdog failure")
    require(digest(log,"sha256") == guard["log_sha256"], "guard log pin")
    require(b"test result: ok. 1 passed; 0 failed;" in log and ("test "+TESTS[mode]+" ...").encode() in log, "wrong successful test transcript")
    limits=config["limits"]
    for key in ("wall_seconds","child_stop_seconds","peak_rss_bytes","scratch_bytes","minimum_free_bytes"):
        integer(limits[key],key,1)
    number(limits["max_sample_gap_seconds"],"max sample gap")
    number(guard["elapsed_seconds"],"elapsed seconds")
    require(0 < guard["elapsed_seconds"] <= limits["wall_seconds"] <= 300 and limits["child_stop_seconds"] <= 250, "guard wall limit")
    require(limits["peak_rss_bytes"] <= 8*1024**3 and limits["scratch_bytes"] <= 1024**3 and limits["minimum_free_bytes"] >= 20*1024**3, "guard resource limits")
    require(bool(guard["samples"]), "missing guard samples")
    for sample in guard["samples"]:
        for key in ("scratch_allocated_bytes","free_bytes","waited_children_peak_rss_bytes"):
            integer(sample[key],key)
        if "owned_group_rss_bytes" in sample:
            integer(sample["owned_group_rss_bytes"],"owned group RSS")
        number(sample["completed_sample_gap_seconds"],"completed sample gap")
        require(sample["scratch_allocated_bytes"] <= limits["scratch_bytes"] and sample["free_bytes"] >= limits["minimum_free_bytes"] and sample["waited_children_peak_rss_bytes"] <= limits["peak_rss_bytes"] and sample.get("owned_group_rss_bytes",0) <= limits["peak_rss_bytes"] and sample["completed_sample_gap_seconds"] <= limits["max_sample_gap_seconds"] <= 5, "guard resource sample failed")


def validate_socket(receipt: dict, manifest: dict, pair: dict, config: dict, guard: dict) -> None:
    require(receipt["schema"] == "hegemon.retained-smza.actual-socket-carriers-v1" and receipt["pass"] is True and receipt["production_authority_denied"] is True, "socket success/schema")
    binding=config["socket_binding"]
    require(receipt["manifest"] == str(Path(binding["candidate"]).relative_to(config["cwd"])) and receipt["manifest_sha512"] == binding["candidate_sha512"], "socket manifest binding")
    require(receipt["source_inventory_verified_before_and_after"] is True, "socket source verification")
    for key in ("root_sha512","file_count","total_bytes"):
        require(same(receipt["source_inventory_"+key],manifest["proof_source_inventory"][key]), "socket source inventory mismatch")
    for value in (receipt["supervisor_owned_process_group"],receipt["parent_pid"],guard["execution"]["pid"],guard["execution"]["pgid"]):
        integer(value,"socket supervisor PID",1)
    require(receipt["supervisor_owned_process_group"] == receipt["parent_pid"] == guard["execution"]["pid"] == guard["execution"]["pgid"], "socket process ownership")
    require(receipt["test_executable"]["path"] == binding["native_binary"] and receipt["test_executable"]["sha512"] == binding["native_sha512"], "socket executable binding")
    require(receipt["child_arguments"] == ["--ignored","--exact","native::poseidon2_v8_verifier::tests::retained_rp03_socket_child","--nocapture","--test-threads=1"], "socket child selector")
    require(len(receipt["episodes"]) == 2 and {e["artifact_role"] for e in receipt["episodes"]} == {"retained_proof_primary","retained_proof_independent"}, "two socket proof episodes required")
    pids=[]
    for episode in receipt["episodes"]:
        role={"retained_proof_primary":"primary","retained_proof_independent":"independent"}[episode["artifact_role"]]
        files=pair[role]
        require(episode["test_selected_locator_transport"] is True and episode["production_authority_denied"] is True, "socket scope/authority")
        require(episode["proof_sha512"] == digest(files["proof.bin"]) and episode["native_leaf_sha512"] == digest(files["native-leaf.bin"]), "socket unchanged proof/leaf")
        for key in ("wire_salt_hex","decs_transcript_root_hex"):
            require(episode[key] == manifest["artifacts"][role]["proof_evidence"][key], "socket entropy binding")
        require(len({episode["source_peer"],episode["relay_peer"],episode["fresh_peer"]}) == 3, "socket distinct peers")
        snapshots=[episode[key] for key in ("source_height_three","relay_height_three","restart_height_three","fresh_height_three","source_final")]
        first=snapshots[0]
        for snapshot in snapshots:
            require(snapshot["height"] == 3 and snapshot["tip"] == first["tip"] and snapshot["blocks"] == first["blocks"] and snapshot["typed_rows"] == first["typed_rows"], "socket chain/state divergence")
            require(integer(snapshot["pending_rows"],"pending rows") == 0 and snapshot["pending_stored"] is None and same(snapshot["pending_memory"],[]), "socket pending state not empty")
            block=snapshot["blocks"][3]
            require(len(block["actions"]) == len(block["leaves"]) == 1, "socket exact action/leaf count")
            pending=bytes.fromhex(block["actions"][0])
            validate_pending(pending,files)
            require(digest(pending) == episode["pending_action_sha512"] and bytes.fromhex(block["leaves"][0]["leaf"]) == files["native-leaf.bin"] and bytes.fromhex(block["leaves"][0]["proof"]) == files["proof.bin"], "socket complete unchanged carrier")
        require(episode["mutation_http"]["success"] is False and "SMZA proof rejected" in episode["mutation_http"]["error"], "socket cryptographic mutation control")
        require(set(episode["shutdown"]) == {"source","relay","restart","fresh"}, "socket worker set")
        for stop in episode["shutdown"].values():
            integer(stop["pid"],"worker PID",1)
            integer(stop["process_group"],"worker process group",1)
            require(stop["exit_success"] is True and stop["rpc_closed"] is True and stop["p2p_closed"] is True and stop["forced_kill"] is False and stop["final_ack"]["stopped"] is True and stop["final_ack"]["authority_denied"] is True, "unclean socket worker exit")
            require(stop["process_group"] == receipt["parent_pid"] and stop["pid"] != receipt["parent_pid"], "socket worker ownership")
            pids.append(stop["pid"])
    require(len(set(pids)) == 8, "socket worker PID reuse")


def require_complete_security_contract(identity: dict, supplied_evidence: Any = None) -> None:
    """Only the source-owned release contract may accept cryptographic evidence.

    No user-provided dictionary/boolean, local audit or q20 certificate can
    bypass the currently missing complete q38 contract.
    """
    policy.require_release_profile_evidence_contract(identity)
    raise EvidenceError("SMZA complete-security adapter is not installed")


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("repo","artifact-dir","generator","generator-sha512","inprocess-config","inprocess-receipt","socket-config","socket-receipt","socket-carrier-receipt"):
        parser.add_argument("--"+name,required=True)
    for name in ("inprocess-config","inprocess-receipt","socket-config","socket-receipt","socket-carrier-receipt"):
        parser.add_argument("--"+name+"-sha256",required=True,help="Externally reviewed immutable evidence pin; not execution authentication")
    parser.add_argument("--require-release-contract",action="store_true")
    args=parser.parse_args(argv)
    for name in ("inprocess_config","inprocess_receipt","socket_config","socket_receipt","socket_carrier_receipt"):
        require(digest(read(Path(getattr(args,name)),64*1024**2),"sha256") == getattr(args,name+"_sha256"),"reviewed evidence pin mismatch: "+name)
    repo=Path(args.repo).resolve();directory=Path(args.artifact_dir).absolute()
    inventory=legacy.recompute_source_inventory(repo)
    manifest,pair=validate_bundle(repo,directory,current_inventory=inventory)
    verified=verify_source_owned(repo,directory,Path(args.generator),args.generator_sha512,manifest)
    guards={}
    configs={}
    for mode in TESTS:
        raw=read(Path(getattr(args,mode+"_config")))
        config=object_json(raw)
        receipt_path=Path(getattr(args,mode+"_receipt"))
        guard=object_json(read(receipt_path))
        validate_guard(config,guard,read(receipt_path.with_name("command.log")),mode=mode,config_sha256=digest(raw,"sha256"),manifest_path=directory/"manifest.json",manifest_sha512=digest(read(directory/"manifest.json")))
        require(len(config["inputs"]) <= 4096, "too many guarded inputs")
        require(all(str(repo/entry["path"]) in config["inputs"] for entry in inventory["entries"]), "lifecycle guard omitted current source inventory inputs")
        for path,expected in config["inputs"].items():
            require(digest(read(Path(path),160*1024**2),"sha256") == expected, "guarded input changed")
        guards[mode]=guard;configs[mode]=config
    require(configs["inprocess"]["socket_binding"] == configs["socket"]["socket_binding"], "lifecycle executable/artifact bindings differ")
    validate_socket(object_json(read(Path(args.socket_carrier_receipt),64*1024**2)),manifest,pair,configs["socket"],guards["socket"])
    require(legacy.recompute_source_inventory(repo) == inventory, "source changed during evidence verification")
    for name in ("inprocess_config","inprocess_receipt","socket_config","socket_receipt","socket_carrier_receipt"):
        require(digest(read(Path(getattr(args,name)),64*1024**2),"sha256") == getattr(args,name+"_sha256"),"reviewed evidence changed during validation: "+name)
    if args.require_release_contract:
        require_complete_security_contract({"profile_wire_id":9,"domain_set":5})
    print(json.dumps({"schema":REPORT_SCHEMA,"artifact_manifest_sha512":digest(read(directory/"manifest.json")),"source_root_sha512":inventory["root_sha512"],"source_owned_proof_verification":verified,"recorded_inprocess_reorg_evidence_consistent":True,"recorded_actual_socket_carrier_evidence_consistent":True,"execution_receipts_authenticated":False,"trusted_execution_and_review_binding_required":True,"generator_build_authority_established":False,"complete_q38_security_contract_satisfied":False,"production_eligible":False},sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError,KeyError,ValueError,OSError,subprocess.SubprocessError) as error:
        raise SystemExit(f"SMZA evidence rejected: {error}")
