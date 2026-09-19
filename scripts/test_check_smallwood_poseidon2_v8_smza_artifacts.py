"""Structural rejection tests; fake wire fixtures never count as accepted proofs."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import check_smallwood_poseidon2_v8_smza_artifacts as check


def put(data, offset, value, width):
    data[offset:offset+width] = value.to_bytes(width,"little")


def framed_files(proof_size=164113, *, profile=check.PROFILE):
    proof=b"SMZA"+b"p"*(proof_size-4)
    public=bytearray(960)
    for i in range(4):put(public,i*8,1,8)
    binding=bytes(56)
    leaf=bytearray(5398+proof_size)
    leaf[:8]=b"HGV8TX03"
    for offset,value,width in [(8,1,2),(10,8,2),(12,7,2),(14,1,2),(16,10,2),(18,2,1),(19,9,1),(20,5,2),(22,120,2),(24,7,2),(28,check.NETWORK,4),(32,proof_size,4),(84,len(leaf),4)]:put(leaf,offset,value,width)
    leaf[36:84]=bytes.fromhex(profile.digest_hex)
    leaf[88:1048]=public;leaf[1048:1104]=binding;leaf[5398:]=proof
    envelope=bytearray(32)
    envelope[:8]=b"SWP8LC03";envelope[8:22]=leaf[8:22];envelope[22]=1
    put(envelope,24,proof_size,4);put(envelope,28,len(leaf),4)
    envelope+=leaf
    args=((len(envelope)<<2)|2).to_bytes(4,"little")+envelope
    return {"proof.bin":proof,"context.bin":b"structural-test-only","public-inputs.bin":bytes(public),"kernel-binding.bin":binding,"native-leaf.bin":bytes(leaf),"rpc-envelope.bin":bytes(envelope),"inline-args.bin":bytes(args)}


def pending(files):
    data=bytearray(104)
    data[0]=1
    for offset,value in [(48,8),(50,7),(52,1),(54,10)]:put(data,offset,value,2)
    leaf=files["native-leaf.bin"]
    hashes=b"".join(check.ciphertext_hash(leaf[1104+i*2147:1104+(i+1)*2147]) for i in range(2))
    data+=b"\0\0\x08"+hashes+b"\x08"+(2147).to_bytes(4,"little")*2
    args=files["inline-args.bin"]
    data+=((len(args)<<2)|2).to_bytes(4,"little")+args+bytes(9)
    data[:48]=check.domain_hash(b"hegemon.native.action-id.v3",bytes(data[48:]))
    return bytes(data)


class FramingTests(unittest.TestCase):
    def test_rp03_and_rp04_are_separate_exact_subjects(self):
        for profile in check.SUPPORTED_PROFILES:
            files=framed_files(profile=profile)
            self.assertEqual(check.select_relation_profile(check.relation_identity(profile)),profile)
            check.validate_carriers(files,profile=profile)
            for other in check.SUPPORTED_PROFILES:
                if profile != other:
                    with self.assertRaises(check.EvidenceError):
                        check.validate_carriers(files,profile=other)
        self.assertEqual(check.PROFILE.magic,b"HGV8RP04")
        self.assertEqual(check.HISTORICAL_PROFILE.program_sha512,
                         check.legacy.METADATA_CORRECTED_RELATION_PROFILE.program_sha512)

    def test_relation_identity_rejects_mixed_or_unknown_program(self):
        identity=check.relation_identity(check.PROFILE)
        mutations=[("relation_digest_hex",check.HISTORICAL_PROFILE.digest_hex),
                   ("relation_program",check.relation_identity(check.HISTORICAL_PROFILE)["relation_program"]),
                   ("profile_id",6),("domain_set",4),("relation_program_profile_lineage",True)]
        for key,value in mutations:
            bad=copy.deepcopy(identity);bad[key]=value
            with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                check.select_relation_profile(bad)
        bad=copy.deepcopy(identity);bad["relation_program"]["sha512"]="0"*128
        with self.assertRaises(check.EvidenceError):check.select_relation_profile(bad)

    def test_q38_maximum_carriers_exceed_q20_but_match_source_caps(self):
        files=framed_files()
        report=check.validate_carriers(files)
        self.assertEqual(report["proof_bytes"],164113)
        self.assertEqual(report["pending_action_bytes"],169772)
        check.validate_pending(pending(files),files)

    def test_q20_and_mixed_profile_rejected(self):
        for name,offset,replacement in [("proof.bin",0,b"SMZ9"),("native-leaf.bin",0,b"HGV8TX02"),("native-leaf.bin",19,b"\x06"),("native-leaf.bin",20,b"\x04\x00"),("rpc-envelope.bin",0,b"SWP8LC02")]:
            with self.subTest(name=name,offset=offset):
                files=framed_files();data=bytearray(files[name]);data[offset:offset+len(replacement)]=replacement;files[name]=bytes(data)
                with self.assertRaises(check.EvidenceError):check.validate_carriers(files)

    def test_oversized_q38_proof_rejected(self):
        with self.assertRaises(check.EvidenceError):check.validate_carriers(framed_files(164114))

    def test_proof_leaf_and_inline_drift_rejected(self):
        for name in ["proof.bin","native-leaf.bin","rpc-envelope.bin","inline-args.bin"]:
            files=framed_files();files[name]=files[name][:-1]+b"x"
            with self.subTest(name=name),self.assertRaises(check.EvidenceError):check.validate_carriers(files)

    def test_noncanonical_scale_and_trailing_bytes_rejected(self):
        for mutation in [lambda x:x+b"\0",lambda x:x[:-1],lambda x:b"\x03"+x[1:]]:
            files=framed_files();files["inline-args.bin"]=mutation(files["inline-args.bin"])
            with self.assertRaises(check.EvidenceError):check.validate_carriers(files)

    def test_field_noncanonical_rejected(self):
        files=framed_files();public=bytearray(files["public-inputs.bin"]);put(public,80,check.legacy.GOLDILOCKS_MODULUS,8);files["public-inputs.bin"]=bytes(public)
        with self.assertRaises(check.EvidenceError):check.validate_carriers(files)

    def test_pending_fee_overhead_and_payload_mutations_rejected(self):
        files=framed_files();honest=pending(files)
        for mutated in [honest+b"\0",honest[:-1],honest[:-1]+b"\x01",honest[:48]+b"\x07"+honest[49:],honest[:-10]+b"x"+honest[-9:]]:
            with self.assertRaises(check.EvidenceError):check.validate_pending(mutated,files)


class CanonicalAndProvenanceTests(unittest.TestCase):
    def test_rp04_fixture_cannot_claim_completed_coinbase_lifecycle(self):
        fixture={"kind":"two_input_two_output_coinbase_spend",
                 "economic_value_source":"fresh_repaired_v5_openings_requiring_action_11_lifecycle",
                 "artifact_alone_authorizes_production":False,
                 "requires_live_coinbase_carrier_lifecycle":True,
                 "economic_production_evidence":False}
        check.validate_fixture_authority(fixture,check.PROFILE)
        for key,value in [("economic_value_source","v8_coinbase_action_11"),
                          ("artifact_alone_authorizes_production",True),
                          ("requires_live_coinbase_carrier_lifecycle",False),
                          ("economic_production_evidence",True)]:
            bad=copy.deepcopy(fixture);bad[key]=value
            with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                check.validate_fixture_authority(bad,check.PROFILE)
        fixture["economic_value_source"]="v8_coinbase_action_11"
        check.validate_fixture_authority(fixture,check.HISTORICAL_PROFILE)

    def test_boolean_and_float_are_not_integer_evidence(self):
        for bad in (True,False,1.0):
            with self.assertRaises(check.EvidenceError):check.integer(bad,"count")
        self.assertFalse(check.same({"count":True},{"count":1}))
        self.assertFalse(check.same([0.0],[0]))

    def test_native_preflight_canonical_manifest_regression(self):
        value={"z":1,"a":{"k":False}}
        canonical=json.dumps(value,sort_keys=True,indent=2).encode()
        self.assertEqual(check.canonical_manifest(canonical),value)
        for bad in [canonical+b"\n",json.dumps(value,indent=2).encode(),json.dumps(value,sort_keys=True).encode()]:
            with self.assertRaises(check.EvidenceError):check.canonical_manifest(bad)

    def test_duplicate_keys_and_nonfinite_json_rejected(self):
        for bad in [b'{"a":1,"a":2}',b'{"a":NaN}',b'[]']:
            with self.assertRaises(check.EvidenceError):check.object_json(bad)

    def test_symlink_and_file_caps_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"source";path.write_bytes(b"1234")
            link=Path(directory)/"link";link.symlink_to(path)
            with self.assertRaises(check.EvidenceError):check.read(link)
            with self.assertRaises(check.EvidenceError):check.read(path,3)

    def test_refresh_cannot_relabel_generation_metadata(self):
        original={"generator":{"exe":"old"},"generation_unix_seconds":1,"proof_source_inventory":{"root_sha512":"old"}}
        names=["node/src/native/"+name for name in ("admission.rs","node_impl.rs","poseidon2_v8_carrier_tests.rs","poseidon2_v8_smza_tests.rs","poseidon2_v8_state.rs","poseidon2_v8_verifier.rs")]
        original["proof_source_inventory"]["entries"]=[{"path":name,"sha512":"old"} for name in names]
        raw=json.dumps(original,sort_keys=True,indent=2).encode()
        refreshed=copy.deepcopy(original);refreshed["proof_source_inventory"]={"root_sha512":"new","entries":[{"path":name,"sha512":"new"} for name in names]}
        refreshed["provenance_refresh"]={"schema":"hegemon-smallwood-poseidon2-v8-smza-provenance-refresh-v1","kind":"native_and_release_validator_source_only_refresh","original_manifest_sha512":check.digest(raw),"original_source_root_sha512":"old","refreshed_source_root_sha512":"new","original_generation_metadata_preserved":True,"proof_bytes_and_entropy_preserved":True,"generation_at_refreshed_source_root_claim":False,"production_eligible":False}
        check.validate_refresh(refreshed,original,raw)
        for target,value in [("generator",{"exe":"new"}),("generation_unix_seconds",2)]:
            bad=copy.deepcopy(refreshed);bad[target]=value
            with self.assertRaises(check.EvidenceError):check.validate_refresh(bad,original,raw)
        bad=copy.deepcopy(refreshed);bad["proof_source_inventory"]["entries"][0]["path"]="circuits/transaction/src/zk.rs"
        with self.assertRaises(check.EvidenceError):check.validate_refresh(bad,original,raw)
        bad=copy.deepcopy(refreshed);bad["proof_source_inventory"]["entries"][0]["sha512"]="old"
        with self.assertRaises(check.EvidenceError):check.validate_refresh(bad,original,raw)
        bad=copy.deepcopy(refreshed);bad["proof_source_inventory"]["entries"].append({"path":"extra","sha512":"new"})
        with self.assertRaises(check.EvidenceError):check.validate_refresh(bad,original,raw)
        bad=copy.deepcopy(refreshed);bad["provenance_refresh"]["generation_at_refreshed_source_root_claim"]=True
        with self.assertRaises(check.EvidenceError):check.validate_refresh(bad,original,raw)

    def test_fake_complete_q38_security_contract_stays_rejected(self):
        for evidence in [None,True,{"complete":True,"pq128":True,"production_eligible":True},{"schema":"smz9-security-complete","q":20}]:
            with self.assertRaises(check.policy.SuccessorAuthorizationError):
                check.require_complete_security_contract({"profile_wire_id":9,"domain_set":5},evidence)

    def test_q20_release_contract_is_not_modified(self):
        check.policy.require_release_profile_evidence_contract({"profile_wire_id":6,"domain_set":4})


class GuardAndLifecycleTests(unittest.TestCase):
    def guard_fixture(self,path):
        path.write_bytes(b"manifest")
        inputs={str(path):check.digest(b"manifest","sha256"),"/native":"a"*64,"/guard":"d136760ee4c8f701df347f11aa58d3ab037d514625d33af556cda90d3275f4ce","/sandbox":"b"*64}
        binding={"candidate":str(path),"candidate_sha512":check.digest(b"manifest"),"native_binary":"/native","native_sha256":"a"*64,"native_sha512":"c"*128,"guard":"/guard","guard_sha256":inputs["/guard"]}
        config={"test_binding":{"mode":"inprocess","full_name":check.TESTS["inprocess"]},"inputs":inputs,"socket_binding":binding,"commands":[{"name":"inprocess","argv":["/usr/bin/sandbox-exec","-f","/sandbox","/native","--ignored","--exact",check.TESTS["inprocess"],"--nocapture","--test-threads=1"]}],"limits":{"wall_seconds":300,"child_stop_seconds":250,"peak_rss_bytes":8*1024**3,"scratch_bytes":1024**3,"minimum_free_bytes":20*1024**3,"max_sample_gap_seconds":5}}
        log=("test "+check.TESTS["inprocess"]+" ... ok\ntest result: ok. 1 passed; 0 failed;").encode()
        guard={"status":"PASS_DEVELOPMENT_ONLY","exit_code":0,"production_authorized":False,"config_sha256":"d"*64,"command":config["commands"][0],"preflight_inputs":inputs,"postflight_inputs":inputs,"execution":{"group_extinct":True,"leader_reaped_after_group_cleanup":True,"group_signals":[]},"active_reservations":[],"log_sha256":check.digest(log,"sha256"),"elapsed_seconds":1,"samples":[{"scratch_allocated_bytes":10,"free_bytes":21*1024**3,"waited_children_peak_rss_bytes":1000,"completed_sample_gap_seconds":0.1}]}
        return config,guard,log

    def test_guard_rejects_forged_success_bindings_and_failed_cleanup(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"manifest.json"
            config,guard,log=self.guard_fixture(path)
            def validate(c,g,l):check.validate_guard(c,g,l,mode="inprocess",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))
            validate(config,guard,log)
            for key,value in [("status","FAILED"),("exit_code",False),("config_sha256","e"*64),("production_authorized",True),("log_sha256","f"*64),("active_reservations",[1]),("elapsed_seconds",True)]:
                bad=copy.deepcopy(guard);bad[key]=value
                with self.subTest(key=key),self.assertRaises(check.EvidenceError):validate(config,bad,log)
            bad=copy.deepcopy(guard);bad["execution"]["group_signals"]=["SIGKILL"]
            with self.assertRaises(check.EvidenceError):validate(config,bad,log)
            bad=copy.deepcopy(config);bad["test_binding"]["full_name"]="retained_q20_test"
            with self.assertRaises(check.EvidenceError):validate(bad,guard,log)
            bad=copy.deepcopy(config);bad["socket_binding"]["candidate_sha512"]="f"*128
            with self.assertRaises(check.EvidenceError):validate(bad,guard,log)

    def test_socket_guard_requires_exact_isolated_pinned_wrapper(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"manifest.json"
            config,guard,_=self.guard_fixture(path)
            config["test_binding"]={"mode":"socket","full_name":check.TESTS["socket"]}
            config["inputs"].update({"/python":"1"*64,"/exec_socket.py":"2"*64})
            config["commands"][0]["argv"]=["/usr/bin/sandbox-exec","-f","/sandbox","/python","-I","-B","/exec_socket.py"]
            guard["preflight_inputs"]=copy.deepcopy(config["inputs"]);guard["postflight_inputs"]=copy.deepcopy(config["inputs"])
            log=("test "+check.TESTS["socket"]+" ... ok\\ntest result: ok. 1 passed; 0 failed;").encode()
            guard["log_sha256"]=check.digest(log,"sha256")
            check.validate_guard(config,guard,log,mode="socket",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))
            for argv in [
                ["/usr/bin/sandbox-exec","-f","/sandbox","/python","-B","/exec_socket.py"],
                ["/usr/bin/sandbox-exec","-f","/sandbox","/python","-I","-B","/unreviewed.py"],
                ["/usr/bin/sandbox-exec","-f","/sandbox","/unreviewed-python","-I","-B","/exec_socket.py"],
                ["/usr/bin/sandbox-exec","-f","/sandbox","/python","-I","-B","/exec_socket.py","--fake-pass"]]:
                bad=copy.deepcopy(config);bad["commands"][0]["argv"]=argv
                bad_guard=copy.deepcopy(guard);bad_guard["command"]=bad["commands"][0]
                with self.assertRaises(check.EvidenceError):check.validate_guard(bad,bad_guard,log,mode="socket",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))

    def socket_fixture(self):
        pair={"primary":framed_files(163217),"independent":framed_files(163537)}
        manifest={"proof_source_inventory":{"root_sha512":"a"*128,"file_count":1,"total_bytes":1},"artifacts":{}}
        config={"cwd":"/repo","socket_binding":{"candidate":"/repo/manifest.json","candidate_sha512":"b"*128,"native_binary":"/native","native_sha512":"c"*128}}
        guard={"execution":{"pid":100,"pgid":100}}
        receipt={"schema":"hegemon.retained-smza.actual-socket-carriers-v1","pass":True,"production_authority_denied":True,"manifest":"manifest.json","manifest_sha512":"b"*128,"source_inventory_verified_before_and_after":True,"source_inventory_root_sha512":"a"*128,"source_inventory_file_count":1,"source_inventory_total_bytes":1,"supervisor_owned_process_group":100,"parent_pid":100,"test_executable":{"path":"/native","sha512":"c"*128},"child_arguments":["--ignored","--exact","native::poseidon2_v8_verifier::tests::retained_rp03_socket_child","--nocapture","--test-threads=1"],"episodes":[]}
        for index,(role,files) in enumerate(pair.items()):
            evidence={"wire_salt_hex":str(index+1)*64,"decs_transcript_root_hex":str(index+1)*128}
            manifest["artifacts"][role]={"proof_evidence":evidence}
            encoded=pending(files)
            block={"actions":[encoded.hex()],"leaves":[{"leaf":files["native-leaf.bin"].hex(),"proof":files["proof.bin"].hex()}]}
            snapshot={"height":3,"tip":"tip","blocks":[{},{},{},block],"typed_rows":{},"pending_rows":0,"pending_stored":None,"pending_memory":[]}
            episode={"artifact_role":"retained_proof_"+role,"test_selected_locator_transport":True,"production_authority_denied":True,"proof_sha512":check.digest(files["proof.bin"]),"native_leaf_sha512":check.digest(files["native-leaf.bin"]),"pending_action_sha512":check.digest(encoded),**evidence,"source_peer":"source","relay_peer":"relay","fresh_peer":"fresh","mutation_http":{"success":False,"error":"SMZA proof rejected"},"shutdown":{}}
            for name in ["source_height_three","relay_height_three","restart_height_three","fresh_height_three","source_final"]:episode[name]=snapshot
            for worker,name in enumerate(["source","relay","restart","fresh"]):
                episode["shutdown"][name]={"exit_success":True,"rpc_closed":True,"p2p_closed":True,"forced_kill":False,"final_ack":{"stopped":True,"authority_denied":True},"process_group":100,"pid":200+index*4+worker}
            receipt["episodes"].append(episode)
        return receipt,manifest,pair,config,guard

    def test_socket_requires_same_proof_complete_pending_action_and_clean_workers(self):
        receipt,manifest,pair,config,guard=self.socket_fixture()
        check.validate_socket(receipt,manifest,pair,config,guard)
        for field,value in [("schema","hegemon.retained-smz9.actual-socket-carriers-v1"),("manifest_sha512","f"*128),("parent_pid",999),("source_inventory_verified_before_and_after",False)]:
            bad=copy.deepcopy(receipt);bad[field]=value
            with self.subTest(field=field),self.assertRaises(check.EvidenceError):check.validate_socket(bad,manifest,pair,config,guard)
        bad=copy.deepcopy(receipt);bad["episodes"][0]["proof_sha512"]="f"*128
        with self.assertRaises(check.EvidenceError):check.validate_socket(bad,manifest,pair,config,guard)
        bad=copy.deepcopy(receipt);bad["episodes"][0]["shutdown"]["fresh"]["forced_kill"]=True
        with self.assertRaises(check.EvidenceError):check.validate_socket(bad,manifest,pair,config,guard)
        bad=copy.deepcopy(receipt);bad["episodes"][0]["fresh_height_three"]["blocks"][3]["actions"][0]+="00"
        with self.assertRaises(check.EvidenceError):check.validate_socket(bad,manifest,pair,config,guard)


class ActualRetainedEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("SMZA_ACTUAL_PACKET"),"coordinator supplies actual completed packet explicitly")
    def test_actual_pair_guard_and_socket_bytes(self):
        root=Path(os.environ["SMZA_ACTUAL_PACKET"])
        config=check.object_json(check.read(root/"CONFIG_SOCKET.json"))
        repo=Path(config["cwd"])
        directory=Path(config["socket_binding"]["candidate"]).parent
        manifest,pair=check.validate_bundle(repo,directory,current_inventory=check.legacy.recompute_source_inventory(repo))
        for mode in check.TESTS:
            raw=check.read(root/("CONFIG_"+mode.upper()+".json"))
            mode_config=check.object_json(raw)
            receipt_path=root/"out"/("dev-"+mode_config["commands"][0]["name"])/"receipt.json"
            guard=check.object_json(check.read(receipt_path))
            check.validate_guard(mode_config,guard,check.read(receipt_path.with_name("command.log")),mode=mode,config_sha256=check.digest(raw,"sha256"),manifest_path=directory/"manifest.json",manifest_sha512=check.digest(check.read(directory/"manifest.json")))
            if mode=="socket":socket_guard=guard
        candidates=list((root/"tmp").glob("hegemon-retained-smz9-carrier-*/actual-socket-carrier-receipt.json"))
        self.assertEqual(len(candidates),1)
        check.validate_socket(check.object_json(check.read(candidates[0],64*1024**2)),manifest,pair,config,socket_guard)


if __name__ == "__main__":unittest.main()
