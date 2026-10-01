"""Structural rejection tests; fake wire fixtures never count as accepted proofs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
    def test_rp03_rp04_and_rp05_are_separate_exact_subjects(self):
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
        self.assertEqual(check.RP05_PROFILE.magic,b"HGV8RP05")
        self.assertEqual(check.RP05_PROFILE.program_bytes,848231)
        self.assertEqual(check.RP05_PROFILE.program_sha512,
                         "4b0acd4289abd6ae2f0544857fd3fd0177dff45c2bae2a400fbf687e375944ffd4"
                         "cf62b6d071ec1f29abd9ddce99c7e4e305e214238b0d34e3c64d7b5a0cde97")

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
    def test_artifact_directory_accepts_only_direct_and_exact_rp05_lane_layouts(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo=Path(temporary)/"repo"
            root=repo/".agent/artifacts/smallwood-poseidon2-v8-smza"
            (root/"legacy-run").mkdir(parents=True)
            lane=root/"rp05-qualification-lanes"/"run_01.A-b"/"pair"
            lane.mkdir(parents=True)
            self.assertEqual(check.validate_artifact_directory(repo,root/"legacy-run"),root/"legacy-run")
            self.assertEqual(check.validate_artifact_directory(repo,lane),lane)

    def test_artifact_directory_rejects_aliases_wrong_nesting_and_unsafe_lane_ids(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo=Path(temporary)/"repo"
            root=repo/".agent/artifacts/smallwood-poseidon2-v8-smza"
            candidates=[
                root,
                root/"legacy"/"nested",
                root/"rp05-qualification-lanes"/"run"/"other",
                root/"rp05-qualification-lanes"/"-bad"/"pair",
                root/"rp05-qualification-lanes"/("r"*65)/"pair",
                str(root/"rp05-qualification-lanes")+"/../legacy",
                str(root/"legacy")+"/./",
            ]
            for candidate in candidates:
                with self.subTest(candidate=str(candidate)),self.assertRaises(check.EvidenceError):
                    check.validate_artifact_directory(repo,candidate)

    def test_artifact_directory_rejects_symlink_components_and_non_directories(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            repo=Path(temporary)/"repo"
            root=repo/".agent/artifacts/smallwood-poseidon2-v8-smza"
            lane_parent=root/"rp05-qualification-lanes"
            lane_parent.mkdir(parents=True)
            outside=Path(temporary)/"outside"
            (outside/"pair").mkdir(parents=True)
            (lane_parent/"linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(check.EvidenceError):
                check.validate_artifact_directory(repo,lane_parent/"linked"/"pair")
            (root/"not-a-directory").write_text("x")
            with self.assertRaises(check.EvidenceError):
                check.validate_artifact_directory(repo,root/"not-a-directory")

    def qualification_manifest(self, profile=check.RP05_PROFILE):
        """Synthetic metadata only: never a verified proof or lifecycle receipt."""
        fixture={"kind":"two_input_two_output_coinbase_spend",
                 "economic_value_source":"fresh_repaired_v5_openings_requiring_action_11_lifecycle",
                 "artifact_alone_authorizes_production":False,
                 "requires_live_coinbase_carrier_lifecycle":True,
                 "economic_production_evidence":False,
                 "input_values":[499429223,499429223],"input_positions":[0,1],
                 "canonical_empty_note_root_hex":b"".join(word.to_bytes(8,"little") for word in check.policy.RP04_KNOWN_EMPTY_NOTE_GENESIS_ROOT).hex()}
        if profile == check.HISTORICAL_PROFILE:
            fixture["economic_value_source"]="v8_coinbase_action_11"
        manifest={"schema":check.SCHEMA,"production_eligible":False,
                  "identity":check.relation_identity(profile),"fixture":fixture,
                  "proof_source_inventory":{"test_only":True},
                  "projection":{"identity":check.relation_identity(profile),
                                "fixture":copy.deepcopy(fixture),
                                "projected_bytes":dict(check.LIMITS),
                                "production_eligible":False}}
        if profile == check.RP05_PROFILE:
            manifest.update(features=["rp05-dev-artifacts"],production_authorized=False,
                            qualification_scope=check.RP05_QUALIFICATION_SCOPE,
                            generator={"source_path":check.RP05_GENERATOR_SOURCE})
            manifest["projection"].update(production_authorized=False,
                                         qualification_scope=check.RP05_QUALIFICATION_SCOPE)
        return manifest

    def test_rp05_metadata_scope_preserves_historical_profile_checks(self):
        for profile in check.SUPPORTED_PROFILES:
            manifest=self.qualification_manifest(profile)
            self.assertEqual(check.validate_manifest(manifest,current_inventory={"test_only":True}),profile)

    def test_rp05_wrong_digest_profile_or_geometry_rejected(self):
        mutations=[("relation_digest_hex",check.PROFILE.digest_hex),
                   ("profile_id",6),("domain_set",4),
                   ("relation_program",{"bytes":848231,"sha512":"0"*128}),
                   ("relation_program",{"bytes":843715,"sha512":check.RP05_PROFILE.program_sha512})]
        for key,value in mutations:
            bad=self.qualification_manifest()
            bad["identity"][key]=value
            bad["projection"]["identity"]=copy.deepcopy(bad["identity"])
            with self.subTest(key=key,value=value),self.assertRaises(check.EvidenceError):
                check.validate_manifest(bad,current_inventory={"test_only":True})

    def test_rp05_missing_or_promoted_qualification_scope_rejected(self):
        for key in ("features","production_authorized","qualification_scope","generator"):
            bad=self.qualification_manifest();del bad[key]
            with self.subTest(missing=key),self.assertRaises(check.EvidenceError):
                check.validate_manifest(bad,current_inventory={"test_only":True})
        for key,value in [("features",[]),("features",["production"]),
                          ("production_eligible",True),("production_authorized",True),
                          ("production_authorized",0),("qualification_scope","production"),
                          ("generator",{"source_path":"circuits/transaction/examples/smallwood_poseidon2_v8_smza_artifact.rs"}),
                          ("proof_source_inventory",{"test_only":False}),
                          ("provenance_refresh",{})]:
            bad=self.qualification_manifest();bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(check.EvidenceError):
                check.validate_manifest(bad,current_inventory={"test_only":True})
        for key in ("production_eligible","production_authorized","qualification_scope"):
            bad=self.qualification_manifest();bad["projection"][key]=True
            with self.subTest(projection=key),self.assertRaises(check.EvidenceError):
                check.validate_manifest(bad,current_inventory={"test_only":True})

    def test_rp05_requires_repaired_source_label_and_current_empty_note_root(self):
        for key,value in [("economic_value_source","v8_coinbase_action_11"),
                          ("canonical_empty_note_root_hex",check.legacy.EXPECTED_FIXTURE["canonical_empty_note_root_hex"]),
                          ("artifact_alone_authorizes_production",True),
                          ("requires_live_coinbase_carrier_lifecycle",False),
                          ("economic_production_evidence",True)]:
            bad=self.qualification_manifest();bad["fixture"][key]=value
            bad["projection"]["fixture"]=copy.deepcopy(bad["fixture"])
            with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                check.validate_manifest(bad,current_inventory={"test_only":True})

    def test_nested_local_evidence_required_and_bound_to_proof(self):
        proof=b"synthetic structural fixture, not a valid proof"
        local={"schema":"hegemon.smallwood.poseidon2-v8.smza.accepted-proof-local-audit.v1",
               "full_privacy_claim":False,"pq128_claim":False,"production_eligible":False,
               "candidate_verifier_accepts":True,"canonical_decode_reencode_exact":True,
               "verifier_trace_replay_exact":True,
               "proof_sha512_hex":check.digest(proof),"proof_bytes":len(proof)}
        report={"proof_evidence":{"local_audit":local}}
        check.validate_proof_evidence(report,proof)
        for bad in ({}, {"local_audit":local}, {"proof_evidence":None},
                    {"proof_evidence":{}}, {"proof_evidence":{"local_audit":True}}):
            with self.subTest(missing=bad),self.assertRaises(check.EvidenceError):
                check.validate_proof_evidence(bad,proof)
        for key,value in [("full_privacy_claim",True),("pq128_claim",True),
                          ("production_eligible",True),("candidate_verifier_accepts",False),
                          ("canonical_decode_reencode_exact",False),("verifier_trace_replay_exact",False),
                          ("proof_sha512_hex","0"*128),("proof_bytes",len(proof)+1),
                          ("proof_bytes",float(len(proof)))]:
            bad=copy.deepcopy(report);bad["proof_evidence"]["local_audit"][key]=value
            with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                check.validate_proof_evidence(bad,proof)

    def test_rp04_fixture_cannot_claim_completed_coinbase_lifecycle(self):
        fixture={"kind":"two_input_two_output_coinbase_spend",
                 "economic_value_source":"fresh_repaired_v5_openings_requiring_action_11_lifecycle",
                 "artifact_alone_authorizes_production":False,
                 "requires_live_coinbase_carrier_lifecycle":True,
                 "economic_production_evidence":False,
                 "canonical_empty_note_root_hex":b"".join(word.to_bytes(8,"little") for word in check.policy.RP04_KNOWN_EMPTY_NOTE_GENESIS_ROOT).hex()}
        check.validate_fixture_authority(fixture,check.PROFILE)
        for key,value in [("economic_value_source","v8_coinbase_action_11"),
                          ("artifact_alone_authorizes_production",True),
                          ("requires_live_coinbase_carrier_lifecycle",False),
                          ("economic_production_evidence",True),
                          ("canonical_empty_note_root_hex",check.legacy.EXPECTED_FIXTURE["canonical_empty_note_root_hex"])]:
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
            with self.assertRaises(check.EvidenceError):
                check.require_complete_security_contract({"profile_wire_id":9,"domain_set":5},evidence)

    def test_q20_release_contract_is_not_modified(self):
        check.policy.require_release_profile_evidence_contract({"profile_wire_id":6,"domain_set":4})


class RecordedContractTests(unittest.TestCase):
    """Synthetic recorded metadata, never Lean execution or proof qualification."""

    def test_not_installed_source_contract_still_rejects_current_identity(self):
        # Keep the historical fail-closed assertion scoped to this test now
        # that the checkout has installed byte-pinned contract evidence.
        with patch.object(
            check.policy,
            "require_release_profile_evidence_contract",
            side_effect=check.policy.SuccessorAuthorizationError("not_installed sentinel fixture"),
        ):
            with self.assertRaisesRegex(check.policy.SuccessorAuthorizationError, "not_installed"):
                check.require_complete_security_contract(check.relation_identity(check.RP05_PROFILE))

    def test_current_installed_q38_contract_verifies_bytes_only(self):
        repo=Path(check.__file__).resolve().parents[1]
        self.assertEqual(
            check.rp05_contract.validate_q38_evidence_contract(repo),
            "source_pinned_evidence_bytes_verified",
        )

    def test_caller_supplied_and_historical_contract_subjects_rejected(self):
        for supplied in (True, False, {}, {"complete":True}):
            with self.assertRaisesRegex(check.EvidenceError, "caller-supplied"):
                check.require_complete_security_contract(check.relation_identity(check.RP05_PROFILE), supplied)
        for profile in (check.PROFILE, check.HISTORICAL_PROFILE):
            with self.assertRaisesRegex(check.EvidenceError, "exact current RP05"):
                check.require_complete_security_contract(check.relation_identity(profile))

    def endpoint_fixture(self, repo, *, target_only=False, target_only_diagnostics=False):
        module,theorem=check.ENDPOINTS["accepted_verifier_soundness"][0]
        root="HegemonCrypto.SmallWood."+module+"."+theorem
        repo.mkdir(parents=True,exist_ok=True)
        toolchain=repo.parent/"selected-lean-toolchain";toolchain.mkdir()
        self.recorded_roots=check.recorded_path_roots(repo,toolchain)
        def recorded(path):
            path=Path(path)
            for recorded_root,local_root in self.recorded_roots.items():
                try:relative=path.relative_to(local_root)
                except ValueError:continue
                return str(Path(recorded_root)/relative)
            raise AssertionError("fixture path outside mapped roots: "+str(path))
        source=repo/(module+".lean");source.write_bytes(b"-- synthetic metadata fixture; no theorem\n")
        obj=repo/(module+".olean");obj.write_bytes(b"not a Lean object")
        scratch_obj=repo/"scratch"/(module+".olean");scratch_obj.parent.mkdir()
        scratch_obj.write_bytes(obj.read_bytes())
        lean=toolchain/"bin"/"lean";lean.parent.mkdir();lean.write_bytes(b"not executable")
        runner=repo/"runner.py";runner.write_bytes(b"# not executed\n")
        audit_source=repo/".agent/prod-closure-2026-09-19/current-compiler/scratch/CurrentEndpointBodyAudit.lean"
        audit_source.parent.mkdir(parents=True)
        audit_source.write_bytes((Path(check.__file__).resolve().parents[1]/
            ".agent/prod-closure-2026-09-19/current-compiler/scratch/CurrentEndpointBodyAudit.lean").read_bytes())
        sha=lambda path:check.digest(path.read_bytes(),"sha256")
        compile_path=repo/"compile.json"
        compile_receipt={"module":module,"source":recorded(source),"source_sha256_pre":sha(source),
            "source_sha256_post":sha(source),"output_sha256":sha(obj),"exit_code":0,"diagnostic_probe":None,
            "lean":recorded(lean),"lean_sha256":sha(lean),
            "argv":[recorded(lean),"-DwarningAsError=true","-DautoImplicit=false","-o",recorded(scratch_obj),recorded(source)],
            "dependency_hashes_pre_post":{"pre":{recorded(source):sha(source),recorded(lean):sha(lean)},
                                           "post":{recorded(source):sha(source),recorded(scratch_obj):sha(scratch_obj)}}}
        if target_only:
            target_only_flags=["-j1","-M8192","-DwarningAsError=true","-DautoImplicit=false",
                "-DmaxHeartbeats=4000000"]
            if target_only_diagnostics:
                target_only_flags.extend(["-Ddiagnostics=true","-Ddiagnostics.threshold=100"])
            compile_receipt["argv"]=[recorded(lean),*target_only_flags,"-o",recorded(scratch_obj),recorded(source)]
            compile_log=repo/"target-only.log";compile_log.write_text("synthetic target-only fixture\n")
            compile_receipt.update(elapsed_seconds=1.0,log=recorded(compile_log),resource_limit={})
        else:
            compile_receipt.update(runner_script=recorded(runner),runner_sha256_pre=sha(runner),
                                   runner_sha256_post=sha(runner))
        compile_path.write_text(json.dumps(compile_receipt))
        audit_inputs=(source,obj,scratch_obj,lean,audit_source,compile_path) if target_only else (
            source,obj,scratch_obj,lean,runner,audit_source,compile_path)
        inputs={recorded(path):sha(path) for path in audit_inputs}
        fingerprint=check.digest(json.dumps(inputs,sort_keys=True,separators=(",",":")).encode(),"sha256")
        log=repo/"audit.log"
        log.write_text("module: "+module+"\nroots: "+root+"\ndeclarations traversed: 1\n"
                       "axioms: Quot.sound, Classical.choice, propext\nnonstandard axioms: \n"
                       "missing kernel constants: \nmissing theorem/opaque bodies: \nresult: PASS\n")
        audit={"module":module,"root":root,"exit_code":0,"all_search_path_objects_stable":True,
               "target_source_sha256":sha(source),"target_olean_sha256":sha(obj),
               "target_receipt_sha256":sha(compile_path),"input_hashes_pre":inputs,"input_hashes_post":inputs,
               "input_fingerprint_sha256_pre":fingerprint,"input_fingerprint_sha256_post":fingerprint,
               "argv":[recorded(lean),"--run",recorded(audit_source),module,root],"audit_source_sha256":sha(audit_source),
               "log":recorded(log),"log_sha256":sha(log)}
        audit_path=repo/"audit.json";audit_path.write_text(json.dumps(audit))
        def pin(path):
            raw=path.read_bytes()
            return {"path":str(path.relative_to(repo)),"bytes":len(raw),"sha512":check.digest(raw)}
        record={"module":module,"root":root,"source":pin(source),"object":pin(obj),
                "compile_receipt":pin(compile_path),"body_audit":pin(audit_path)}
        wrapper={"schema":check.GATE_SCHEMA,"gate":"accepted_verifier_soundness",
                 "identity":check.relation_identity(check.RP05_PROFILE),"scope":check.RECORDED_SCOPE,
                 "execution_receipts_authenticated":False,"production_authorized":False,
                 "source_inventory":{"test_only":True},"records":[record]}
        return wrapper,pin

    def validate_endpoint_gate(self, repo, wrapper):
        return check.validate_recorded_gate(repo,wrapper,"accepted_verifier_soundness",
            {"test_only":True},recorded_roots=self.recorded_roots)

    def test_synthetic_recorded_schema_consistency_only(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,_=self.endpoint_fixture(repo)
            # This accepts metadata only; the public entrypoint still requires
            # source-owned installed pins, absent from this temporary fixture.
            self.validate_endpoint_gate(repo,wrapper)
            self.assertFalse(wrapper["production_authorized"])
            self.assertFalse(wrapper["execution_receipts_authenticated"])

    def test_exact_target_only_receipt_without_runner_fields_is_accepted_as_metadata(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,_=self.endpoint_fixture(repo,target_only=True)
            self.validate_endpoint_gate(repo,wrapper)
            self.assertFalse(wrapper["production_authorized"])
            self.assertFalse(wrapper["execution_receipts_authenticated"])

    def test_exact_target_only_diagnostics_variant_is_accepted_as_metadata(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout"
            wrapper,_=self.endpoint_fixture(repo,target_only=True,target_only_diagnostics=True)
            self.validate_endpoint_gate(repo,wrapper)
            self.assertFalse(wrapper["production_authorized"])
            self.assertFalse(wrapper["execution_receipts_authenticated"])

    def test_partial_or_stale_runner_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,pin=self.endpoint_fixture(repo)
            path=repo/wrapper["records"][0]["compile_receipt"]["path"]
            original=path.read_bytes()
            for missing in ("runner_script","runner_sha256_pre","runner_sha256_post"):
                receipt=json.loads(original);del receipt[missing];path.write_text(json.dumps(receipt))
                bad=copy.deepcopy(wrapper);bad["records"][0]["compile_receipt"]=pin(path)
                with self.subTest(missing=missing),self.assertRaisesRegex(check.EvidenceError,"fields must be present together"):
                    self.validate_endpoint_gate(repo,bad)
            receipt=json.loads(original);receipt["runner_sha256_pre"]="0"*64
            path.write_text(json.dumps(receipt));bad=copy.deepcopy(wrapper)
            bad["records"][0]["compile_receipt"]=pin(path)
            with self.assertRaisesRegex(check.EvidenceError,"stale strict compiler driver"):
                self.validate_endpoint_gate(repo,bad)

    def test_target_only_shape_rejects_extra_flags_partial_metadata_and_kernel_skips(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,pin=self.endpoint_fixture(repo,target_only=True)
            path=repo/wrapper["records"][0]["compile_receipt"]["path"]
            original=path.read_bytes()
            for option in ("-Ddebug.skipKernelTC=true","-Ddebug.skipKernelEval=true","-DmaxRecDepth=2048"):
                receipt=json.loads(original);receipt["argv"].insert(1,option);path.write_text(json.dumps(receipt))
                bad=copy.deepcopy(wrapper);bad["records"][0]["compile_receipt"]=pin(path)
                with self.subTest(option=option),self.assertRaises(check.EvidenceError):
                    self.validate_endpoint_gate(repo,bad)
            path.write_bytes(original)
            receipt=json.loads(original);receipt["runner_script"]="/not/recorded.py"
            path.write_text(json.dumps(receipt));bad=copy.deepcopy(wrapper)
            bad["records"][0]["compile_receipt"]=pin(path)
            with self.assertRaisesRegex(check.EvidenceError,"fields must be present together"):
                self.validate_endpoint_gate(repo,bad)

    def test_recorded_root_remapping_is_exact_and_hash_preserving(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            base=Path(directory);repo=base/"checkout";repo.mkdir()
            toolchain=base/"lean-4.32.2";toolchain.mkdir()
            roots=check.recorded_path_roots(repo,toolchain)
            mapped=repo/"module.olean";mapped.write_bytes(b"pinned object")
            historical=check.RECORDED_REPO_ROOT+"/module.olean"
            check.current_hashes({historical:check.digest(mapped.read_bytes(),"sha256")},roots)
            with self.assertRaisesRegex(check.EvidenceError,"outside or ambiguous"):
                check.resolve_recorded_path(check.RECORDED_REPO_ROOT+"-evil/module.olean",roots)
            with self.assertRaisesRegex(check.EvidenceError,"outside or ambiguous"):
                check.current_hashes({"/unrecorded/toolchain/module.olean":"0"*64},roots)
            with self.assertRaises(FileNotFoundError):
                check.current_hashes({check.RECORDED_REPO_ROOT+"/missing.olean":"0"*64},roots)
            mapped.write_bytes(b"changed object")
            with self.assertRaisesRegex(check.EvidenceError,"stale recorded"):
                check.current_hashes({historical:check.digest(b"pinned object","sha256")},roots)
            outside=base/"outside";outside.write_bytes(b"outside")
            (repo/"linked.olean").symlink_to(outside)
            with self.assertRaisesRegex(check.EvidenceError,"symlink forbidden"):
                check.current_hashes({check.RECORDED_REPO_ROOT+"/linked.olean":check.digest(b"outside","sha256")},roots)

    def test_current_hashes_streams_complete_sparse_file_over_128_mib(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            base=Path(directory);repo=base/"repo";repo.mkdir()
            toolchain=base/"lean-4.32.2";toolchain.mkdir()
            roots=check.recorded_path_roots(repo,toolchain)
            large=repo/"large-import.olean";size=128*1024**2+17
            with large.open("wb") as stream:stream.truncate(size)
            expected=hashlib.sha256();zeroes=bytes(1024**2);remaining=size
            while remaining:
                chunk=min(remaining,len(zeroes));expected.update(zeroes[:chunk]);remaining-=chunk
            historical=check.RECORDED_REPO_ROOT+"/large-import.olean"
            check.current_hashes({historical:expected.hexdigest()},roots)
            with self.assertRaisesRegex(check.EvidenceError,"stale recorded"):
                check.current_hashes({historical:"0"*64},roots)

    def test_current_hashes_rejects_file_mutated_during_stream(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            base=Path(directory);repo=base/"repo";repo.mkdir()
            toolchain=base/"lean-4.32.2";toolchain.mkdir()
            roots=check.recorded_path_roots(repo,toolchain)
            source=repo/"mutable.olean";source.write_bytes(b"a"*4096)
            historical=check.RECORDED_REPO_ROOT+"/mutable.olean"
            original_sha256=hashlib.sha256
            changed=False

            class MutatingHasher:
                def __init__(self):self.inner=original_sha256()
                def update(self,chunk):
                    nonlocal changed
                    self.inner.update(chunk)
                    if not changed:
                        changed=True
                        with source.open("r+b") as stream:
                            stream.write(b"b");stream.flush()
                def hexdigest(self):return self.inner.hexdigest()

            with patch.object(check.hashlib,"sha256",MutatingHasher):
                with self.assertRaisesRegex(check.EvidenceError,"file changed during hash"):
                    check.current_hashes({historical:check.digest(b"a"*4096,"sha256")},roots)

    def test_recorded_endpoint_rejects_skip_kernel_compilation_options(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,pin=self.endpoint_fixture(repo)
            with self.assertRaisesRegex(check.EvidenceError,"exact recorded repository and Lean toolchain roots"):
                check.validate_recorded_gate(repo,wrapper,"accepted_verifier_soundness",{"test_only":True},
                    recorded_roots={check.RECORDED_REPO_ROOT:repo})
            path=repo/wrapper["records"][0]["compile_receipt"]["path"]
            original=path.read_bytes()
            for option in ("-Ddebug.skipKernelTC=true","-Ddebug.skipKernelEval=true"):
                receipt=json.loads(original);receipt["argv"].insert(1,option)
                path.write_text(json.dumps(receipt))
                bad=copy.deepcopy(wrapper);bad["records"][0]["compile_receipt"]=pin(path)
                with self.subTest(option=option),self.assertRaisesRegex(check.EvidenceError,"strict compile flags"):
                    self.validate_endpoint_gate(repo,bad)
            path.write_bytes(original)
            audit_path=repo/wrapper["records"][0]["body_audit"]["path"]
            audit_original=audit_path.read_bytes()
            audit=json.loads(audit_original);audit["argv"].insert(1,"-Ddebug.skipKernelTC=true")
            audit_path.write_text(json.dumps(audit))
            bad=copy.deepcopy(wrapper);bad["records"][0]["body_audit"]=pin(audit_path)
            with self.assertRaisesRegex(check.EvidenceError,"reviewed body audit program"):
                self.validate_endpoint_gate(repo,bad)
            audit_path.write_bytes(audit_original)

    def test_recorded_scratch_output_must_match_canonical_pinned_object(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,_=self.endpoint_fixture(repo)
            compile_path=repo/wrapper["records"][0]["compile_receipt"]["path"]
            receipt=json.loads(compile_path.read_bytes())
            output=check.resolve_recorded_path(receipt["argv"][receipt["argv"].index("-o")+1],
                                               self.recorded_roots)
            canonical=repo/wrapper["records"][0]["object"]["path"]
            self.assertNotEqual(output,repo/canonical)
            self.validate_endpoint_gate(repo,wrapper)
            output.write_bytes(b"substituted scratch OLean")
            with self.assertRaisesRegex(check.EvidenceError,"stale recorded|compile output"):
                self.validate_endpoint_gate(repo,wrapper)

    def test_absent_substituted_or_authorizing_record_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,_=self.endpoint_fixture(repo)
            for key,value in [("records",[]),("identity",check.relation_identity(check.PROFILE)),
                              ("production_authorized",True),("execution_receipts_authenticated",True),
                              ("scope","production"),("source_inventory",{})]:
                bad=copy.deepcopy(wrapper);bad[key]=value
                with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                    self.validate_endpoint_gate(repo,bad)
            bad=copy.deepcopy(wrapper);bad["records"][0]["root"]="Historical.q20_privacy"
            with self.assertRaisesRegex(check.EvidenceError,"endpoint root"):
                self.validate_endpoint_gate(repo,bad)
            bad=copy.deepcopy(wrapper);del bad["records"][0]["body_audit"]
            with self.assertRaises(check.EvidenceError):
                self.validate_endpoint_gate(repo,bad)

    def test_stale_or_resealed_source_object_and_audit_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,pin=self.endpoint_fixture(repo)
            for key in ("source","object","compile_receipt","body_audit"):
                record=wrapper["records"][0];path=repo/record[key]["path"]
                original=path.read_bytes();path.write_bytes(original+b" ")
                try:
                    with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                        self.validate_endpoint_gate(repo,wrapper)
                    if key != "body_audit":
                        bad=copy.deepcopy(wrapper);bad["records"][0][key]=pin(path)
                        with self.subTest(resealed=key),self.assertRaises(check.EvidenceError):
                            self.validate_endpoint_gate(repo,bad)
                finally:path.write_bytes(original)
            audit_path=repo/wrapper["records"][0]["body_audit"]["path"]
            audit=json.loads(audit_path.read_text());audit["root"]="Historical.q20_privacy"
            audit_path.write_text(json.dumps(audit))
            bad=copy.deepcopy(wrapper);bad["records"][0]["body_audit"]=pin(audit_path)
            with self.assertRaises(check.EvidenceError):
                self.validate_endpoint_gate(repo,bad)

    def test_record_descriptor_rejects_path_escape_and_missing_review(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)
            for name in ("../escape","/absolute","./file","nested/../file",
                         "nested/./file","nested//file","nested/", "nested\\file", ""):
                with self.assertRaises(check.EvidenceError):
                    check.pinned_record(repo,{"path":name,"bytes":0,"sha512":"0"*128})
            with self.assertRaisesRegex(check.EvidenceError,"review descriptor fields"):
                check.validate_recorded_artifact_review(repo,{}, {})

    def test_record_descriptor_rejects_symlink_parent_and_repository(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root=Path(directory);repo=root/"repo";repo.mkdir()
            actual=root/"actual";actual.mkdir();(actual/"receipt.json").write_bytes(b"{}")
            (repo/"linked").symlink_to(actual,target_is_directory=True)
            pin={"path":"linked/receipt.json","bytes":2,"sha512":check.digest(b"{}")}
            with self.assertRaisesRegex(check.EvidenceError,"symlink receipt ancestor"):
                check.pinned_record(repo,pin)
            linked_repo=root/"linked-repo";linked_repo.symlink_to(actual,target_is_directory=True)
            pin["path"]="receipt.json"
            with self.assertRaisesRegex(check.EvidenceError,"symlink receipt repository"):
                check.pinned_record(linked_repo,pin)

    def test_rp05_readback_explicitly_denies_production_authority(self):
        good={"production_eligible":False,"production_authorized":False}
        check.validate_rp05_readback_authority(good)
        for key in good:
            for value in (True,0,None):
                bad=dict(good);bad[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(check.EvidenceError):
                    check.validate_rp05_readback_authority(bad)
            bad=dict(good);del bad[key]
            with self.assertRaises(check.EvidenceError):
                check.validate_rp05_readback_authority(bad)

    def test_resealed_probe_nonstrict_compile_or_wrong_direct_import_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            repo=Path(directory)/"checkout";wrapper,pin=self.endpoint_fixture(repo)
            path=repo/wrapper["records"][0]["compile_receipt"]["path"]
            original=path.read_bytes()
            for key,value in [("diagnostic_probe","trace-only"),("exit_code",False),
                              ("argv",["lean","-DwarningAsError=false"]),
                              ("source_sha256_post","0"*64)]:
                receipt=json.loads(original);receipt[key]=value
                path.write_text(json.dumps(receipt))
                bad=copy.deepcopy(wrapper);bad["records"][0]["compile_receipt"]=pin(path)
                with self.subTest(key=key),self.assertRaises(check.EvidenceError):
                    self.validate_endpoint_gate(repo,bad)
            path.write_bytes(original)
            receipt=json.loads(original)
            extra=repo/"Unrelated.olean";extra.write_bytes(b"not an imported Lean object")
            for stage in ("pre","post"):
                receipt["dependency_hashes_pre_post"][stage][check.RECORDED_REPO_ROOT+"/Unrelated.olean"]=check.digest(extra.read_bytes(),"sha256")
            path.write_text(json.dumps(receipt))
            bad=copy.deepcopy(wrapper);bad["records"][0]["compile_receipt"]=pin(path)
            with self.assertRaisesRegex(check.EvidenceError,"direct-import set"):
                self.validate_endpoint_gate(repo,bad)


class GuardAndLifecycleTests(unittest.TestCase):
    def guard_fixture(self,path):
        path.write_bytes(b"manifest")
        inputs={str(path):check.digest(b"manifest","sha256"),"/native":"a"*64,"/guard":"d136760ee4c8f701df347f11aa58d3ab037d514625d33af556cda90d3275f4ce","/sandbox":"b"*64}
        binding={"candidate":str(path),"candidate_sha512":check.digest(b"manifest"),"native_binary":"/native","native_sha256":"a"*64,"native_sha512":"c"*128,"guard":"/guard","guard_sha256":inputs["/guard"]}
        config={"test_binding":{"mode":"inprocess","full_name":check.TESTS["inprocess"]},"inputs":inputs,"socket_binding":binding,"commands":[{"name":"inprocess","argv":["/usr/bin/sandbox-exec","-f","/sandbox","/native","--ignored","--exact",check.TESTS["inprocess"],"--nocapture","--test-threads=1"]}],"limits":{"wall_seconds":300,"child_stop_seconds":250,"peak_rss_bytes":8*1024**3,"scratch_bytes":1024**3,"minimum_free_bytes":20*1024**3,"max_sample_gap_seconds":5}}
        log=("test "+check.TESTS["inprocess"]+" ... ok\ntest result: ok. 1 passed; 0 failed;").encode()
        guard={"status":"PASS_DEVELOPMENT_ONLY","exit_code":0,"production_authorized":False,"config_sha256":"d"*64,"command":config["commands"][0],"preflight_inputs":inputs,"postflight_inputs":inputs,"execution":{"group_extinct":True,"leader_reaped_after_group_cleanup":True,"group_signals":[]},"active_reservations":[],"log_sha256":check.digest(log,"sha256"),"elapsed_seconds":1,"samples":[{"scratch_allocated_bytes":10,"free_bytes":21*1024**3,"waited_children_peak_rss_bytes":1000,"completed_sample_gap_seconds":0.1}]}
        return config,guard,log

    def use_guard_profile(self, config, guard, guard_sha):
        """Synthetic receipt metadata; no process execution is asserted."""
        binding=config["socket_binding"]
        del config["inputs"][binding["guard"]]
        binding["guard_sha256"]=guard_sha
        if guard_sha != check.HISTORICAL_GUARD_SHA256:
            binding["guard"]=str(Path(check.__file__).resolve().parents[1]/check.RP05_GUARD_SOURCE)
            guard.update(purpose="development-only",execution_receipts_authenticated=False,production_eligible=False)
        config["inputs"][binding["guard"]]=guard_sha
        rss,wall,child=check.REVIEWED_GUARD_LIMITS[guard_sha]
        config["limits"].update(peak_rss_bytes=rss,wall_seconds=wall,child_stop_seconds=child)
        if guard_sha == check.RP05_GUARD_SHA256:
            config["limits"]["child_stop_seconds"]=3400
        guard["preflight_inputs"]=copy.deepcopy(config["inputs"])
        guard["postflight_inputs"]=copy.deepcopy(config["inputs"])

    def test_guard_reviewed_profiles_and_hash_specific_caps(self):
        self.assertEqual(set(check.REVIEWED_GUARD_LIMITS),{check.HISTORICAL_GUARD_SHA256,check.RP05_GUARD_SHA256})
        source=Path(check.__file__).resolve().parents[1]/check.RP05_GUARD_SOURCE
        self.assertEqual(check.digest(check.read(source),"sha256"),check.RP05_GUARD_SHA256)
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"manifest.json"
            def validate(c,g,l):check.validate_guard(c,g,l,mode="inprocess",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))
            for guard_sha,(rss,wall,child) in check.REVIEWED_GUARD_LIMITS.items():
                config,guard,log=self.guard_fixture(path)
                self.use_guard_profile(config,guard,guard_sha)
                guard["elapsed_seconds"]=config["limits"]["child_stop_seconds"]-1
                guard["samples"][0]["owned_group_rss_bytes"]=rss-1024**3
                validate(config,guard,log)
                for key,value in [("peak_rss_bytes",rss+1),("wall_seconds",wall+1),("child_stop_seconds",child+1)]:
                    bad=copy.deepcopy(config);bad["limits"][key]=value
                    with self.subTest(guard=guard_sha,limit=key),self.assertRaises(check.EvidenceError):
                        validate(bad,guard,log)
                if guard_sha == check.RP05_GUARD_SHA256:
                    bad=copy.deepcopy(config);bad["limits"]["child_stop_seconds"]=3500
                    with self.assertRaisesRegex(check.EvidenceError,"cleanup time margin"):
                        validate(bad,guard,log)
                for key,value in [("owned_group_rss_bytes",rss+1),("waited_children_peak_rss_bytes",rss+1),
                                  ("scratch_allocated_bytes",1024**3+1),("free_bytes",20*1024**3-1),
                                  ("completed_sample_gap_seconds",5.1)]:
                    bad=copy.deepcopy(guard);bad["samples"][0][key]=value
                    with self.subTest(guard=guard_sha,sample=key),self.assertRaises(check.EvidenceError):
                        validate(config,bad,log)
            config,guard,log=self.guard_fixture(path)
            config["limits"].update(peak_rss_bytes=16*1024**3,wall_seconds=3600,child_stop_seconds=3500)
            with self.assertRaises(check.EvidenceError):validate(config,guard,log)
            config["socket_binding"]["guard_sha256"]="0"*64
            config["inputs"][config["socket_binding"]["guard"]]="0"*64
            guard["preflight_inputs"]=copy.deepcopy(config["inputs"])
            guard["postflight_inputs"]=copy.deepcopy(config["inputs"])
            with self.assertRaisesRegex(check.EvidenceError,"reviewed process guard"):
                validate(config,guard,log)

    def test_current_guard_keeps_scope_cleanup_and_source_bindings(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"manifest.json"
            def validate(c,g,l):check.validate_guard(c,g,l,mode="inprocess",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))
            for guard_sha in check.REVIEWED_GUARD_LIMITS.keys()-{check.HISTORICAL_GUARD_SHA256}:
                config,guard,log=self.guard_fixture(path);self.use_guard_profile(config,guard,guard_sha)
                for key,value in [("purpose","production"),("execution_receipts_authenticated",True),
                                  ("execution_receipts_authenticated",0),
                                  ("production_authorized",True),("production_eligible",True),
                                  ("samples",[]),("postflight_inputs",{})]:
                    bad=copy.deepcopy(guard);bad[key]=value
                    with self.subTest(key=key),self.assertRaises(check.EvidenceError):validate(config,bad,log)
                for key in ("purpose","execution_receipts_authenticated","production_eligible"):
                    bad=copy.deepcopy(guard);del bad[key]
                    with self.subTest(missing=key),self.assertRaises(check.EvidenceError):validate(config,bad,log)
                bad=copy.deepcopy(guard);bad["execution"]["group_extinct"]=False
                with self.assertRaises(check.EvidenceError):validate(config,bad,log)
                bad=copy.deepcopy(guard);bad["execution"]={}
                with self.assertRaises((check.EvidenceError,KeyError)):validate(config,bad,log)
                bad=copy.deepcopy(config);bad["socket_binding"]["guard"]="/copied-unreviewed-location.py"
                bad["inputs"][bad["socket_binding"]["guard"]]=guard_sha
                changed=copy.deepcopy(guard);changed["preflight_inputs"]=bad["inputs"];changed["postflight_inputs"]=bad["inputs"]
                with self.assertRaisesRegex(check.EvidenceError,"current guard source path"):
                    validate(bad,changed,log)

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

    def test_current_guard_socket_still_requires_pinned_isolated_wrapper(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"manifest.json"
            for guard_sha in check.REVIEWED_GUARD_LIMITS.keys()-{check.HISTORICAL_GUARD_SHA256}:
                config,guard,_=self.guard_fixture(path);self.use_guard_profile(config,guard,guard_sha)
                config["test_binding"]={"mode":"socket","full_name":check.TESTS["socket"]}
                config["inputs"].update({"/python":"1"*64,"/exec_socket.py":"2"*64})
                argv=["/usr/bin/sandbox-exec","-f","/sandbox","/python","-I","-B","/exec_socket.py"]
                config["commands"][0]["argv"]=argv
                guard["preflight_inputs"]=copy.deepcopy(config["inputs"]);guard["postflight_inputs"]=copy.deepcopy(config["inputs"])
                log=("test "+check.TESTS["socket"]+" ... ok\ntest result: ok. 1 passed; 0 failed;").encode()
                guard["log_sha256"]=check.digest(log,"sha256")
                def validate(c,g):check.validate_guard(c,g,log,mode="socket",config_sha256="d"*64,manifest_path=path,manifest_sha512=check.digest(b"manifest"))
                validate(config,guard)
                for altered in (argv[:4]+argv[5:],argv[:-1]+["/unreviewed.py"],argv+["--extra"],argv[3:]):
                    bad=copy.deepcopy(config);bad["commands"][0]["argv"]=altered
                    changed=copy.deepcopy(guard);changed["command"]=bad["commands"][0]
                    with self.subTest(argv=altered),self.assertRaises(check.EvidenceError):validate(bad,changed)

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
