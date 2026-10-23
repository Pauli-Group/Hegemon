#!/usr/bin/env python3
"""Focused offline identity/profile/authority regressions; fixtures grant no authority."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_private_spend_launch_authorization as policy


def manifest(profile="pre-mainnet", *, ongoing=True):
    return {
        "schema": "hegemon.native.network-manifest.v1",
        "profile": profile,
        "genesis_timestamp_ms": 1,
        "pow_bits": 0x207fffff,
        "rules_hash": ("0x" if ongoing else "") + "11" * 32,
        "launch_reference_rules_hash": ("0x" if ongoing else "") + "22" * 32,
        "funding_address": "public-fixture-only-not-a-native-address",
        "funding_subsidy_numerator": 1,
        "funding_subsidy_denominator": 5,
    }


def identity(profile="pre-mainnet", *, ongoing=True):
    public_manifest = manifest(profile, ongoing=ongoing)
    canonical = json.dumps(public_manifest, separators=(",", ":"), ensure_ascii=False).encode()
    value = dict(policy.ONGOING_FIXED if ongoing else policy.FIXED, chain_id="33" * 32, genesis_hash="44" * 32,
        manifest_digest=hashlib.sha512(b"hegemon.native.network-manifest.sha512.v1\0" + canonical).hexdigest(),
        relation_digest=policy.ONGOING_POLICY_RELATION if ongoing else policy.CURRENT_RUNTIME_RELATION, activation_height=1,
        deactivation_height_exclusive=None if ongoing else 1000,
        max_proof_bytes=2102936 if ongoing else 1931869, stablecoin_genesis_root=[0] * 7,
        note_genesis_root=[1] * 7, max_proof_actions_per_block=8,
        max_total_proofs=None if ongoing else 128,
        cryptographic_class=copy.deepcopy(policy.ONGOING_CRYPTOGRAPHIC_CLASS if ongoing else policy.CRYPTOGRAPHIC_CLASS))
    if ongoing:
        value.update(schema=policy.ONGOING_IDENTITY_SCHEMA, network_profile=profile,
                     relation_id=policy.ONGOING_POLICY_PROFILE["relation_id"], public_words=86)
    return value


def binding(value):
    schema, manifest_key, receipt_key = policy.release_binding_layout(value)
    result = {key: {} for key in (
        "assumptions", "gates", "pr205_contract", "runtime_predecessor", "formal_predecessor",
        "reviewed_runtime_delta", "runtime_delta_review", "runtime_inventory", "formal_inventory",
        "retained_binaries", "retained_proofs", manifest_key, receipt_key,
        "identity_native_binary", "authority_sources")}
    result.update(schema=schema, identity=value)
    if value.get("schema") == policy.ONGOING_IDENTITY_SCHEMA:
        result["ongoing_security_qualification"] = {}
        result["ongoing_policy_qualification"] = {}
    return result


def source_literal(value):
    # This fixture uses Rust's real Option spelling, not JSON null or a sentinel.
    def array(raw):
        return "[" + ", ".join(map(str, raw)) + "]"
    def optional(raw):
        return "None" if raw is None else f"Some({raw})"
    fields = ["kind: LaunchProofKind::PrivateSpend"]
    fields += [f"{key}: {array(bytes.fromhex(value[key]))}" for key in
               ("chain_id", "genesis_hash", "manifest_digest", "relation_digest")]
    fields += [f"activation_height: {value['activation_height']}",
               f"deactivation_height_exclusive: {optional(value['deactivation_height_exclusive'])}",
               f"max_proof_bytes: {value['max_proof_bytes']}",
               f"stablecoin_genesis_root: {array(value['stablecoin_genesis_root'])}",
               f"note_genesis_root: {array(value['note_genesis_root'])}",
               f"max_proof_actions_per_block: {value['max_proof_actions_per_block']}",
               f"max_total_proofs: {optional(value['max_total_proofs'])}"]
    return "const AUTHORIZED_LAUNCH_PROOF_CAPABILITIES: &[LaunchProofCapability] = &[LaunchProofCapability {\n" + ",\n".join(fields) + ",\n}];\n"


class NativeIdentityTests(unittest.TestCase):
    def test_ongoing_pre_mainnet_and_mainnet_are_distinct_valid_identities(self):
        for profile in ("pre-mainnet", "mainnet"):
            value = identity(profile)
            policy.identity_check(value)
            policy.network_manifest_check(manifest(profile), value)
            self.assertEqual(policy.identity_network_profile(value), profile)
        self.assertNotEqual(identity()["manifest_digest"], identity("mainnet")["manifest_digest"])

    def test_bounded_historical_identity_keeps_its_original_class(self):
        value = identity("mainnet", ongoing=False)
        policy.identity_check(value)
        policy.network_manifest_check(manifest("mainnet", ongoing=False), value)
        self.assertEqual(policy.release_binding_layout(value),
                         ("hegemon.private-spend.release-binding.v3", "mainnet_manifest", "mainnet_identity_receipt"))
        value["cryptographic_class"] = copy.deepcopy(policy.ONGOING_CRYPTOGRAPHIC_CLASS)
        with self.assertRaises(policy.Rejected):
            policy.identity_check(value)

    def test_null_options_cannot_be_mixed_with_bounded_values_or_sentinels(self):
        for field in ("deactivation_height_exclusive", "max_total_proofs"):
            for raw in (0, 1, 1000, (1 << 64) - 1, True, "None", "null"):
                with self.subTest(field=field, raw=raw):
                    value = identity(); value[field] = raw
                    with self.assertRaisesRegex(policy.Rejected, "explicit null"):
                        policy.identity_check(value)
            value = identity(); del value[field]
            with self.assertRaisesRegex(policy.Rejected, "keys mismatch"):
                policy.identity_check(value)
            value = identity("mainnet", ongoing=False); value[field] = None
            with self.assertRaisesRegex(policy.Rejected, "positive integer"):
                policy.identity_check(value)

    def test_schema_profile_and_unknown_fields_fail_closed(self):
        for field, raw in (("schema", "unknown"), ("network_profile", "development"),
                           ("network_profile", "PreMainnet"), ("network_profile", None),
                           ("development_candidate", {}), ("kind", "Rp06")):
            with self.subTest(field=field, raw=raw):
                value = identity(); value[field] = raw
                with self.assertRaises(policy.Rejected):
                    policy.identity_check(value)
        value = identity(); del value["schema"]
        with self.assertRaises(policy.Rejected):
            policy.identity_check(value)

    def test_per_action_limits_and_activation_remain_checked(self):
        for field, raw in (("activation_height", True), ("activation_height", 0),
                           ("activation_height", 1 << 63), ("max_proof_actions_per_block", 513),
                           ("max_proof_bytes", 2102937), ("max_proof_bytes", 0)):
            value = identity(); value[field] = raw
            with self.subTest(field=field, raw=raw), self.assertRaises(policy.Rejected):
                policy.identity_check(value)

    def test_historical_finite_bounds_are_not_widened(self):
        for field, raw in (("max_total_proofs", (1 << 21) + 1),
                           ("deactivation_height_exclusive", 1),
                           ("deactivation_height_exclusive", (1 << 64) - 1)):
            value = identity("mainnet", ongoing=False); value[field] = raw
            with self.subTest(field=field, raw=raw), self.assertRaises(policy.Rejected):
                policy.identity_check(value)

    def test_old_cryptographic_class_cannot_label_ongoing_identity(self):
        value = identity(); value["cryptographic_class"] = copy.deepcopy(policy.CRYPTOGRAPHIC_CLASS)
        with self.assertRaisesRegex(policy.Rejected, "cryptographic class"):
            policy.identity_check(value)

    def test_manifest_profile_relabel_or_development_authority_rejects(self):
        for profile in ("mainnet", "development"):
            with self.subTest(profile=profile), self.assertRaisesRegex(policy.Rejected, "profile differs"):
                policy.network_manifest_check(manifest(profile), identity())
        changed = manifest(); changed["development_candidate"] = {}
        with self.assertRaisesRegex(policy.Rejected, "keys mismatch"):
            policy.network_manifest_check(changed, identity())
        changed = manifest(); changed["genesis_timestamp_ms"] += 1
        with self.assertRaisesRegex(policy.Rejected, "manifest digest"):
            policy.network_manifest_check(changed, identity())

    def test_binding_formats_cannot_be_mixed(self):
        for value in (identity(), identity("mainnet", ongoing=False)):
            current = binding(value)
            policy.release_binding_check(current, value)
            current["mainnet_manifest" if value.get("schema") else "network_manifest"] = {}
            with self.assertRaisesRegex(policy.Rejected, "keys mismatch"):
                policy.release_binding_check(current, value)
        current = binding(identity()); del current["ongoing_security_qualification"]
        with self.assertRaisesRegex(policy.Rejected, "keys mismatch"):
            policy.release_binding_check(current, identity())

    def test_current86_relation_transport_and_maximum_are_exact(self):
        value = identity()
        policy.identity_check(value)
        self.assertEqual(value["circuit"], 12)
        self.assertEqual(value["max_proof_bytes"], 2102936)
        for field, raw in (("circuit", 11), ("public_words", 77), ("relation_id", policy.CURRENT_RELATION_ID),
                           ("relation_digest", policy.CURRENT_RUNTIME_RELATION)):
            changed = copy.deepcopy(value); changed[field] = raw
            with self.subTest(field=field), self.assertRaises(policy.Rejected):
                policy.identity_check(changed)
        current = binding(value); del current["ongoing_policy_qualification"]
        with self.assertRaises(policy.Rejected):
            policy.release_binding_check(current, value)
        changed = manifest(); changed["rules_hash"] = changed["rules_hash"][2:]
        with self.assertRaisesRegex(policy.Rejected, "canonical 0x prefix"):
            policy.network_manifest_check(changed, value)


class SourceAndReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.context = patch.object(policy, "ROOT", self.root)
        self.context.start(); self.addCleanup(self.context.stop)

    def write(self, relative, data):
        target = self.root / relative; target.parent.mkdir(parents=True, exist_ok=True)
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        target.write_bytes(raw)
        return {"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_native_registry_requires_exact_none_or_some_literals(self):
        for value in (identity(), identity("mainnet", ongoing=False)):
            self.write("protocol/versioning/src/launch_candidate.rs", source_literal(value).encode())
            policy.native_capability(value)
        value = identity()
        for changed in (source_literal(value).replace("deactivation_height_exclusive: None", "deactivation_height_exclusive: Some(1000)"),
                        source_literal(value).replace("max_total_proofs: None", "max_total_proofs: 0"),
                        source_literal(value).replace("max_total_proofs: None", "max_total_proofs: unlimited()"),
                        "const AUTHORIZED_LAUNCH_PROOF_CAPABILITIES: &[LaunchProofCapability] = &[];\n"):
            self.write("protocol/versioning/src/launch_candidate.rs", changed.encode())
            with self.assertRaisesRegex(policy.Rejected, "reviewed literal tuple"):
                policy.native_capability(value)

    def receipt_fixture(self, value):
        profile = policy.identity_network_profile(value)
        current = binding(value)
        _, manifest_key, receipt_key = policy.release_binding_layout(value)
        public_manifest = manifest(profile, ongoing=bool(value.get("schema")))
        current[manifest_key] = self.write("manifest.json", public_manifest)
        current["identity_native_binary"] = self.write("native.bin", b"fixture-not-executable")
        derived = {
            "schema": "hegemon.private-spend.native-identity.v2" if value.get("schema") else "hegemon.private-spend.mainnet-identity.v1",
            "identity": value,
            "manifest_sha256": current[manifest_key]["sha256"],
            "native_command": ["fixture-native-identity"],
            "native_executable_sha256": current["identity_native_binary"]["sha256"],
            "actual_output": self.write("native-output.txt", {
                "genesis_hash": "0x" + value["genesis_hash"],
                "node_config": {"networkManifest": public_manifest, "networkProfile": profile,
                    "chainId": "0x" + value["chain_id"], "networkManifestDigest": "0x" + value["manifest_digest"]},
                "private_spend_parameters": copy.deepcopy(policy.ONGOING_POLICY_PROFILE)}),
        }
        if value.get("schema"):
            derived["network_profile"] = profile
        current[receipt_key] = self.write("derived.json", derived)
        return current, derived, receipt_key

    def test_native_receipt_profiles_and_schemas_are_exact(self):
        for value in (identity(), identity("mainnet"), identity("mainnet", ongoing=False)):
            current, derived, receipt_key = self.receipt_fixture(value)
            self.assertEqual(policy.native_network_identity_check(current, value),
                             manifest(policy.identity_network_profile(value), ongoing=bool(value.get("schema"))))
            if value.get("schema"):
                for key, raw in (("network_profile", "development"), ("schema", "hegemon.private-spend.mainnet-identity.v1")):
                    changed = dict(derived); changed[key] = raw
                    current[receipt_key] = self.write("derived.json", changed)
                    with self.assertRaises(policy.Rejected):
                        policy.native_network_identity_check(current, value)

    def test_native_receipt_requires_unchanged_pinned_output(self):
        value = identity(); current, _, _ = self.receipt_fixture(value)
        self.write("native-output.txt", b"substituted")
        with self.assertRaisesRegex(policy.Rejected, "bytes changed"):
            policy.native_network_identity_check(current, value)

    def test_ongoing_security_authority_is_initially_closed(self):
        with patch.object(policy, "SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256", None):
            with self.assertRaisesRegex(policy.Rejected, "source-owned qualification pin"):
                policy.ongoing_security_qualification({"sha256": "ab" * 32})

    def test_preparation_or_old_class_cannot_be_promoted_by_a_pin_alone(self):
        receipt = {"schema": "hegemon.private-spend.ongoing-security-qualification.v1",
            "status": "QUALIFIED_CONDITIONAL", "qualified": True, "preparation_only": False,
            "production_authorized": False, "cryptographic_class": copy.deepcopy(policy.ONGOING_CRYPTOGRAPHIC_CLASS),
            "assumptions": list(policy.ASSUMPTIONS),
            "gate_coverage": ["G3", "G4", "G5"],
            "actual_checks": self.write("checks.json", {"fixture": True}),
            "independent_review": self.write("review.json", {"fixture": True})}
        for field, raw in (("qualified", False), ("preparation_only", True), ("production_authorized", True),
                           ("cryptographic_class", copy.deepcopy(policy.CRYPTOGRAPHIC_CLASS)),
                           ("gate_coverage", ["G5"])):
            changed = copy.deepcopy(receipt); changed[field] = raw
            descriptor = self.write("qualification.json", changed)
            with patch.object(policy, "SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256", descriptor["sha256"]):
                with self.subTest(field=field), self.assertRaises(policy.Rejected):
                    policy.ongoing_security_qualification(descriptor)

    def test_empty_production_registry_still_rejects(self):
        self.write(policy.REGISTRY, {"schema": "hegemon.private-spend.source-authorized-registry.v2", "release": None, "final_artifacts": []})
        with patch("sys.argv", ["checker", "--require-authorized"]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(policy.main(), 1)

    def test_ongoing_runtime_source_pin_stays_closed(self):
        with patch.object(policy, "SOURCE_ONGOING_RUNTIME_DELTA_REVIEW_SHA256", None):
            with self.assertRaisesRegex(policy.Rejected, "source-owned independent review"):
                policy.ongoing_runtime_source_closure(binding(identity()), identity())

    def test_current_policy_qualification_is_closed_and_development_cannot_promote(self):
        with patch.object(policy, "SOURCE_ONGOING_POLICY_QUALIFICATION_SHA256", None):
            with self.assertRaisesRegex(policy.Rejected, "source-owned security qualification"):
                policy.ongoing_policy_qualification({"sha256": "ab" * 32})
        development = self.write("development.json", {
            "schema": "hegemon.bounded-policy.completed-development-evidence.v1",
            "status": "DEVELOPMENT_PROOFS_FOCUSED_TESTS_AND_BOUNDED_LIFECYCLE_PASSED",
            "scope": "DEVELOPMENT_ONLY", "production_authorized": False})
        with patch.object(policy, "SOURCE_ONGOING_POLICY_QUALIFICATION_SHA256", development["sha256"]):
            with self.assertRaises(policy.Rejected):
                policy.ongoing_policy_qualification(development)

    def test_actual_native_parameters_cannot_reuse_old77_or_old_cap(self):
        policy.ongoing_native_parameters_check(copy.deepcopy(policy.ONGOING_POLICY_PROFILE))
        for field, raw in (("public_words", 77), ("relation_digest", policy.CURRENT_RUNTIME_RELATION),
                           ("relation_id", policy.CURRENT_RELATION_ID), ("max_carrier_bytes", 2102896),
                           ("max_proof_bytes", 1931869)):
            changed = copy.deepcopy(policy.ONGOING_POLICY_PROFILE); changed[field] = raw
            with self.subTest(field=field), self.assertRaises(policy.Rejected):
                policy.ongoing_native_parameters_check(changed)

    def test_capability_normalization_keeps_executable_logic(self):
        original = source_literal(identity())
        different_tuple = original.replace("activation_height: 1", "activation_height: 2")
        self.assertEqual(policy.normalized_capability_sha256(original), policy.normalized_capability_sha256(different_tuple))
        self.assertNotEqual(policy.normalized_capability_sha256(original),
                            policy.normalized_capability_sha256(original + "fn changed() {}"))
        with self.assertRaises(policy.Rejected):
            policy.normalized_capability_sha256(original + original)

    def test_obligations_require_unique_names_and_actual_pinned_field(self):
        descriptor = self.write("observation.json", {"actual": {"passed": True}})
        rows = [{"id": "observed", "mode": "retained", "passed": True, "evidence": [
            {"receipt": descriptor, "pointer": ["actual", "passed"], "expected": True}]}]
        policy.structured_obligations(rows, {"observed"}, "test", {"retained"})
        for changed in ([], rows + rows, [dict(rows[0], passed=False)], [dict(rows[0], mode="assumed")],
                        [dict(rows[0], evidence=[])], [dict(rows[0], id="different")]):
            with self.assertRaises(policy.Rejected):
                policy.structured_obligations(changed, {"observed"}, "test", {"retained"})
        for pointer, expected in ((["absent"], True), (["actual", "passed"], False), ([], True)):
            changed = copy.deepcopy(rows); changed[0]["evidence"][0].update(pointer=pointer, expected=expected)
            with self.assertRaises(policy.Rejected):
                policy.structured_obligations(changed, {"observed"}, "test", {"retained"})
        self.write("observation.json", {"actual": {"passed": False}})
        with self.assertRaisesRegex(policy.Rejected, "bytes changed"):
            policy.structured_obligations(rows, {"observed"}, "test", {"retained"})

    def composite_fixture(self):
        value = identity(); approved = manifest(); target = "fixture-target"
        artifacts = {name: "aa" * 32 for name in ("hegemon-node", "wallet", "walletd")}
        inventory = self.write("inventory.json", {"fixture": "not-source-authority"})
        observed = self.write("observed.json", {"observed": True})
        def obligations(names, mode="fresh"):
            return [{"id": name, "mode": mode, "passed": True, "evidence": [
                {"receipt": observed, "pointer": ["observed"], "expected": True}]} for name in sorted(names)]
        common = dict(final_identity=value, target_triple=target, artifact_sha256=artifacts,
                      runtime_inventory=inventory, evidence={"fixture": observed})
        tool = self.write("tool.bin", b"not-an-executable")
        external = dict(schema="hegemon.private-spend.actualnode.compff01.v1",
            status="PASS_LOCAL_EXTERNAL_TREASURY_NETWORK_LIFECYCLE", release_identity=value,
            artifact_sha256=artifacts, manifest=approved, genesis="0x" + value["genesis_hash"],
            treasury_spend_exercised=False, treasury_custody_status="operator_custody_rehearsed_not_spent",
            all_owned_exit0=True, all_owned_reaped=True, rpc_closed=True,
            proofs={case: {"case": case} for case in ("ordinary", "lock", "claim", "refund")},
            gates={gate: True for gate in policy.EXTERNAL_GATES | {"reward_maturity_wait"}},
            unexercised_release_checks=["treasury_payout", "treasury_single_key_payout",
                "treasury_single_key_payout_reorg_rollback", "treasury_single_key_payout_unchanged_resubmission"],
            binaries={"hegemon-node": {"sha256": artifacts["hegemon-node"]}, "private-spend": tool, "treasury-v8": tool},
            parameters=copy.deepcopy(policy.ONGOING_POLICY_PROFILE))
        current_files = {}
        external["proofs"] = {}
        external["actions"] = {}
        for name, case in policy.CURRENT_ACTION_CASES.items():
            proof = b"SMZDfixture-only-not-a-proof"
            carrier = bytearray(5784)
            carrier[:24] = b"HGPSLC02" + bytes.fromhex("01000c00070001000f000800020c0100")
            carrier[24:72] = bytes.fromhex(policy.ONGOING_POLICY_RELATION)[:48]
            carrier[72:104] = bytes.fromhex(value["chain_id"])
            carrier[104:136] = bytes.fromhex(value["genesis_hash"])
            carrier = bytes(carrier) + proof
            header = bytearray(104); header[52:56] = b"\x01\x00\x0f\x00"
            action_bytes = bytes(header) + b"\x00" * 4 + ((len(carrier) << 2) | 1).to_bytes(2, "little") + carrier + b"\x00" * 9
            current_files[name] = {"proof": self.write(name + ".smzd", proof),
                "carrier": self.write(name + ".hgps", carrier), "action": self.write(name + ".action", action_bytes)}
            external["proofs"][name] = dict(case=case, wallet_local_proof_verify=True, proof_bytes=len(proof),
                carrier_bytes=len(carrier), proof_sha512=hashlib.sha512(proof).hexdigest(),
                carrier_sha512=hashlib.sha512(carrier).hexdigest(), reference_parent_height=0,
                reference_parent_hash="0x" + value["genesis_hash"])
            external["actions"][name] = {"action_sha256": hashlib.sha256(action_bytes).hexdigest()}
        public = dict(common, schema="hegemon.hgn-single-key.treasury-public-output.v1", status="PASS_PUBLIC_OUTPUT",
            funding_address=approved["funding_address"], reward_height=1, maturity_blocks=120, first_spend_height=121,
            subsidy_atoms=500, treasury_atoms=100, miner_atoms=403, fees_atoms=3, output_position=1,
            opening={"asset_id": 0, "value": 100}, authorization_limbs=[1]*7, recipient_key=[2]*4,
            commitment=[3]*7, block_hash="ab"*32, action_sha256="ac"*32, canonical_body_sha256="ad"*32)
        readback = dict(status="PASS_PUBLIC_OUTPUT_NATIVE_READBACK", final_identity=value, runtime_inventory=inventory,
            observed={key: public[key] for key in ("funding_address", "reward_height", "block_hash", "action_sha256",
                "canonical_body_sha256", "output_position", "opening", "recipient_key", "authorization_limbs", "commitment")},
            commitment_recomputed=True, restart_fresh_node_match=True, producer=tool)
        public["native_readback"] = self.write("readback.json", readback)
        public_identity = {key: public[key] for key in ("funding_address", "recipient_key", "authorization_limbs")}
        restore = dict(status="PASS_EXACT_KEY_RESTORE", original_public_identity=public_identity,
                       restored_public_identity=public_identity, backup_artifact_sha256="ba"*32)
        custody = dict(restore, schema="hegemon.hgn-single-key.custody-restore.v1",
            funding_address=approved["funding_address"], restore_receipt=self.write("restore.json", restore),
            producer=tool, evidence={"fixture": observed})
        action = self.write("action.bin", b"fixture-only-action")
        disposable = dict(schema="hegemon.hgn-single-key.disposable-treasury-spend.v1", status="PASS_RETAINED_OBLIGATIONS",
            source_inventory=inventory, generation_receipt=observed,
            continuation_receipt=self.write("continuation.json", {"original_action_sha256": action["sha256"]}),
            action=action, proof_carrier=action, reward_evidence=observed, producer_binaries={"tool": tool},
            obligations=obligations(policy.DISPOSABLE_OBLIGATIONS, "retained"),
            unexercised=["wallet_readback", "fresh_node_sync"], evidence={"fixture": observed})
        components = {"external_lifecycle": external, "treasury_public_output": public,
                      "custody_restore": custody, "disposable_treasury_spend": disposable}
        pins = {key: self.write(key + ".json", component) for key, component in components.items()}
        bridge = dict(common, schema="hegemon.hgn-single-key.treasury-semantic-bridge.v1", status="PASS_SCOPED_SOURCE_BRIDGE",
            limitations=["schema fixture only; no production evidence"], deferred_scope=["fresh_two_of_three_approval_final"],
            source_rows=[dict(role=role, before=tool, after=tool, review=observed, comparison="identical",
                             affected_obligation_ids=["treasury_public_output"]) for role in sorted(policy.BRIDGE_ROLES)],
            independent_review=observed, obligation_map=obligations(policy.COMPOSITE_OBLIGATIONS),
            **{key: pins[key] for key in ("treasury_public_output", "custody_restore", "disposable_treasury_spend")})
        regressions = dict(common, schema="hegemon.hgn-single-key.policy-regressions.v1", status="PASS_AFFECTED_POLICY_REGRESSIONS",
            runs=[dict(exit_code=0, argv=["fixture"], source_inventory=inventory, test_names=["fixture"], passed_tests=1,
                       natural_exit=True, reaped=True, binary_sha256=tool["sha256"], stdout=observed, stderr=observed)],
            limitations=["fixture"], obligation_map=obligations(policy.POLICY_OBLIGATIONS))
        components.update(semantic_bridge=bridge, policy_regressions=regressions)
        pins.update({key: self.write(key + ".json", components[key]) for key in ("semantic_bridge", "policy_regressions")})
        wrapper = dict(schema=policy.COMPOSITE_SCHEMA, status="PASS_LOCAL_HGN_SINGLE_KEY_COMPOSITE",
            final_identity=value, artifact_sha256=artifacts, target_triple=target, manifest=approved,
            runtime_inventory=inventory, production_authorized=False, real_treasury_spend_exercised=False,
            current_proofs=current_files,
            deferred_scope=["fresh_two_of_three_approval_final"],
            legacy_gate_map={gate: ("deferred" if gate in policy.DEFERRED_GATES else
                "composed" if gate in {"treasury_payout", "treasury_canonical_value"} else "fresh") for gate in policy.LIFECYCLE_GATES}, **pins)
        return wrapper, components, (value, artifacts, approved, target, inventory)

    def test_composite_fixture_and_component_mutations(self):
        wrapper, components, args = self.composite_fixture()
        # Test only this validator's schema/pin checks; no fixture is source-authorized.
        with patch.object(policy, "_RETAINED_PATH_ALIAS_CACHE", {}):
            policy.composite_lifecycle_checks(wrapper, *args)
            for name, field, changed in (
                ("external_lifecycle", "treasury_spend_exercised", True),
                ("external_lifecycle", "all_owned_reaped", False),
                ("external_lifecycle", "proofs", {"ordinary": {"case": "ordinary"}}),
                ("treasury_public_output", "treasury_atoms", 101),
                ("treasury_public_output", "first_spend_height", 120),
                ("custody_restore", "restored_public_identity", {}),
                ("disposable_treasury_spend", "unexercised", []),
                ("semantic_bridge", "source_rows", []),
                ("policy_regressions", "runs", [])):
                current = copy.deepcopy(components[name]); current[field] = changed
                modified = copy.deepcopy(wrapper); modified[name] = self.write(name + "-mutated.json", current)
                with self.subTest(name=name, field=field), self.assertRaises(policy.Rejected):
                    policy.composite_lifecycle_checks(modified, *args)
            for field, changed in (("production_authorized", True), ("real_treasury_spend_exercised", True),
                                   ("target_triple", "wrong"), ("legacy_gate_map", {})):
                modified = copy.deepcopy(wrapper); modified[field] = changed
                with self.subTest(field=field), self.assertRaises(policy.Rejected):
                    policy.composite_lifecycle_checks(modified, *args)
            self.write("external_lifecycle.json", {"substituted": True})
            with self.assertRaisesRegex(policy.Rejected, "bytes changed"):
                policy.composite_lifecycle_checks(wrapper, *args)

    def test_current_carrier_rejects_old_route_context_and_unjoined_action(self):
        wrapper, components, args = self.composite_fixture()
        external = components["external_lifecycle"]
        policy.current_policy_proof_files(external["proofs"], wrapper["current_proofs"], external["actions"], args[0])
        original = (self.root / wrapper["current_proofs"]["claim"]["carrier"]["path"]).read_bytes()
        for offset, raw in ((0, b"HGPSLC01"), (10, b"\x0b\x00"), (24, bytes.fromhex(policy.CURRENT_RUNTIME_RELATION)[:48]),
                            (72, b"\xff" * 32)):
            changed = bytearray(original); changed[offset:offset + len(raw)] = raw
            descriptors = copy.deepcopy(wrapper["current_proofs"])
            descriptors["claim"]["carrier"] = self.write("wrong-carrier.hgps", bytes(changed))
            with self.subTest(offset=offset), self.assertRaises(policy.Rejected):
                policy.current_policy_proof_files(external["proofs"], descriptors, external["actions"], args[0])
        malformed = self.write("wrong-action.bin", b"not-an-action")
        descriptors = copy.deepcopy(wrapper["current_proofs"]); descriptors["claim"]["action"] = malformed
        actions = copy.deepcopy(external["actions"]); actions["claim"]["action_sha256"] = malformed["sha256"]
        with self.assertRaises(policy.Rejected):
            policy.current_policy_proof_files(external["proofs"], descriptors, actions, args[0])


class LifecycleIdentityTests(unittest.TestCase):
    def test_full_lifecycle_requires_exact_network_manifest_and_profile(self):
        for profile in ("pre-mainnet", "mainnet"):
            value = identity(profile); approved = manifest(profile)
            binaries = {name: "aa" * 32 for name in ("hegemon-node", "wallet", "walletd")}
            receipt = {"schema": "hegemon.private-spend.actualnode.compff01.v1", "status": "PASS_LOCAL_RELEASE_TUPLE",
                "release_identity": value, "artifact_sha256": binaries, "manifest": approved, "genesis": "0x" + value["genesis_hash"]}
            policy.release_lifecycle_identity_check(receipt, value, binaries, approved)
            for field, raw in (("status", "PASS_DEV_ONLY"), ("status", "PASS_LOCAL_EXTERNAL_TREASURY_NETWORK_LIFECYCLE"),
                               ("genesis", "0x" + "bb" * 32), ("manifest", manifest("development")),
                               ("artifact_sha256", {"hegemon-node": "cc" * 32})):
                changed = copy.deepcopy(receipt); changed[field] = raw
                with self.subTest(profile=profile, field=field, raw=raw), self.assertRaises(policy.Rejected):
                    policy.release_lifecycle_identity_check(changed, value, binaries, approved)
            changed = copy.deepcopy(receipt); changed["manifest"]["pow_bits"] += 1
            with self.assertRaises(policy.Rejected):
                policy.release_lifecycle_identity_check(changed, value, binaries, approved)


if __name__ == "__main__":
    unittest.main()
