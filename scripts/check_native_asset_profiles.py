#!/usr/bin/env python3
"""Actual Development asset profile/predicate supplement.

Preparation starts no processes. The coordinator executes after the frozen
runtime build. --with-main-lifecycle adds the supplement to one fresh complete
lifecycle run, preserving every failed earlier run and its exact artifacts.
"""

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/check_native_asset_lifecycle.py"
spec = importlib.util.spec_from_file_location("native_asset_lifecycle_frozen", HELPER)
live = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = live
spec.loader.exec_module(live)
require, rpc = live.require, live.rpc

GATES = ["ordinary-depth8-live", "ordinary-depth16-live", "bounded-depth8-live",
         "bounded-depth16-cheap-rejection", "mint-disabled-current-valid-credentials",
         "current-valid-wrong-subject-credentials", "freeze-enabled-mint-and-valid-both-branches",
         "bounded-height-hash-release-negatives"]

ERROR_SOURCE_PATHS = ["wallet/src/asset_spend_store.rs", "wallet/src/asset_spend_rpc.rs",
    "wallet/src/asset_spend_v1.rs", "wallet/src/poseidon2_v8_sync.rs", "wallet/src/poseidon2_v8_launch_sync.rs",
    "wallet/src/store.rs", "wallet/src/private_spend.rs", "wallet/src/private_spend_rpc.rs",
    "wallet/src/error.rs", "walletd/src/asset.rs", "circuits/transaction/src/asset_spend_v1_admission.rs"]

UNSUPPORTED_PROFILE_DISPLAY = "native asset admission: UnsupportedProfile"
UNSUPPORTED_PROFILE_ROUTES = frozenset({
    ("internal_error", UNSUPPORTED_PROFILE_DISPLAY),
    ("transaction_failed", "asset native profile is unsupported"),
})
RELATION_CONSTRUCTION_ROUTE = ("transaction_failed", "asset relation rejected construction")
CURRENT_ACCOUNTING_ROUTE = ("transaction_failed", "asset current accounting policy")
NEGATIVE_EXPECTED_ROUTES = {
    **{"current-root-wrong-owner-slot-" + str(slot): frozenset({RELATION_CONSTRUCTION_ROUTE}) for slot in range(3)},
    **{label: frozenset({RELATION_CONSTRUCTION_ROUTE}) for label in (
        "current-root-wrong-recipient", "bounded8-before-height", "bounded8-wrong-hash-preimage")},
    **{label: frozenset({CURRENT_ACCOUNTING_ROUTE}) for label in (
        "frozen-current-enabled-mint", "frozen-current-valid-branch-0", "frozen-current-valid-branch-1",
        "mint-disabled-current-valid-credentials")},
    **{label: frozenset({RELATION_CONSTRUCTION_ROUTE}) for label in (
        "bounded-before-height", "bounded-disabled-branch", "old-credential-witness")},
    **{label: frozenset({CURRENT_ACCOUNTING_ROUTE}) for label in (
        "frozen-mint", "frozen-transfer", "frozen-burn", "frozen-bounded-create",
        "frozen-bounded-primary", "frozen-bounded-fallback")},
    "missing-current-zero-change-credential": frozenset({
        ("transaction_failed", "asset credential depth mismatch")}),
    # This exact walletd API rejects before reaching the library fallback.
    "bounded16-before-reservation": frozenset({("internal_error", UNSUPPORTED_PROFILE_DISPLAY)}),
}


def typed_error_categories():
    """Allow one unit variant's exact Display, anchored to its source route."""
    relative = "circuits/transaction/src/asset_spend_v1_admission.rs"
    text = (ROOT / relative).read_text()
    anchors = ["pub enum NativeAssetAdmissionErrorV1 {\n    UnsupportedProfile,",
               'write!(f, "native asset admission: {self:?}")',
               "_ => return Err(NativeAssetAdmissionErrorV1::UnsupportedProfile)"]
    require(all(anchor in text for anchor in anchors), "typed unsupported-profile diagnostic source changed")
    sources = [{"file": relative, "line": text.count("\n", 0, text.index(anchor)) + 1} for anchor in anchors]
    daemon_path = "walletd/src/asset.rs"
    daemon = (ROOT / daemon_path).read_text()
    route = ("transaction_circuit::asset_spend_v1_admission::spend_profile_upper_bound_v1(\n"
             "        u8::from(policy.create == 1 || policy.spend == 1),\n"
             "        authenticated.row().credential_depth,\n    )\n    .map_err(WalletdError::internal)?;")
    require(route in daemon, "wallet unsupported-profile diagnostic route changed")
    sources.append({"file": daemon_path, "line": daemon.count("\n", 0, daemon.index(route)) + 1})
    return {UNSUPPORTED_PROFILE_DISPLAY: sources}


def static_error_categories():
    """Extract literal error arguments only, never format strings or values."""
    literal = r'("(?:[^"\\]|\\.)*")'
    patterns = [r'\b(?:invalid|WalletError::(?:InvalidState|InvalidArgument))\(\s*' + literal,
                r'WalletdError::new\(\s*WalletdErrorCode::\w+\s*,\s*' + literal,
                r'#\[error\(\s*' + literal,
                r'const\s+PRODUCTION_DISABLED\s*:\s*&str\s*=\s*' + literal]
    categories = {}
    for relative in ERROR_SOURCE_PATHS:
        # Test-only items can be interleaved with later runtime impl blocks;
        # extract only error-constructor literals throughout the source.
        text = (ROOT / relative).read_text()
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                try:
                    message = json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
                if 8 <= len(message) <= 512 and all(ord(c) >= 32 for c in message) and not any(c in message for c in "{}"):
                    categories.setdefault(message, []).append({"file": relative,
                        "line": text.count("\n", 0, match.start()) + 1})
    return categories


STATIC_ERROR_SOURCES = static_error_categories()
TYPED_ERROR_SOURCES = typed_error_categories()


def safe_reason(message):
    # Persist only constant source-owned categories, never arbitrary diagnostics.
    if isinstance(message, str) and message in TYPED_ERROR_SOURCES:
        return message
    lowered = str(message).lower()
    for known in sorted(STATIC_ERROR_SOURCES, key=lambda item: (-len(item), item)):
        if known.lower() in lowered:
            return known
    return "unclassified wallet failure; raw diagnostics not retained"


def is_unsupported_profile_rejection(code, category):
    return isinstance(code, str) and isinstance(category, str) and (code, category) in UNSUPPORTED_PROFILE_ROUTES


def expected_negative_routes(label, cheap):
    require(isinstance(label, str) and label in NEGATIVE_EXPECTED_ROUTES,
            "supplemental negative label has no source-owned expected route")
    require(type(cheap) is bool and cheap == (label == "bounded16-before-reservation"),
            "supplemental negative label has inconsistent cheap profile flag")
    return NEGATIVE_EXPECTED_ROUTES[label]


def is_expected_negative_rejection(label, cheap, code, category):
    allowed = expected_negative_routes(label, cheap)
    return isinstance(code, str) and isinstance(category, str) and (code, category) in allowed


class PublicWalletRejected(live.WalletRejected):
    def __init__(self, method, code, reason):
        super().__init__(method, code)
        self.public_reason = reason
        self.public_error_sources = TYPED_ERROR_SOURCES.get(reason, STATIC_ERROR_SOURCES.get(reason, []))
        self.args = (f"{method} rejected: {code}; {reason}",)


def rejected_journal_delta(before, after, cheap=False):
    """Permit only harmless new tombstones; preserve every existing entry."""
    def indexed(rows):
        require(isinstance(rows, list), "asset journal must be an array")
        result = {}
        for row in rows:
            require(isinstance(row, dict) and set(row) == {
                "id", "status", "parent_height", "action_id", "mined_in", "inputs_reserved"},
                "asset journal view shape changed")
            identity = row["id"]
            require(isinstance(identity, list) and len(identity) == 32
                    and all(type(word) is int and 0 <= word <= 255 for word in identity),
                    "asset journal reservation identity invalid")
            key = tuple(identity)
            require(key not in result, "duplicate reservation in asset journal")
            result[key] = row
        return result
    original, current = indexed(before), indexed(after)
    require(all(current.get(key) == row for key, row in original.items()),
            "rejected operation changed an existing reservation")
    added = [row for key, row in current.items() if key not in original]
    if cheap:
        require(before == after, "cheap profile rejection changed reservation journal")
    else:
        require(all(row["status"] == "Abandoned" and row["inputs_reserved"] is False
                    and row["action_id"] == [] and row["mined_in"] is None for row in added),
                "rejected operation retained a new active reservation or submitted action")
    return added


def wallet_request(binary, store, phrase, method, params, environment, timeout, guard, create=False):
    """Real bounded walletd stdio; private input and raw stderr stay in memory."""
    require(isinstance(phrase, bytes) and phrase and b"\n" not in phrase and b"\r" not in phrase,
            "passphrase framing mismatch")
    request = json.dumps({"id": 101, "method": method, "params": params}, separators=(",", ":")).encode()
    require(len(request) <= live.MAX_WALLETD_REQUEST_BYTES, "wallet request exceeds exact daemon bound")
    payload = phrase + b"\n" + request + b"\n"
    child = subprocess.Popen([str(binary), "--store", str(store), "--mode", "create" if create else "open"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, env=environment, close_fds=True)
    output, diagnostic, sent = bytearray(), bytearray(), 0
    readers, writer = [child.stdout, child.stderr], child.stdin
    os.set_blocking(writer.fileno(), False)
    deadline = time.monotonic() + timeout
    try:
        while readers or writer is not None:
            guard()
            require(time.monotonic() < deadline, "wallet operation deadline exceeded")
            readable, writable, _ = select.select(readers, [writer] if writer is not None else [], [], 0.1)
            if writable:
                try:
                    count = os.write(writer.fileno(), payload[sent:sent + 65536]); sent += count
                except BrokenPipeError:
                    count = 0
                if sent == len(payload) or count == 0:
                    writer.close(); writer = None
            for stream in readable:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk: readers.remove(stream)
                elif stream is child.stdout: output += chunk
                else: diagnostic += chunk
                require(len(output) <= live.MAX_WALLETD_RESPONSE_BYTES and len(diagnostic) <= live.MAX_DIAGNOSTIC_BYTES,
                        "wallet output exceeds bound")
        code = child.wait(timeout=5)
        require(sent == len(payload) and phrase not in output and phrase not in diagnostic,
                "wallet input incomplete or passphrase echoed")
        lines = output.splitlines()
        require(len(lines) == 1, "wallet response must be one JSON line")
        response = json.loads(lines[0])
        require(isinstance(response, dict) and response.get("id") == 101 and type(response.get("ok")) is bool,
                "wallet response identity mismatch")
        if not response["ok"]:
            raise PublicWalletRejected(method, response.get("error_code"), safe_reason(response.get("error")))
        require(code == 0 and response.get("error") is None and response.get("error_code") is None and "result" in response,
                "wallet process/response disagree")
        return response["result"]
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait()
        if writer is not None: writer.close()
        child.stdout.close(); child.stderr.close()


class ProfileRun(live.NativeLifecycle):
    def __init__(self, args):
        super().__init__(args)
        self.receipt["schema"] = "hegemon.native-asset.actual-profile-supplement.v1"
        self.receipt["with_main_lifecycle"] = args.with_main_lifecycle
        self.receipt["sources"].append(live.file_record(__file__))
        pinned = {row["path"] for row in self.receipt["sources"]}
        self.receipt["sources"] += [live.file_record(ROOT / p) for p in ERROR_SOURCE_PATHS
                                    if str(ROOT / p) not in pinned]
        self.receipt["safe_error_diagnostics"] = {"static_categories": len(STATIC_ERROR_SOURCES),
            "typed_categories": sorted(TYPED_ERROR_SOURCES), "typed_categories_require_exact_display": True,
            "longest_matching_literal_only": True, "sources": ERROR_SOURCE_PATHS,
            "raw_error_values_persisted": False}
        self.receipt["negative_expected_error_routes"] = {label: [list(route) for route in sorted(routes)]
                                                         for label, routes in NEGATIVE_EXPECTED_ROUTES.items()}
        self.receipt["requested_gates"] = (self.receipt["requested_gates"] if args.with_main_lifecycle else []) + GATES
        self.receipt["supplemental_proof_plan"] = {"asset_proofs": 4, "controls_proofs": 5,
                                                  "profiles": [[0, 8], [0, 16], [1, 8]],
                                                  "bounded16_proofs_requested": 0}
        if args.with_main_lifecycle:
            self.receipt["projected_full_run_proofs"] = {"asset_ordinary": 13, "asset_bounded": 7,
                "native_ordinary": 4, "controls_admin": 11, "total": 35,
                "scope": "planned retained real proofs, including rejected stale/conflicting candidates"}
        self.save()

    def wait(self, condition, label, timeout=600):
        # Actual cold canonical replay can exceed180s; the whole-run cap remains.
        return super().wait(condition, label, max(600, timeout))

    def w(self, actor, method, params=None, create=False, store=None):
        self.current = method
        return wallet_request(self.args.walletd, store or self.stores[actor], self.phrases[actor], method,
                              params or {}, self.env, self.args.proof_timeout, self.guard, create)

    def params(self, operation="transfer", amount=1, credentials=None, policy=None, position=None):
        result = super().params(operation, amount, credentials, policy, position)
        if operation == "mint":
            result["credentials"][0] = {"index": 0, "expires_at": 0,
                "siblings": [[0] * 7 for _ in self.cred[0]["siblings"]]}
        return result

    def tree(self, entries, depth):
        return self.w(0, "asset.credentials", {"asset_id": 17, "policy_version": 1, "depth": depth,
                      "entries": [dict(entry, expires_at=9000) for entry in entries]})

    def use_tree(self, name, tree, **controls):
        self.admin(name, dict(credential_root=tree["credential_root"], credential_depth=tree["credential_depth"], **controls))
        self.cred = [entry["witness"] for entry in tree["entries"]]

    def denied(self, label, params, cheap=False):
        # Reject unknown labels before sync, reservations or any wallet call.
        expected_negative_routes(label, cheap)
        self.sync()
        before, journal, proofs = self.snap(), self.w(0, "asset.journal"), len(self.proofs)
        notes, balances = self.w(0, "asset.notes"), self.w(0, "asset.balances")
        try:
            self.w(0, "asset.prepare", params)
        except PublicWalletRejected as error:
            require(self.snap() == before, "rejected supplemental operation changed canonical state")
            current = self.w(0, "asset.journal")
            added = rejected_journal_delta(journal, current, cheap)
            require(self.w(0, "asset.notes") == notes and self.w(0, "asset.balances") == balances,
                    "rejected supplemental operation changed or locked an owned note")
            # Journal views omit action bytes. Probe the actual exact export
            # API for every tolerated new tombstone rather than inferring.
            for row in added:
                try:
                    self.w(0, "asset.export", {"reservation_id": bytes(row["id"]).hex()})
                except PublicWalletRejected as export_error:
                    require(export_error.public_reason == "asset candidate absent",
                            "new rejected reservation export failed for unrelated reason")
                else:
                    raise live.AcceptanceError("rejected reservation retained exportable proof/action bytes")
            require(len(self.proofs) == proofs, "negative supplemental operation retained a proof")
            matches_expected = is_expected_negative_rejection(label, cheap, error.code, error.public_reason)
            self.receipt.setdefault("supplemental_rejections", []).append({"name": label, "code": error.code,
                "qualifies_expected_predicate": matches_expected,
                "public_reason": error.public_reason, "canonical_state_unchanged": True,
                "public_error_sources": error.public_error_sources,
                "reservation_journal_unchanged": current == journal, "existing_reservations_unchanged": True,
                "new_abandoned_records": len(added), "new_active_reservations": 0, "owned_note_locks_unchanged": True,
                "new_exportable_proof_or_action_bytes": False, "cheap_pre_reservation_rejection": cheap})
            self.save()
            require(matches_expected, "supplemental negative rejected through unrelated error route: " + label)
            return
        raise live.AcceptanceError("negative supplemental operation unexpectedly proved: " + label)

    def wallet_reject(self, name, params):
        # Main lifecycle negatives receive the same predicate-specific route
        # and reservation invariants as the supplemental negative cases.
        return self.denied(name, params)

    def profile_cases(self, entries):
        # A current valid leaf with the SAME recipient but another full owner.
        entries = [dict(entry) for entry in entries[:2]]
        entries.append({"index": 2, "recipient": self.addresses[0]["address"], "owner": self.addresses[1]["authority"]})
        tree8 = self.tree(entries, 8)
        self.use_tree("supplement-depth8-enable-mint", tree8, mint_enabled=True, frozen=False)
        for slot in range(3):
            wrong = [self.cred[0]] * 3; wrong[slot] = self.cred[2]
            self.denied("current-root-wrong-owner-slot-" + str(slot), self.params(amount=1, credentials=wrong))
        # Another recipient's otherwise current, valid witness must also fail.
        wrong = [self.cred[0], self.cred[1], self.cred[0]]
        self.denied("current-root-wrong-recipient", self.params(amount=1, credentials=wrong))
        self.mark("current-valid-wrong-subject-credentials", credential_root=tree8["credential_root"],
                  valid_current_path_wrong_full_owner_slots=[0, 1, 2], valid_current_path_wrong_recipient=True)
        ordinary8 = self.build("supplement-ordinary-depth8", amount=1)
        require(ordinary8[0]["public_statement"][40] == 8 and ordinary8[0]["public_statement"][124] == 0,
                "ordinary8 selected wrong graph")
        self.include(*ordinary8)
        self.mark("ordinary-depth8-live", inclusion=ordinary8[0]["inclusion"], inner_proof_bytes=ordinary8[0]["proof_bytes"])
        tree16 = self.tree(entries, 16)
        self.use_tree("supplement-depth16", tree16)
        ordinary16 = self.build("supplement-ordinary-depth16", amount=1)
        require(ordinary16[0]["public_statement"][40] == 16 and ordinary16[0]["public_statement"][124] == 0,
                "ordinary16 selected wrong graph")
        # Actual current ordinary16 proof is reused only as rejected framing;
        # the unsupported mode/depth pair is rejected before graph/proof parse.
        policy = {"nullifier_key": [secrets.randbelow(live.GOLDILOCKS - 1) + 1 for _ in range(5)],
                  "branches": [{"enabled": 1, "authority": self.addresses[0]["authority"]}, {}]}
        self.denied("bounded16-before-reservation", self.params(amount=1, policy={"create": 1, "output": policy}), True)
        parsed = live.inspect_asset_carrier(ordinary16[1]); unsupported = bytearray(ordinary16[1])
        at = parsed["public_offset"] + 124 * 8; unsupported[at:at + 8] = (1).to_bytes(8, "little")
        self.reject("bounded16-native-cheap-profile-gate", self.req(bytes(unsupported)))
        self.mark("bounded-depth16-cheap-rejection", no_bounded16_proof_requested=True,
                  wallet_journal_unchanged=True, current_parent_rpc_rejected_on_both_nodes=True,
                  preflight_source="walletd/src/asset.rs early spend_profile_upper_bound_v1 maps UnsupportedProfile through WalletdError::internal before the persistent builder/reservation; native decoder checks mode/depth before SMZE",
                  wallet_typed_error_display=UNSUPPORTED_PROFILE_DISPLAY,
                  wallet_typed_error_sources=TYPED_ERROR_SOURCES[UNSUPPORTED_PROFILE_DISPLAY])
        self.include(*ordinary16)
        self.mark("ordinary-depth16-live", inclusion=ordinary16[0]["inclusion"], inner_proof_bytes=ordinary16[0]["proof_bytes"])
        secret = bytearray(secrets.token_bytes(32)); secret[-1] |= 0x80; secret = bytes(secret)
        boundary = self.status()[0] + 6
        branch = {"enabled": 1, "authority": self.addresses[0]["authority"], "not_before": boundary,
                  "hash_required": 1, "hashlock": list(hashlib.sha256(secret).digest()), "release_secret": 1}
        policy = {"nullifier_key": [secrets.randbelow(live.GOLDILOCKS - 1) + 1 for _ in range(5)],
                  "branches": [dict(branch), dict(branch)]}
        owner = self.w(0, "asset.policyOwner", {"chain_id": self.chain, "asset_id": 17, "policy": policy})["owner"]
        entries.append({"index": 3, "recipient": self.addresses[0]["address"], "owner": owner})
        bounded_tree = self.tree(entries, 8)
        self.use_tree("supplement-bounded8-credential", bounded_tree)
        lock = self.build("supplement-bounded-depth8-lock", amount=25,
                          credentials=[self.cred[0], self.cred[3], self.cred[0]], policy={"create": 1, "output": policy})
        require(lock[0]["public_statement"][40] == 8 and lock[0]["public_statement"][124] == 1,
                "bounded8 lock selected wrong graph")
        self.include(*lock)
        position = next(note["position"] for note in lock[0]["outputs"] if note["script_owned"])
        opening = {"spend": 1, "input": policy, "selected": [1, 0], "secret": list(secret)}
        self.denied("bounded8-before-height", self.params(amount=25,
                    credentials=[self.cred[3], self.cred[0], self.cred[0]], policy=opening, position=position))
        self.mine(boundary); self.converge(); self.sync()
        wrong_secret = json.loads(json.dumps(opening)); wrong_secret["secret"][0] ^= 1
        self.denied("bounded8-wrong-hash-preimage", self.params(amount=25,
                    credentials=[self.cred[3], self.cred[0], self.cred[0]], policy=wrong_secret, position=position))
        # Freeze is the only changed predicate: both branches enabled, same
        # owned authority, reached height, correct hash/release, current certs.
        require(all(b["enabled"] == 1 and b["not_before"] <= self.status()[0]
                    and b["authority"] == self.addresses[0]["authority"]
                    and bytes(b["hashlock"]) == hashlib.sha256(secret).digest() for b in policy["branches"]),
                "freeze test branches are not independently eligible")
        require(self.row()["mint_enabled"] is True and self.row()["frozen"] is False, "mint must be enabled before isolated freeze")
        self.admin("supplement-freeze-enabled-mint", {"frozen": True})
        self.denied("frozen-current-enabled-mint", self.params("mint", credentials=[
                    {"index": 0, "expires_at": 0, "siblings": [[0] * 7 for _ in range(8)]}, self.cred[0], self.cred[0]]))
        for selected in ([1, 0], [0, 1]):
            current = dict(opening, selected=selected)
            self.denied("frozen-current-valid-branch-" + str(selected.index(1)), self.params(amount=25,
                        credentials=[self.cred[3], self.cred[0], self.cred[0]], policy=current, position=position))
        self.mark("freeze-enabled-mint-and-valid-both-branches", depth=8, enabled_mint=True,
                  both_branches_enabled_height_reached_authority_owned_hash_correct=True,
                  current_credentials_preserved=True, freeze_only_blocking_control=True)
        self.admin("supplement-unfreeze-disable-mint", {"frozen": False, "mint_enabled": False})
        self.denied("mint-disabled-current-valid-credentials", self.params("mint", credentials=[
                    {"index": 0, "expires_at": 0, "siblings": [[0] * 7 for _ in range(8)]}, self.cred[0], self.cred[0]]))
        self.mark("mint-disabled-current-valid-credentials", unfrozen=True, current_padded_credentials=True,
                  issuer_unchanged=True, valid_issuer_secret_supplied=True)
        spend = self.build("supplement-bounded-depth8-spend", amount=25,
                           credentials=[self.cred[3], self.cred[0], self.cred[0]], policy=opening, position=position)
        parsed = live.inspect_asset_carrier(spend[1])
        require(parsed["released_secret_hex"] == secret.hex(), "actual bounded8 proof did not disclose all256 bits")
        omitted = bytearray(spend[1]); start = parsed["public_offset"] + 125 * 8
        omitted[start:start + 9 * 8] = bytes(9 * 8)
        self.reject("bounded8-required-release-omitted", self.req(bytes(omitted)))
        changed = bytearray(spend[1]); start = parsed["public_offset"] + 133 * 8
        changed[start:start + 8] = (int.from_bytes(changed[start:start + 8], "little") ^ (1 << 31)).to_bytes(8, "little")
        self.reject("bounded8-highest-release-bit-changed", self.req(bytes(changed)))
        self.include(*spend)
        self.mark("bounded-depth8-live", creation=lock[0]["inclusion"], spend=spend[0]["inclusion"],
                  inner_proof_bytes=spend[0]["proof_bytes"], full_release_bytes=32)
        self.mark("bounded-height-hash-release-negatives", before_height_rejected=True, wrong_hash_rejected=True,
                  required_release_omitted_rpc_rejected=True, highest_256th_bit_rpc_rejected=True,
                  mutation_requests_used_current_parent=True)

    def policy_checks(self, entries):
        super().policy_checks(entries)
        self.profile_cases(entries)

    def standalone(self):
        self.addresses = [self.w(actor, "asset.address", {"index": 0}, create=True) for actor in range(2)]
        entries = [{"index": i, "recipient": a["address"]} for i, a in enumerate(self.addresses)]
        initial = self.tree(entries, 4); self.cred = [e["witness"] for e in initial["entries"]]
        row = self.w(0, "asset.row", {"disposable": True, "asset_id": 17, "policy_version": 1,
                     "issuer_secret": self.issuer, "admin_secret": self.admin_secret,
                     "credential_root": initial["credential_root"], "credential_depth": 4})
        live.write_json(self.base / "asset-descriptor.json", row["descriptor"])
        command = [str(self.args.node), "--print-development-candidate-manifest", "--development-funding-address",
                   self.addresses[0]["address"], "--development-assets-json", str(self.base / "asset-descriptor.json")]
        output = subprocess.run(command, env=self.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
        require(output.returncode == 0 and len(output.stdout) < 65536, "fresh manifest generation failed")
        self.manifest = json.loads(output.stdout); self.manifest["pow_bits"] = 0x207fffff
        live.write_json(self.base / "manifest.json", self.manifest)
        self.node("profile-a", self.base / "node-a", 0)
        self.node("profile-b", self.base / "node-b", 1, f"127.0.0.1:{self.ports[2]}")
        self.converge(); self.mine(121); self.converge()
        for actor in range(2): self.sync(actor)
        seed = self.build("supplement-real-mint-seed", "mint", 1000)
        self.include(*seed)
        self.profile_cases(entries)
        self.verify_retained_actions(); self.gates()
        require(all(live.sha(r["path"]) == r["sha256"] for r in self.receipt["sources"])
                and all(live.sha(r["path"]) == r["sha256"] for r in self.receipt["binaries"].values()),
                "source or binary changed during actual profile run")
        self.receipt["status"] = "passed"


def orphan_release_helper_regression():
    """Offline transport fixtures exercise the actual helper's safety checks."""
    identity, action = "31" * 32, "41" * 48
    body = b"offline-orphan-release-fixture"
    public = [0] * 134; public[16] = 7
    row = {"reservation_id": identity, "action_id": action, "public_statement": public}
    original = {"id": list(bytes.fromhex(identity)), "status": "Submitted", "parent_height": 7,
                "action_id": list(bytes.fromhex(action)), "mined_in": None, "inputs_reserved": True}

    class Fixture:
        def __init__(self, mutation):
            self.mutation, self.released, self.receipt = mutation, False, {}
            self.journal = [dict(original), dict(original, id=[0x32] * 32, status="Abandoned", inputs_reserved=False)]
            if mutation == "still-mined": self.journal[0]["mined_in"] = [8, [5] * 32]
            if mutation == "wrong-parent-before": self.journal[0]["parent_height"] = 6
            if mutation == "wrong-action-before": self.journal[0]["action_id"] = [4] * 48
            if mutation == "not-submitted": self.journal[0]["status"] = "Candidate"
        def status(self): return (7 if self.mutation == "reference-still-current" else 9), "fixture-hash"
        def snap(self): return {"fixture_canonical": 2 if self.released and self.mutation == "canonical-changed" else 1}
        def save(self): pass
        def w(self, actor, method, params=None):
            require(actor == 0, "fixture actor changed")
            if method == "asset.journal": return json.loads(json.dumps(self.journal))
            require(params == {"reservation_id": identity}, "fixture reservation request changed")
            if method == "asset.export":
                value = body
                if self.mutation == "bytes-changed-before" or self.released and self.mutation == "bytes-changed-after":
                    value += b"changed"
                return {"reservation_id": identity, "encoding": "hex", "action_bytes": len(value), "action": value.hex()}
            require(method == "asset.abandon", "unexpected fixture operation")
            self.released = True
            self.journal[0].update(status="Abandoned", inputs_reserved=False)
            if self.mutation == "still-locked": self.journal[0]["inputs_reserved"] = True
            if self.mutation == "wrong-parent-after": self.journal[0]["parent_height"] = 8
            if self.mutation == "wrong-identity-after": self.journal[0]["id"] = [0x33] * 32
            if self.mutation == "deleted-tombstone": self.journal.pop(0)
            if self.mutation == "other-reservation-changed": self.journal[1]["parent_height"] = 8
            return {"reservation_id": identity}

    accepted = Fixture(None)
    live.NativeLifecycle.release_orphaned_mint(accepted, row, body)
    require(accepted.receipt["orphan_mint_explicit_release"]["exact_exported_bytes_preserved"],
            "actual orphan release helper did not retain evidence")
    mutations = ("still-mined", "wrong-parent-before", "wrong-action-before", "not-submitted",
                 "reference-still-current", "bytes-changed-before", "bytes-changed-after", "still-locked",
                 "wrong-parent-after", "wrong-identity-after", "deleted-tombstone", "other-reservation-changed", "canonical-changed")
    for mutation in mutations:
        try:
            live.NativeLifecycle.release_orphaned_mint(Fixture(mutation), row, body)
        except live.AcceptanceError:
            continue
        raise live.AcceptanceError("orphan release helper accepted unsafe fixture " + mutation)
    return {"accepted": 1, "rejected": len(mutations), "actual_helper_exercised": True,
            "actual_wallet_runtime_exercised": False}


def prepared():
    source = Path(__file__).resolve()
    tree = ast.parse(source.read_text())
    dispatched = {call.args[0].value for call in ast.walk(tree)
                  if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                  and call.func.attr == "mark" and call.args
                  and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)}
    require(set(GATES) <= dispatched, "supplemental gate dispatch missing")
    main_tree = ast.parse(HELPER.read_text())
    main_dispatched = {call.args[0].value for call in ast.walk(main_tree)
                       if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                       and call.func.attr == "mark" and call.args
                       and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)}
    require({identity for identity, _ in live.CHECKLIST} <= main_dispatched,
            "main lifecycle gate dispatch missing")
    compile(tree, str(source), "exec")
    compile(HELPER.read_text(), str(HELPER), "exec")
    orphan_release = orphan_release_helper_regression()
    tombstone = {"id": [7] * 32, "status": "Abandoned", "parent_height": 1,
                 "action_id": [], "mined_in": None, "inputs_reserved": False}
    require(rejected_journal_delta([], []) == []
            and rejected_journal_delta([], [tombstone]) == [tombstone], "safe journal outcome guard failed")
    negative_fixtures = [( [], [tombstone], True)]
    negative_fixtures += [([], [dict(tombstone, status=status)], False)
                         for status in ("Proving", "Candidate", "SubmissionUncertain", "Submitted", "Prepared", "Exported")]
    negative_fixtures += [([], [dict(tombstone, **changed)], False)
                         for changed in ({"inputs_reserved": True}, {"action_id": [1]}, {"mined_in": [1, [0] * 32]})]
    negative_fixtures += [([tombstone], [], False), ([tombstone], [dict(tombstone, parent_height=2)], False)]
    for before, after, cheap in negative_fixtures:
        try:
            rejected_journal_delta(before, after, cheap)
        except live.AcceptanceError:
            continue
        raise live.AcceptanceError("unsafe journal outcome accepted by preparation guard")
    # Source-level transport fixtures only. No RPC, nodes or processes start.
    original_rpc = live.rpc
    pending_cases = 0
    try:
        tx = "17" * 48
        body = bytes.fromhex(tx) + b"pending-fixture"
        def chunk(offset, count):
            data = body[offset:offset + count]
            return {"schema": "hegemon.development-pending-action-chunk-v1", "tx_hash": "0x" + tx,
                    "offset": offset, "chunk": "0x" + data.hex(), "chunk_len": len(data), "total_len": len(body)}
        for responses, expected in (([None], None), ([chunk(0, 8), None], None),
                                    ([chunk(0, 8), chunk(8, len(body))], body)):
            replies = iter(responses)
            live.rpc = lambda *_args, **_kwargs: next(replies)
            require(live.NativeLifecycle.pending(object(), "http://unused", tx) == expected,
                    "nullable pending chunk regression")
            pending_cases += 1
        try:
            raise ValueError("private fixture detail must not persist")
        except ValueError as error:
            evidence = live.failure_evidence(error, "public-fixture-stage")
        require(evidence["traceback_frames"] and "private fixture detail" not in json.dumps(evidence),
                "structured public traceback leaked exception input")
    finally:
        live.rpc = original_rpc
    expected_errors = ["mature reward recovery occurrence differs from mirror",
                       "private-spend recovery did not cover projected leaves",
                       "asset native profile is unsupported", "asset candidate absent"]
    for category in expected_errors:
        require(category in STATIC_ERROR_SOURCES
                and safe_reason("invalid wallet state: " + category + "; private fixture value") == category,
                "source-owned safe error category missing")
    require(safe_reason("private fixture value with no static error category")
            == "unclassified wallet failure; raw diagnostics not retained", "unclassified error value leaked")
    require(safe_reason(UNSUPPORTED_PROFILE_DISPLAY) == UNSUPPORTED_PROFILE_DISPLAY
            and PublicWalletRejected("asset.prepare", "internal_error", UNSUPPORTED_PROFILE_DISPLAY).public_error_sources,
            "exact typed unsupported-profile display missing safe source anchors")
    typed_redaction_fixtures = ["native asset admission: SourceIdentity",
        "native asset admission: UnsupportedProfileExtra", UNSUPPORTED_PROFILE_DISPLAY.lower(),
        "prefix " + UNSUPPORTED_PROFILE_DISPLAY, UNSUPPORTED_PROFILE_DISPLAY + "; private fixture value",
        UNSUPPORTED_PROFILE_DISPLAY + "\nprivate fixture value"]
    for message in typed_redaction_fixtures:
        require(safe_reason(message) == "unclassified wallet failure; raw diagnostics not retained",
                "nonexact typed error escaped redaction")
    for code, category in UNSUPPORTED_PROFILE_ROUTES:
        require(is_unsupported_profile_rejection(code, category), "valid unsupported profile route rejected")
    invalid_profile_routes = [("transaction_failed", UNSUPPORTED_PROFILE_DISPLAY),
        ("internal_error", "asset native profile is unsupported"),
        ("internal_error", "native asset admission: SourceIdentity"),
        ("invalid_params", UNSUPPORTED_PROFILE_DISPLAY),
        ("internal_error", "unclassified wallet failure; raw diagnostics not retained")]
    require(not any(is_unsupported_profile_rejection(*route) for route in invalid_profile_routes),
            "unrelated error accepted as unsupported profile")
    label_route_accepted = label_route_rejected = 0
    for label, allowed in NEGATIVE_EXPECTED_ROUTES.items():
        cheap = label == "bounded16-before-reservation"
        for code, category in allowed:
            require(is_expected_negative_rejection(label, cheap, code, category),
                    "expected labeled negative route rejected")
            require(category in STATIC_ERROR_SOURCES or category in TYPED_ERROR_SOURCES,
                    "expected labeled error has no source-owned category")
            label_route_accepted += 1
        for route in [("invalid_params", "asset relation rejected construction"),
                      ("rpc_connection_failed", "asset current accounting policy"),
                      ("store_locked", "asset relation rejected construction"),
                      ("transaction_failed", "asset candidate absent"),
                      ("internal_error", "unclassified wallet failure; raw diagnostics not retained"),
                      (None, "asset current accounting policy"),
                      ({"unexpected": "code"}, "asset relation rejected construction"),
                      ("transaction_failed", ["asset current accounting policy"])]:
            require(not is_expected_negative_rejection(label, cheap, *route),
                    "malformed or unrelated failure passed a labeled negative")
            label_route_rejected += 1
        unrelated = CURRENT_ACCOUNTING_ROUTE if RELATION_CONSTRUCTION_ROUTE in allowed else RELATION_CONSTRUCTION_ROUTE
        require(not is_expected_negative_rejection(label, cheap, *unrelated), "wrong predicate route passed negative")
        label_route_rejected += 1
    require(not is_expected_negative_rejection("bounded16-before-reservation", True,
                "transaction_failed", "asset native profile is unsupported"),
            "shadowed library route passed the walletd early-profile negative")
    invalid_labels = [("unknown-negative", False), (None, False), ([], False),
                      ("bounded16-before-reservation", False), ("bounded8-before-height", True)]
    for label, cheap in invalid_labels:
        try:
            ProfileRun.denied(object(), label, {}, cheap)
        except live.AcceptanceError:
            continue
        raise live.AcceptanceError("unknown or inconsistent negative label reached a wallet call")
    receipt = {"schema": "hegemon.native-asset.profile-supplement-preparation.v1", "status": "PREPARED_NOT_EXECUTED",
               "production_authorized": False, "script": live.file_record(source), "frozen_helper": live.file_record(HELPER),
               "gates": GATES, "asset_proofs_added_to_main": 4, "controls_proofs_added_to_main": 5,
               "standalone_extra_seed_proofs": 1, "syntax_compiled": True,
               "all_supplemental_gate_dispatches_present": True, "node_processes_started": 0,
               "all_main_gate_dispatches_present": True, "combined_unique_gate_count": len(set(GATES) | {i for i, _ in live.CHECKLIST}),
               "projected_full_run_proofs": {"asset_ordinary": 13, "asset_bounded": 7,
                   "native_ordinary": 4, "controls_admin": 11, "total": 35},
               "orphan_mint_explicit_release_offline_regression": orphan_release,
               "journal_guard_positive_cases": 2, "journal_guard_negative_cases": len(negative_fixtures),
               "nullable_pending_chunk_regression_cases": pending_cases, "public_traceback_redaction_fixture_passed": True,
               "source_owned_error_categories": len(STATIC_ERROR_SOURCES),
               "safe_error_literal_fixtures": len(expected_errors), "unclassified_error_redaction_fixture_passed": True,
               "source_owned_typed_error_categories": TYPED_ERROR_SOURCES,
               "typed_error_exact_display_fixture_passed": True,
               "typed_error_redaction_fixtures": len(typed_redaction_fixtures),
               "unsupported_profile_allowed_route_fixtures": len(UNSUPPORTED_PROFILE_ROUTES),
               "unsupported_profile_rejected_route_fixtures": len(invalid_profile_routes),
               "negative_expected_error_routes": {label: [list(route) for route in sorted(routes)]
                                                   for label, routes in NEGATIVE_EXPECTED_ROUTES.items()},
               "labeled_negative_route_accepted_fixtures": label_route_accepted,
               "labeled_negative_route_rejected_fixtures": label_route_rejected + 1,
               "invalid_labels_rejected_before_wallet_calls": len(invalid_labels),
               "proofs_generated": 0, "proofs_verified": 0, "resource_floor_percent": 40,
               "maximum_live_nodes": 2, "minimum_free_disk_bytes": 10 * 1024**3,
               "limitations": ["Preparation does not establish any actual acceptance result.",
                               "Wrong-subject/hash/height negatives exercise actual wallet rejection; release/profile mutations also exercise both native RPC routes.",
                               "Freeze branch eligibility is checked from the actual selected descriptor/current credentials; no frozen branch proof is generated.",
                               "Finite actual-node evidence does not close inherited backend/refinement/privacy/production obligations."]}
    path = live.ARTIFACT_ROOT / "supplemental-prepared.json"
    live.write_json(path, receipt)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--with-main-lifecycle", action="store_true", help="include supplemental gates in one complete fresh main rerun")
    parser.add_argument("--node", type=Path, default=ROOT / "target-stablecoin/retained-proof/hegemon-node")
    parser.add_argument("--walletd", type=Path, default=ROOT / "target-stablecoin/retained-proof/walletd")
    parser.add_argument("--private-spend", type=Path, default=ROOT / "target-stablecoin/retained-proof/private-spend")
    parser.add_argument("--run-name", default="profiles-" + time.strftime("%Y%m%dT%H%M%S"))
    parser.add_argument("--timeout", type=int, default=10800)
    parser.add_argument("--proof-timeout", type=int, default=600)
    parser.add_argument("--coordinator-usage-remaining", type=float)
    args = parser.parse_args(); os.umask(0o077)
    require(not (args.run and args.prepare_only), "choose preparation or actual execution")
    if not args.run:
        path = prepared(); print(json.dumps({"status": "PREPARED_NOT_EXECUTED", "receipt": str(path), "sha256": live.sha(path)})); return 0
    require(args.coordinator_usage_remaining is not None and args.coordinator_usage_remaining > 40,
            "coordinator must supply fresh remaining-account readback above40 percent")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_name), "unsafe run name")
    require(0 < args.proof_timeout <= 1800 and 0 < args.timeout <= 14400, "deadline out of bounds")
    for key in ("node", "walletd", "private_spend"):
        path = getattr(args, key).resolve(); require(path.is_file() and os.access(path, os.X_OK), "missing executable " + key); setattr(args, key, path)
    run = ProfileRun(args)
    def interrupted(number, _frame): raise live.AcceptanceError("owned run interrupted by signal " + str(number))
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        run.execute() if args.with_main_lifecycle else run.standalone()
    except BaseException as error:
        run.receipt.update(live.failure_evidence(error, run.current))
    finally:
        for child in reversed(run.children):
            if child.poll() is None: run.pool.stop_process_group(child)
        run.receipt.update(owned_processes=len(run.children), owned_processes_reaped=all(c.poll() is not None for c in run.children),
                           disk_free_bytes=shutil.disk_usage(run.base).free, harness_sha256=live.sha(__file__))
        run.save(); print(json.dumps({"status": run.receipt["status"], "receipt": str(run.base / "receipt.json"),
                                    "failed_step": run.receipt.get("failed_step"), "error": run.receipt.get("error")}), flush=True)
    return 0 if run.receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
