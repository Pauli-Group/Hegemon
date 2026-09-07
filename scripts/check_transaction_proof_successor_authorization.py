#!/usr/bin/env python3
"""Source-owned, fail-closed authorization gate for a future transaction proof.

Repository JSON is evidence inventory, never authority. An authorized profile
must first be added to the separate source-reviewed registry. The exact tagged
commit roots both this checker and that registry. A registry entry pins the
exact identity, canonical evidence-bundle path, and SHA-512 of the bundle. The
bundle then pins every required evidence file by exact byte length and
recomputed SHA-512. The bundle may not include itself, this checker, or the
registry. This one-way graph has no hash fixed point. There is deliberately no
boolean capability or ``production_authorized`` input.

The registry is empty until the exact V8 release evidence satisfies every gate.
Consequently authorization mode cannot succeed in this revision.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Iterable, Mapping, NoReturn


SELECTION_SCHEMA = "hegemon.transaction-proof.successor-selection.v1"
EVIDENCE_BUNDLE_SCHEMA = "hegemon.transaction-proof.successor-evidence-bundle.v1"
DEFAULT_SELECTION_PATH = Path("config/transaction-proof-successor-selection.json")
SOURCE_REGISTRY_RELATIVE_PATH = (
    "scripts/transaction_proof_successor_authorized_registry.py"
)
AUTHORITY_SOURCE_PATHS = frozenset(
    {
        "scripts/check_transaction_proof_successor_authorization.py",
        SOURCE_REGISTRY_RELATIVE_PATH,
    }
)
RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml"
RELEASE_WORKFLOW_SHA512 = (
    "f08ffb8a3567293bc1c77f16ba089d260626c70db897f5bc9f85a0271ffd9588e"
    "b2537b5eeb458762aef9f5da385a459e32567099c196f58eac909ae57f0ed6b"
)
NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512 = (
    "087fd1f3dc04f653b6d380f104467842c1b4b42b7ba0fabfbe75220f3664f0e"
    "870b80f92bda748b571cce3768b0386cf870a5586f92d0547e780518b2e04a881"
)
NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH = (
    "docs/crypto/smallwood_poseidon2_v8_smz9_source_security_report.json"
)
NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_BYTES = 136_119
EXECUTABLE_ZK_REFINEMENT_REPORT_PATH = (
    "docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json"
)
EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES = 4_230
EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512 = (
    "02d3e86eb1f9d5e33091611cbe8786e4ef7c38411cbc48a92b4b926e94f76975"
    "2b3d1e61173b92d959c697b2c45867a993335c69a3cdb22c506a0ec695a353dd"
)
MAX_SELECTION_JSON_BYTES = 64 * 1024
MAX_RELEASE_WORKFLOW_BYTES = 512 * 1024
MAX_EVIDENCE_BUNDLE_JSON_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
MAX_VERIFIER_BINARY_BYTES = 512 * 1024 * 1024
MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES = 1024 * 1024
SHA512_HEX_BYTES = 128
GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001

IDENTITY_KEYS = {
    "network_id",
    "circuit_version",
    "crypto_suite",
    "family_id",
    "action_id",
    "coinbase_action_id",
    "backend_wire_id",
    "profile_wire_id",
    "domain_set",
    "statement_magic_hex",
    "statement_bytes",
    "envelope_magic_hex",
    "envelope_version",
    "native_leaf_magic_hex",
    "native_leaf_version",
    "inner_proof_wire_magic_hex",
    "inner_proof_wire_version",
    "proof_mode",
    "consensus_binding_digest_bytes",
    "transaction_digest_bytes",
    "stablecoin_policy_hash_bytes",
    "stablecoin_oracle_commitment_bytes",
    "stablecoin_attestation_commitment_bytes",
    "transcript_digest_bytes",
    "proof_commitment_bytes",
    "chain_id_hex",
    "genesis_id_hex",
    "rules_hash_hex",
    "relation_digest_hex",
    "activation_height",
    "deactivation_height_exclusive",
    "activation_genesis_hash",
    "stablecoin_genesis_root",
    "note_genesis_root",
    "relation_program_sha512",
    "relation_manifest_sha512",
    "profile_manifest_sha512",
    "verifier_program_sha512",
    "verifier_binary_manifest_sha512",
    "transcript_manifest_sha512",
    "cryptographic_role_manifest_sha512",
    "source_derived_security_report_sha512",
    "security_epoch_max_proofs",
    "max_proofs_per_block",
    "max_proof_actions_per_block",
    "claimed_security_bits",
    "max_proof_bytes",
    "max_outer_envelope_bytes",
    "max_inline_route_args_bytes",
    "max_v8_pending_action_bytes",
}

DIGEST_WIDTH_IDENTITY_FIELDS = (
    "chain_id_hex",
    "genesis_id_hex",
    "rules_hash_hex",
    "relation_digest_hex",
)
CAPABILITY_IDENTITY_FIELDS = (
    "network_id",
    "circuit_version",
    "crypto_suite",
    "family_id",
    "action_id",
    "coinbase_action_id",
    "backend_wire_id",
    "profile_wire_id",
    "domain_set",
    "relation_digest_hex",
    "activation_height",
    "deactivation_height_exclusive",
    "activation_genesis_hash",
    "stablecoin_genesis_root",
    "note_genesis_root",
    "max_proof_actions_per_block",
    "claimed_security_bits",
)
SHA512_IDENTITY_PIN_FIELDS = (
    "relation_program_sha512",
    "relation_manifest_sha512",
    "profile_manifest_sha512",
    "verifier_program_sha512",
    "verifier_binary_manifest_sha512",
    "transcript_manifest_sha512",
    "cryptographic_role_manifest_sha512",
    "source_derived_security_report_sha512",
)
PINNED_EVIDENCE_DIGEST_FIELDS = {
    "relation_program": "relation_program_sha512",
    "relation_manifest": "relation_manifest_sha512",
    "profile_manifest": "profile_manifest_sha512",
    "verifier_program": "verifier_program_sha512",
    "verifier_binary_manifest": "verifier_binary_manifest_sha512",
    "transcript_manifest": "transcript_manifest_sha512",
    "cryptographic_role_manifest": "cryptographic_role_manifest_sha512",
    "source_derived_composed_security_report": "source_derived_security_report_sha512",
}

# Each requirement is satisfied only by one distinct exact file.  These labels
# describe evidence classes; they do not assert that any current artifact has
# passed.  A future registry entry pins the one reviewed bundle that names all
# of them.
REQUIRED_EVIDENCE_KINDS: dict[str, str] = {
    "canonical_statement_and_parser_source": "source",
    "exact_full_relation_source": "source",
    "relation_compiler_source": "source",
    "relation_program": "program",
    "relation_program_transcript_spec": "certificate",
    "relation_program_digest_conformance_report": "report",
    "executable_csr_program_refinement_receipt": "receipt",
    "executable_nonlinear_program_refinement_receipt": "receipt",
    "relation_source_supply_chain_manifest": "manifest",
    "relation_manifest": "manifest",
    "profile_manifest": "manifest",
    "proof_system_source": "source",
    "production_verifier_source": "source",
    "verifier_program": "program",
    "verifier_binary_manifest": "manifest",
    "transcript_manifest": "manifest",
    "cryptographic_role_manifest": "manifest",
    "production_capability_manifest": "manifest",
    "version_and_kernel_manifest_source": "source",
    "wallet_action_projection_source": "source",
    "rpc_relay_mempool_transport_source": "source",
    "consensus_dispatch_source": "source",
    "state_storage_replay_source": "source",
    "global_v8_proof_lifetime_accounting_source": "source",
    "relation_geometry_certificate": "certificate",
    "transcript_inventory_certificate": "certificate",
    "piop_correction_aware_sampling_refinement_receipt": "receipt",
    "complete_zero_knowledge_certificate": "certificate",
    "knowledge_extraction_certificate": "certificate",
    "composed_pcs_iop_fiat_shamir_qrom_certificate": "certificate",
    "source_derived_composed_security_report": "report",
    "cryptographic_role_security_certificate": "certificate",
    "lean_compiled_relation_semantic_refinement_receipt": "receipt",
    "lean_poseidon2_relation_refinement_receipt": "receipt",
    "rust_verifier_acceptance_refinement_receipt": "receipt",
    "rust_lean_verifier_conformance_receipt": "receipt",
    "sha512_qrom_composition_receipt": "receipt",
    "adaptive_qrom_whole_view_zk_receipt": "receipt",
    "executable_zk_refinement_report": "report",
    "global_sha512_qrom_lifetime_theorem_receipt": "receipt",
    "authenticated_independent_security_review": "attestation",
    "production_value_balance_zero_projection_receipt": "receipt",
    "conditional_v8_proof_lifetime_accounting_receipt": "receipt",
    "parser_and_public_mutation_report": "report",
    "lifecycle_same_bytes_report": "report",
    "restart_reorg_fresh_node_report": "report",
    "proof_measurement_report": "report",
    "retained_proof_primary": "proof",
    "retained_proof_independent": "proof",
    "successor_release_manifest": "manifest",
}
EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID = "executable_zk_refinement_report"
EXECUTABLE_ZK_REFINEMENT_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.smz9.executable-zk-refinement.v1"
)
ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID = "adaptive_qrom_whole_view_zk_receipt"
ADAPTIVE_QROM_WHOLE_VIEW_SCHEMA = (
    "hegemon.formal.smallwood-smz9.adaptive-qrom-whole-view.v1"
)
GLOBAL_QROM_LIFETIME_EVIDENCE_ID = (
    "global_sha512_qrom_lifetime_theorem_receipt"
)
GLOBAL_QROM_LIFETIME_SCHEMA = (
    "hegemon.formal.smallwood-smz9.global-sha512-qrom-lifetime.v1"
)
INDEPENDENT_REVIEW_EVIDENCE_ID = "authenticated_independent_security_review"
INDEPENDENT_REVIEW_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.authenticated-independent-security-review.v1"
)
ADAPTIVE_QROM_WHOLE_VIEW_FORMAL_SOURCE_PATH = (
    "formal/crypto/HegemonCrypto/SmallWoodV8Smz9ZeroKnowledge.lean"
)
ADAPTIVE_QROM_WHOLE_VIEW_RELEASE_THEOREM = (
    "HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge."
    "deployed_smz9_adaptive_qrom_whole_view_release_receipt"
)
GLOBAL_QROM_LIFETIME_FORMAL_SOURCE_PATH = (
    "formal/crypto/HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean"
)
GLOBAL_QROM_LIFETIME_RELEASE_THEOREM = (
    "HegemonCrypto.SmallWood.V8Smz9AdaptiveFiniteAccounting."
    "deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le"
)
FORMAL_SECURITY_RECEIPT_BINDINGS = {
    ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID: {
        "scope": "adaptive_qrom_whole_view_complete_zero_knowledge",
        "formal_source_path": ADAPTIVE_QROM_WHOLE_VIEW_FORMAL_SOURCE_PATH,
        "release_theorem": ADAPTIVE_QROM_WHOLE_VIEW_RELEASE_THEOREM,
    },
    GLOBAL_QROM_LIFETIME_EVIDENCE_ID: {
        "scope": "global_deployed_sha512_qrom_lifetime",
        "formal_source_path": GLOBAL_QROM_LIFETIME_FORMAL_SOURCE_PATH,
        "release_theorem": GLOBAL_QROM_LIFETIME_RELEASE_THEOREM,
    },
}
FORMAL_SECURITY_RECEIPT_KEYS = {
    "scope",
    "formal_source_path",
    "formal_source_sha512",
    "release_theorem",
    "release_receipt_constructed",
    "all_release_inputs_instantiated",
    "concrete_security_bits_floor",
    "source_inventory_sha512",
    "capability_identity_sha512",
    "retained_proof_primary_sha512",
    "retained_proof_independent_sha512",
}
RELEASE_EVIDENCE_SCHEMA_OVERRIDES = {
    EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID: EXECUTABLE_ZK_REFINEMENT_SCHEMA,
    ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID: ADAPTIVE_QROM_WHOLE_VIEW_SCHEMA,
    GLOBAL_QROM_LIFETIME_EVIDENCE_ID: GLOBAL_QROM_LIFETIME_SCHEMA,
    INDEPENDENT_REVIEW_EVIDENCE_ID: INDEPENDENT_REVIEW_SCHEMA,
}
FIXED_NON_SOURCE_EVIDENCE_PATHS_BY_ID = {
    EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID: EXECUTABLE_ZK_REFINEMENT_REPORT_PATH,
    ADAPTIVE_QROM_WHOLE_VIEW_EVIDENCE_ID: (
        ".agent/artifacts/smallwood-poseidon2-v8/formal/"
        "adaptive-qrom-whole-view-release-receipt.json"
    ),
    GLOBAL_QROM_LIFETIME_EVIDENCE_ID: (
        ".agent/artifacts/smallwood-poseidon2-v8/formal/"
        "global-sha512-qrom-lifetime-release-receipt.json"
    ),
    INDEPENDENT_REVIEW_EVIDENCE_ID: (
        ".agent/artifacts/smallwood-poseidon2-v8/review/"
        "authenticated-independent-security-review.json"
    ),
}
SOURCE_EVIDENCE_PATHS_BY_ID: dict[str, str] = {
    "canonical_statement_and_parser_source": (
        "circuits/transaction/src/smallwood_poseidon2_v8_types.rs"
    ),
    "exact_full_relation_source": (
        "circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs"
    ),
    "relation_compiler_source": (
        "circuits/transaction/src/smallwood_poseidon2_v8_program.rs"
    ),
    "proof_system_source": "circuits/transaction/src/smallwood_engine.rs",
    "production_verifier_source": (
        "circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs"
    ),
    "version_and_kernel_manifest_source": "protocol/versioning/src/lib.rs",
    "wallet_action_projection_source": "wallet/src/poseidon2_v8.rs",
    "rpc_relay_mempool_transport_source": (
        "protocol/shielded-pool/src/poseidon2_production_transport.rs"
    ),
    "consensus_dispatch_source": "node/src/native/block_flow.rs",
    "state_storage_replay_source": "node/src/native/poseidon2_v8_state.rs",
    "global_v8_proof_lifetime_accounting_source": (
        "node/src/native/smallwood_v8_lifetime.rs"
    ),
}
SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS = frozenset(
    evidence_id
    for evidence_id, kind in REQUIRED_EVIDENCE_KINDS.items()
    if kind in {"certificate", "report", "receipt", "manifest", "attestation"}
    and evidence_id
    not in {
        EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID,
        "relation_manifest",
        "profile_manifest",
        "source_derived_composed_security_report",
        "lifecycle_same_bytes_report",
        "restart_reorg_fresh_node_report",
    }
)
# Every locally executable release claim must have an exact source-owned
# command here before it can authorize. Repository JSON cannot populate this
# inventory. External reviews have no local command and remain uninhabited
# until a separate source-reviewed trust-root/signature schema is added.
SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS: dict[str, tuple[str, ...]] = {}
SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS: dict[
    str, dict[str, object]
] = {}
HERMETIC_RELEASE_AUTHORITY_SCHEMA = (
    "hegemon.transaction-proof.hermetic-release-authority.v1"
)
HERMETIC_RELEASE_AUTHORITY_KEYS = {
    "schema",
    "profile_id",
    "release_root",
    "checkout_relative_path",
    "git_metadata_relative_path",
    "dependency_cache_relative_path",
    "release_manifest_relative_path",
    "release_manifest_bytes",
    "release_manifest_sha512",
    "mount_attestation_relative_path",
    "mount_attestation_bytes",
    "mount_attestation_sha512",
    "bootstrap_files",
    "command_files",
    "fixed_environment",
}
HERMETIC_RELEASE_FILE_KEYS = {
    "role",
    "path",
    "bytes",
    "sha512",
    "owner_uid",
    "mode",
}
HERMETIC_RELEASE_REQUIRED_BOOTSTRAP_ROLES = frozenset(
    {
        "python",
        "python_standard_library",
        "dynamic_loader",
        "runtime_libraries",
    }
)
HERMETIC_RELEASE_REQUIRED_COMMAND_ROLES = frozenset(
    {
        "git",
        "cargo",
        "rustc",
        "rustdoc",
        "linker",
        "archiver",
        "c_compiler",
        "cxx_compiler",
    }
)
HERMETIC_RELEASE_FIXED_ENVIRONMENT = {
    "PATH": "",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "CARGO_NET_OFFLINE": "true",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
}
# Empty by design. A future source review must pin one root-owned read-only
# Linux mount and the exact manifest, bootstrap, toolchain, cache, and command
# identities before the production command boundary can run at all.
SOURCE_BOUND_HERMETIC_RELEASE_ROOTS: dict[str, dict[str, object]] = {}
INDEPENDENT_REVIEW_TRUST_ROOT_KEYS = {
    "trust_root_id",
    "reviewer_identity",
    "signature_scheme",
    "public_key_path",
    "public_key_bytes",
    "public_key_sha512",
    "review_artifact_path",
    "signature_path",
    "verification_command",
}
INDEPENDENT_REVIEW_ATTESTATION_KEYS = {
    "trust_root_id",
    "public_key_path",
    "public_key_bytes",
    "public_key_sha512",
    "review_artifact_path",
    "review_artifact_bytes",
    "review_artifact_sha512",
    "signature_path",
    "signature_bytes",
    "signature_sha512",
    "reviewed_source_revision",
    "reviewed_source_inventory_sha512",
    "reviewed_capability_identity_sha512",
    "reviewed_primary_proof_sha512",
    "reviewed_independent_proof_sha512",
    "verification_command",
}
INDEPENDENT_REVIEW_ARTIFACT_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.independent-security-review-artifact.v1"
)
INDEPENDENT_REVIEW_ARTIFACT_KEYS = {
    "schema",
    "review_id",
    "reviewer_identity",
    "reviewed_source_revision",
    "reviewed_source_inventory_sha512",
    "reviewed_capability_identity_sha512",
    "reviewed_primary_proof_sha512",
    "reviewed_independent_proof_sha512",
    "security_conclusion",
    "approved_for_production",
    "blockers",
}
ML_DSA_87_PUBLIC_KEY_BYTES = 2_592
ML_DSA_87_SIGNATURE_BYTES = 4_627
SOURCE_COMMAND_RECEIPT_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.source-command-receipt.v1"
)
SOURCE_COMMAND_RECEIPT_KEYS = {
    "schema",
    "evidence_id",
    "kind",
    "profile_id",
    "relation_program_sha512",
    "source_revision",
    "source_inventory_sha512",
    "retained_proof_primary_sha512",
    "retained_proof_independent_sha512",
    "source_derived_security_report_sha512",
    "capability_identity_sha512",
    "evidence_claim_sha512",
    "release_workflow_sha512",
    "passed",
    "unresolved_premises",
}
RETAINED_PROOF_IDS = ("retained_proof_primary", "retained_proof_independent")
RELEASE_EVIDENCE_BASE_KEYS = {
    "schema",
    "evidence_id",
    "kind",
    "profile_id",
    "relation_program_sha512",
    "source_revision",
    "source_files",
    "release_gate_passed",
    "authority_conferred",
    "claim_boundary",
    "result",
}
RELEASE_EVIDENCE_RESULT_KEYS = {
    "status",
    "passed",
    "profile_id",
    "semantic_relation",
    "relation_program_sha512",
    "source_revision",
    "unresolved_premises",
    "checks",
}
PRODUCTION_CAPABILITY_MANIFEST_EVIDENCE_ID = "production_capability_manifest"
PRODUCTION_VALUE_BALANCE_EVIDENCE_ID = (
    "production_value_balance_zero_projection_receipt"
)
PRODUCTION_VALUE_BALANCE_PROJECTION_KEYS = {
    "transparent_pool_enabled",
    "relation_enforces_zero",
    "wallet_projection_enforces_zero",
    "native_projection_enforces_zero",
}
PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID = (
    "conditional_v8_proof_lifetime_accounting_receipt"
)
PROOF_LIFETIME_ACCOUNTING_KEYS = {
    "scope",
    "conditional_max_proofs_per_block",
    "conditional_accounting_window_blocks",
    "conditional_accounting_window_proofs",
    "conditional_max_total_proofs_at_128_bits",
    "persistent_checked_canonical_count",
    "count_overflow_rejected",
    "lifetime_limit_rejected",
    "restart_deterministic",
    "sync_replay_deterministic",
    "reorg_restores_ancestor_count",
    "fresh_replay_exact_rows",
    "accounting_window_is_cryptographic_reset",
    "counts_all_verifier_invocations",
    "conditional_accounting_only",
    "deployed_security_claimed",
}
CONDITIONAL_MAX_V8_PROOFS_PER_BLOCK = 512
CONDITIONAL_V8_ACCOUNTING_WINDOW_BLOCKS = 4_096
CONDITIONAL_V8_ACCOUNTING_WINDOW_PROOFS = 2_097_152
CONDITIONAL_MAX_TOTAL_V8_PROOFS_AT_128_BITS = 621_730_874
RELEASE_EVIDENCE_CHECK_KEYS = {
    "name",
    "command",
    "exit_code",
    "passed",
    "output_sha512",
}
LIFECYCLE_INTEGRATION_EVIDENCE = {
    "lifecycle_same_bytes_report": (
        "wallet",
        "rpc",
        "relay",
        "mempool",
        "mining",
        "block",
    ),
    "restart_reorg_fresh_node_report": (
        "restart",
        "sync",
        "reorg",
        "fresh_node_verify",
    ),
}
# Empty until release workflows execute real V8/SMZ9 subsystem paths.  Artifact
# parser-stage labels are deliberately ineligible.  A future source review must
# add exact stage/command tuples here and repin the release workflow before a
# lifecycle receipt can pass.
SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS: dict[
    str, tuple[tuple[str, str], ...]
] = {}
LIFECYCLE_INTEGRATION_KEYS = {
    "execution_kind",
    "retained_proof_id",
    "proof_sha512",
    "proof_bytes",
    "capability",
    "capability_identity_sha512",
    "state_binding",
    "same_proof_bytes_at_every_stage",
    "production_verifier_used",
    "parser_stage_labels_used_as_authority",
    "validity_shortcuts_used",
    "release_workflow_sha512",
    "stage_results",
}
LIFECYCLE_STAGE_RESULT_KEYS = {
    "stage",
    "command",
    "passed",
    "output_sha512",
    "proof_sha512",
    "proof_bytes",
    "state_binding",
}
LIFECYCLE_COMMAND_RECEIPT_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.actual-lifecycle-command-receipt.v1"
)
LIFECYCLE_COMMAND_RECEIPT_KEYS = {
    "schema",
    "evidence_id",
    "profile_id",
    "relation_program_sha512",
    "source_revision",
    "execution_kind",
    "retained_proof_id",
    "proof_sha512",
    "proof_bytes",
    "capability",
    "capability_identity_sha512",
    "state_binding",
    "production_verifier_used",
    "parser_stage_labels_used_as_authority",
    "validity_shortcuts_used",
    "stages",
}
LIFECYCLE_COMMAND_RECEIPT_STAGE_KEYS = {
    "stage",
    "passed",
    "proof_sha512",
    "proof_bytes",
    "state_binding",
}
LIFECYCLE_STATE_BINDING_KEYS = {
    "parent_height",
    "candidate_height",
    "relation_digest_hex",
    "note_anchor",
    "note_root_after",
    "stablecoin_current_root",
    "stablecoin_root_before",
    "stablecoin_root_after",
}
RETAINED_ARTIFACT_SCHEMA = "hegemon-smallwood-poseidon2-v8-retained-artifact-v5"
RETAINED_LEGACY_ARTIFACT_SCHEMA = (
    "hegemon-smallwood-poseidon2-v8-retained-artifact-v4"
)
RETAINED_ARTIFACT_EXAMPLE = "smallwood_poseidon2_v8_artifact"
RETAINED_BUILD_PROFILE = "retained-proof"
SOURCE_SECURITY_REPORT_EXAMPLE = "smallwood_poseidon2_v8_security_report"
SOURCE_SECURITY_REPORT_SCHEMA = (
    "hegemon.smallwood.poseidon2-v8.smz9.source-security-report.v3"
)
SOURCE_SECURITY_REPORT_KEYS = {
    "adaptive_final_piop_programming_screen",
    "adaptive_first_program_no_go",
    "adaptive_full_tree_programming_screen",
    "adaptive_lazy_merkle_programming_screen",
    "assumptions",
    "beta",
    "blockers",
    "budget",
    "candidate_parameter_screens",
    "canonical_piop_opening_abort",
    "claim_ledger",
    "conditional_completeness_abort_finite_history",
    "conditional_completeness_abort_per_proof",
    "conditional_fixed_query_baseline_without_honest_program_exposures",
    "conditional_global_query_composed_reduction_failure",
    "conditional_global_query_soundness_only",
    "conditional_global_query_work_screens",
    "conditional_total_failure_finite_history_diagnostic",
    "byte_quotient_diagnostic",
    "constraint_degree",
    "decs_domain_size",
    "decs_eta",
    "decs_openings",
    "deployed_composed_security_bits_floor",
    "deployed_finite_history_composed",
    "external_whole_view_terms",
    "field_xof_abort_union",
    "field_xof_candidate_words",
    "field_xof_minimum_rejections",
    "field_xof_request_union",
    "field_xof_requested_words",
    "fixed_decs_sampler_abort",
    "ideal_cms_qrom",
    "interactive_aggregate",
    "interactive_terms",
    "known_attacks",
    "lifetime_binding",
    "maximum_linear_identity_count",
    "maximum_summed_identity_union",
    "meets_128_bit_deployed_floor",
    "nonlinear_identity_count",
    "no_grinding",
    "packing_factor",
    "piop_admissibility_bad_tuple_coefficient",
    "piop_linear_correction_degree",
    "piop_nonce_bad_per_trial",
    "piop_openings",
    "piop_pcs_unstack_additional_forbidden_values",
    "poseidon2_collision",
    "poseidon_honest_evaluations_decimal",
    "poseidon2_preimage",
    "poseidon2_primitive_security_bound",
    "production_eligible",
    "profile_wire_id",
    "program_digest_hex",
    "program_sha512_hex",
    "projected_inner_proof_bytes",
    "projected_pending_action_bytes",
    "projected_two_output_action_bytes",
    "proof_exposure_accounting",
    "proof_columns",
    "proof_wire_magic_ascii",
    "rho",
    "row_count",
    "schema",
    "security_epoch_is_cryptographic_reset",
    "sha512_collision",
    "sha512_preimage",
    "sha512_primitive_security_bound",
    "sha512_to_indexed_product_oracle_reduction_bound",
    "strongest_conditional_global_query_work_factor_log2",
    "tape_database_bridge",
    "unbounded_history_theorem_required",
    "first_failing_conditional_global_query_work_factor_log2",
}
SOURCE_SECURITY_REQUIRED_ASSUMPTIONS = (
    "exact_compiled_relation_refinement",
    "exact_smz9_transcript_refinement",
    "exact_smz9_indexed_logical_oracle_instantiation",
    "sha512_to_indexed_product_oracle_reduction",
    "piop_correction_aware_sampling_refinement",
    "sha512_primitive_security_bound",
    "poseidon2_primitive_security_bound",
    "adaptive_final_piop_programming_refinement",
    "executable_program_inventory_excludes_salt_only_first_program",
    "executable_rng_to_ideal_lazy_inputs_refinement",
    "adaptive_lazy_merkle_completion_qrom_reduction",
    "all_adaptive_program_points_conditioned",
    "adaptive_whole_view_complete_zero_knowledge",
    "observed_honest_proof_views_model",
    "global_history_composition",
    "consensus_budget_binding",
    "public_attack_inventory_complete",
    "independent_review",
)
SOURCE_SECURITY_EXACT_LOSS_TERM_KEYS = {
    "approximate_security_bits",
    "denominator_decimal",
    "id",
    "numerator_decimal",
    "security_bits_floor",
}
SOURCE_SECURITY_BUDGET_KEYS = {
    "capability_activation_height",
    "capability_deactivation_height_exclusive",
    "max_proofs_per_block",
    "quantum_hash_query_log2",
    "security_epoch_blocks",
    "security_epoch_max_proofs",
}
SOURCE_SECURITY_BYTE_QUOTIENT_DIAGNOSTIC_KEYS = {
    "block_action_byte_cap",
    "projected_pending_action_bytes",
    "complete_projected_records_per_block",
    "is_upper_bound_on_proof_interactions",
    "used_in_security_loss_terms",
}
SOURCE_SECURITY_PRIMITIVE_WORK_SCREEN_KEYS = {
    "quantum_query_log2",
    "collision_advantage_upper_bound",
    "preimage_advantage_upper_bound",
}
SOURCE_SECURITY_PRIMITIVE_BOUND_RECEIPT_KEYS = {
    "schema",
    "receipt_id",
    "primitive_id",
    "exact_primitive_profile_identity",
    "source_inventory_sha512_hex",
    "theorem_or_reduction_id",
    "theorem_source_sha512_hex",
    "advantage_function",
    "advantage_scope",
    "adversarial_query_log2_max",
    "honest_programmed_oracle_exposures_decimal",
    "bound_uses_queries_plus_honest_exposures",
    "max_proof_actions_per_block",
    "max_proof_interactions",
    "validity_activation_height",
    "validity_deactivation_height_exclusive",
    "work_screens",
    "review_artifact_sha512_hex",
    "independently_reviewed",
}
SOURCE_SECURITY_PRIMITIVE_THEOREM_PATHS = {
    "HegemonCrypto.SmallWood.V8Smz9AdaptiveFiniteAccounting.deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le": (
        "formal/crypto/HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean"
    ),
    "HegemonCrypto.SmallWood.V8Smz9QromAccounting.poseidon2_width16_quantitative_security_bound": (
        "formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean"
    ),
}
SOURCE_SECURITY_PRIMITIVE_RECEIPT_BINDINGS = {
    "sha512_primitive_security_bound": {
        "theorem_or_reduction_id": (
            "HegemonCrypto.SmallWood.V8Smz9AdaptiveFiniteAccounting."
            "deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le"
        ),
        "theorem_source_path": (
            "formal/crypto/HegemonCrypto/"
            "SmallWoodV8Smz9AdaptiveFiniteAccounting.lean"
        ),
    },
    "poseidon2_primitive_security_bound": {
        "theorem_or_reduction_id": (
            "HegemonCrypto.SmallWood.V8Smz9QromAccounting."
            "poseidon2_width16_quantitative_security_bound"
        ),
        "theorem_source_path": (
            "formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean"
        ),
    },
}
SOURCE_SECURITY_LIFETIME_BINDING_KEYS = {
    "analysis_max_proof_interactions",
    "analysis_window_blocks",
    "analysis_window_is_cryptographic_reset",
    "capability_activation_height",
    "capability_deactivation_height_exclusive",
    "capability_max_proof_interactions",
    "capability_window_blocks",
    "capability_window_within_analysis_budget",
    "consensus_budget_binding_receipt_present",
}
SOURCE_SECURITY_PROOF_EXPOSURE_ACCOUNTING_KEYS = {
    "canonical_accepted_proofs",
    "observed_honest_proof_views",
    "observed_honest_proof_views_model_receipt_present",
    "consensus_counter_bounds_observed_honest_proof_views",
    "analyzed_proof_views",
    "analyzed_proof_views_are_canonical_count_diagnostic_only",
    "eager_programs_per_proof",
    "active_eager_per_proof_programming_loss",
    "active_eager_per_proof_security_bits_floor",
    "active_eager_max_observed_proof_views_for_strict_128_decimal",
    "active_eager_successor_fails_strict_128",
    "compact448_eager_per_proof_programming_loss",
    "compact448_eager_per_proof_security_bits_floor",
    "compact448_eager_max_observed_proof_views_for_strict_128_decimal",
    "compact448_eager_successor_fails_strict_128",
}
SOURCE_SECURITY_GLOBAL_QUERY_SCREEN_KEYS = {
    "abort_terms_excluded_from_soundness_and_reduction_failure",
    "accepted_proof_interactions",
    "adaptive_programming_uses_conditional_512_bit_entropy",
    "adaptive_programming_uses_total_step_log2_ceiling",
    "adaptive_programming_query_log2_ceiling",
    "certified_reduction_upper_bound_strictly_below_half",
    "conditional_composed_reduction_failure",
    "conditional_soundness_only",
    "conditional_total_failure_diagnostic",
    "exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated",
    "final_piop_and_full_tree_adaptive_programming_terms_included",
    "honest_programmed_oracle_exposures_decimal",
    "id",
    "is_known_attack",
    "quantum_hash_query_log2",
    "query_dependent_terms_charged_once",
    "cms_instability_uses_queries_plus_honest_programmed_exposures",
    "sha512_collision_uses_queries_plus_honest_programmed_exposures",
    "total_oracle_exposures_decimal",
}
SOURCE_SECURITY_CANDIDATE_SCREEN_KEYS = {
    "accepted_proof_interactions",
    "active_wire",
    "completeness_aborts_excluded",
    "decs_openings",
    "decs_polynomial_degree",
    "first_failing_certified_reduction_query_log2",
    "first_failing_screen",
    "first_failing_screen_strictly_below_half",
    "fixed_query_conditional_composed_reduction_failure",
    "fixed_query_conditional_soundness_only",
    "id",
    "merkle_conditional_entropy_bits",
    "piop_openings",
    "quantum_hash_query_log2",
    "requires_new_backend_wire_and_layout_theorem",
    "strongest_certified_reduction_query_log2",
    "strongest_screen",
    "strongest_screen_strictly_below_half",
    "theorem_hypotheses_instantiated",
}
SOURCE_SECURITY_FIRST_PROGRAM_KEYS = {
    "route_id",
    "salt_only_oracle_program_count",
    "exact_lazy_program_keys_exclude_salt_only_point",
    "direct_256_bit_first_program_route_used",
    "paper_hypotheses_instantiated_for_exact_smz9_program_point",
    "quantum_hash_query_log2",
    "accepted_proof_interactions",
    "current_entropy_bits",
    "current_entropy_bytes",
    "current_single_proof_loss",
    "current_finite_history_loss",
    "current_single_proof_supports_strict_128_bits",
    "current_finite_history_supports_strict_128_bits",
    "minimum_even_entropy_bits_for_finite_history",
    "minimum_even_entropy_loss",
    "previous_even_entropy_bits",
    "previous_even_entropy_loss",
    "minimum_byte_entropy_bits",
    "minimum_byte_entropy_bytes",
    "salt_word_alignment_bytes",
    "minimum_wire_entropy_bits",
    "minimum_wire_entropy_bytes",
    "additional_wire_entropy_bytes",
    "wire_change_required_only_if_this_route_applies",
    "alternative_reduction_may_avoid_wire_change",
}
SOURCE_SECURITY_FINAL_PIOP_KEYS = {
    "route_id",
    "program_point_scope",
    "paper_and_executable_hypotheses_instantiated",
    "entropy_bits",
    "quantum_hash_query_log2",
    "accepted_proof_interactions",
    "conditional_loss",
    "supports_strict_128_bits",
}
SOURCE_SECURITY_FULL_TREE_KEYS = {
    "route_id",
    "program_point_scope",
    "paper_and_all_points_hypotheses_instantiated",
    "programs_per_proof",
    "accepted_proof_interactions",
    "total_programming_events_decimal",
    "conditional_entropy_bits_per_program",
    "conditional_loss",
    "supports_strict_128_bits",
    "minimum_even_entropy_bits_for_strict_128",
    "minimum_even_entropy_loss",
    "previous_even_entropy_bits",
    "previous_even_entropy_loss",
    "previous_even_entropy_supports_strict_128_bits",
    "minimum_whole_byte_entropy_bits",
    "minimum_whole_byte_entropy_bytes",
    "salt_word_alignment_bytes",
    "minimum_wire_entropy_bits",
    "minimum_wire_entropy_bytes",
    "additional_wire_entropy_bytes",
    "minimum_wire_entropy_loss",
    "current_leaf_tape_entropy_bits",
    "leaf_input_fiber_refinement_instantiated",
    "hidden_child_internal_node_propagation_instantiated",
}
SOURCE_SECURITY_LAZY_MERKLE_KEYS = {
    "route_id",
    "source_records_exact_input_output_pairs_for_each_lazy_program",
    "maximum_compact_authentication_nodes",
    "maximum_abstract_programs_per_proof_including_final_piop",
    "fixture_abstract_programs_per_proof_including_final_piop",
    "accepted_proof_interactions",
    "maximum_abstract_programming_events_decimal",
    "maximum_leaf_programs_per_proof",
    "maximum_internal_node_programs_per_proof",
    "internal_node_program_cap_when_leaf_programs_equal_20",
    "joint_leaf_plus_internal_program_cap",
    "weighted_upper_bound_leaf_and_final_program_cap",
    "weighted_upper_bound_internal_node_program_cap",
    "leaf_and_final_conditional_entropy_bits",
    "internal_node_conditional_entropy_bits",
    "conditional_leaf_and_final_loss",
    "conditional_internal_node_loss",
    "conditional_combined_loss",
    "supports_strict_128_bits",
    "maximum_observed_honest_proof_views_for_strict_128_decimal",
    "first_failing_observed_honest_proof_views_decimal",
    "maximum_observed_honest_proof_views_supports_strict_128",
    "first_failing_observed_honest_proof_views_supports_strict_128",
    "source_role_framed_io_recording_refinement_instantiated",
    "source_duplicate_program_input_rejection_instantiated",
    "executable_rng_to_ideal_fresh_inputs_refinement_instantiated",
    "adaptive_lazy_completion_qrom_reduction_instantiated",
    "concrete_sha512_qro_instantiated",
    "global_prior_query_schedule_instantiated",
}
SOURCE_SECURITY_CLAIM_LEDGER_KEYS = {
    "proved_arithmetic",
    "source_checked_bindings",
    "stated_primitive_assumptions",
    "absent_reductions",
    "strongest_quantified_attack_id",
    "public_attack_inventory_complete",
}
SOURCE_SECURITY_KNOWN_ATTACK_KEYS = {
    "id",
    "primitive",
    "model",
    "approximate_work_factor_bits",
    "end_to_end_forgery_reduction_available",
    "independently_reviewed",
    "disposition",
}
RETAINED_GENERATION_PROVENANCE_SCHEMA = (
    "hegemon-smallwood-poseidon2-v8-generation-provenance-v1"
)
RETAINED_LEGACY_GENERATION_INDEPENDENCE_SCOPE = (
    "separate_process_fresh_rng_same_source"
)
RETAINED_GENERATION_METADATA_SCOPE = "informational_unattested_generation_metadata"
RETAINED_SOURCE_INVENTORY_SCHEMA = (
    "hegemon-smallwood-poseidon2-v8-release-source-inventory-v2"
)
RETAINED_SOURCE_INVENTORY_DOMAIN = (
    b"hegemon.smallwood.poseidon2-v8.release-source-inventory.v2\0"
)
RETIRED_SOURCE_INVENTORY_V1_DOMAIN = (
    b"hegemon.smallwood.poseidon2-v8.proof-source-inventory.v1\0"
)
RETAINED_SOURCE_INVENTORY_ROOT_PACKAGE = "transaction-circuit"
RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES = (
    "transaction-circuit",
    "hegemon-node",
    "wallet",
    "walletd",
)
RETAINED_SOURCE_INVENTORY_ROOT_FEATURES = {
    "transaction-circuit": ("default",),
    "hegemon-node": (),
    "wallet": ("default",),
    "walletd": ("default",),
}
RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_FILES = (
    ".cargo/config.toml",
    ".gitignore",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ADAPTIVE_QROM_WHOLE_VIEW_FORMAL_SOURCE_PATH,
    GLOBAL_QROM_LIFETIME_FORMAL_SOURCE_PATH,
)
RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES = (
    "formal/crypto",
    "formal/lean",
)
RETAINED_SOURCE_INVENTORY_MAX_FILES = 4_096
RETAINED_SOURCE_INVENTORY_MAX_FILE_BYTES = 16 * 1024 * 1024
RETAINED_SOURCE_INVENTORY_MAX_TOTAL_BYTES = 64 * 1024 * 1024
RETAINED_PROVENANCE_TRANSITION_SCHEMA = (
    "hegemon-smallwood-poseidon2-v8-provenance-transition-v1"
)
RETAINED_VERIFIER_PROVENANCE_SCHEMA = (
    "hegemon-smallwood-poseidon2-v8-verifier-provenance-v1"
)
RETAINED_GENERATOR_SOURCE_PATH = (
    "circuits/transaction/examples/smallwood_poseidon2_v8_artifact.rs"
)
RETAINED_GENERATION_PROVENANCE_KEYS = {
    "schema",
    "independence_scope",
    "artifact_role",
    "source_revision",
    "generator_source_path",
    "generator_source_sha512",
    "generator_binary_bytes",
    "generator_binary_sha512",
    "run_id_hex",
    "process_id",
    "started_unix_seconds",
    "proof_sha512",
}
RETAINED_RELATION_PROGRAM_MAGIC = "HGV8RP03"
RETAINED_RELATION_PROGRAM_BYTES = 853_429
RETAINED_RELATION_PROGRAM_SHA512 = (
    "180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d22"
    "39e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84"
)
RETAINED_PROJECTED_PENDING_ACTION_BYTES = 128_522
RETAINED_MAXIMUM_RECORD_BYTE_QUOTIENT_DIAGNOSTIC = (
    (64 * 1024 * 1024) // RETAINED_PROJECTED_PENDING_ACTION_BYTES
)
# This is the shared consensus proof-bearing-action count cap.  The 522
# maximum-record byte quotient is not an upper bound because smaller valid
# carriers can fit in the same byte budget.
RETAINED_MAX_PROOFS_PER_BLOCK = 512
RETAINED_SECURITY_EPOCH_BLOCKS = 1 << 12
RETAINED_SECURITY_EPOCH_MAX_PROOFS = (
    RETAINED_MAX_PROOFS_PER_BLOCK * RETAINED_SECURITY_EPOCH_BLOCKS
)
RETAINED_SEMANTIC_RELATION = (
    "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
)
RETAINED_NOTE_GENESIS_ROOT = [
    12_226_185_660_156_925_492,
    16_548_254_069_300_115_382,
    17_963_077_431_300_986_894,
    14_365_881_287_888_804_118,
    3_161_548_030_029_626_838,
    2_967_397_566_732_774_316,
    2_647_985_511_926_568_324,
]
RETAINED_FIXED_IDENTITY_VALUES: dict[str, object] = {
    "network_id": 0x4847_4D38,
    "circuit_version": 8,
    "crypto_suite": 7,
    "family_id": 1,
    "action_id": 10,
    "coinbase_action_id": 11,
    "backend_wire_id": 2,
    "profile_wire_id": 6,
    "domain_set": 4,
    "statement_magic_hex": "4847563850423032",
    "statement_bytes": 960,
    "envelope_magic_hex": "535750384c433032",
    "envelope_version": 1,
    "native_leaf_magic_hex": "4847563854583032",
    "native_leaf_version": 1,
    "inner_proof_wire_magic_hex": "534d5a39",
    "inner_proof_wire_version": 1,
    "proof_mode": "inline_self_contained",
    "consensus_binding_digest_bytes": 48,
    "transaction_digest_bytes": 56,
    "stablecoin_policy_hash_bytes": 48,
    "stablecoin_oracle_commitment_bytes": 48,
    "stablecoin_attestation_commitment_bytes": 48,
    "transcript_digest_bytes": 64,
    "proof_commitment_bytes": 64,
    "note_genesis_root": RETAINED_NOTE_GENESIS_ROOT,
    "relation_program_sha512": RETAINED_RELATION_PROGRAM_SHA512,
    "security_epoch_max_proofs": RETAINED_SECURITY_EPOCH_MAX_PROOFS,
    "max_proofs_per_block": RETAINED_MAX_PROOFS_PER_BLOCK,
    "max_proof_actions_per_block": RETAINED_MAX_PROOFS_PER_BLOCK,
    "claimed_security_bits": 128,
    "max_proof_bytes": 122_863,
    "max_outer_envelope_bytes": 131_068,
    "max_inline_route_args_bytes": 131_072,
    "max_v8_pending_action_bytes": 131_297,
}
RETAINED_ARTIFACT_PROFILE = {
    "rho": 5,
    "opened_evaluations": 6,
    "beta": 2,
    "decs_evaluations": 1 << 23,
    "decs_opened_leaves": 20,
    "decs_eta": 5,
    "leaf_tape_bytes": 64,
    "evaluation_domain": "radix2-disjoint-coset",
    "transcript": "SHA-512 Poseidon2 V8",
}
RETAINED_ARTIFACT_GEOMETRY = {
    "public_words": 120,
    "relation_balance_limbs": 7,
    "witness_rows": 686,
    "packing_factor": 64,
    "packed_witness_words": 43_904,
    "constraint_degree": 8,
    "nonlinear_constraints": 830,
    "linear_constraints": 19_935,
    "auxiliary_words": 0,
    "hash_calls": 125,
}
RETAINED_TRANSPORT_PARSER_STAGES = (
    "wallet",
    "rpc",
    "relay",
    "mempool",
    "mining",
    "block",
    "restart",
    "sync",
    "reorg",
    "fresh_node_verify",
)
RETAINED_NODE_PENDING_ACTION_LIFECYCLE_FIELDS = {
    "constructed_from_exact_scale_inline_args",
    "canonical_scale_decode",
    "canonical_reencode_equal",
    "public_args_byte_identical",
    "tx_hash_recomputed",
    "route_tuple_matches",
    "no_legacy_outer_state",
    "encoded_size_matches",
    "same_smz9_proof_bytes",
}
RETAINED_RELATION_MUTATIONS = (
    "private_row",
    "hash_initial",
    "public_ciphertext_commitment",
)
RETAINED_PROOF_MUTATIONS = (
    "proof_magic",
    "proof_middle",
    "proof_truncated",
    "proof_trailing_byte",
    "network_id",
    "relation_digest",
    "public_fee",
    "relation_balance_binding",
)
RETAINED_TRANSPORT_MUTATIONS = (
    "native_leaf_magic",
    "native_leaf_proof_length",
    "rpc_envelope_magic",
    "scale_compact_length",
    "scale_inline_trailing_byte",
    "native_leaf_statement_rewrap",
    "native_leaf_relation_binding_rewrap",
)
RETAINED_PENDING_ACTION_MUTATIONS = (
    "tx_hash",
    "binding_circuit",
    "binding_crypto",
    "family_id",
    "action_id",
    "anchor",
    "nullifiers",
    "commitments",
    "ciphertext_hashes",
    "ciphertext_sizes",
    "public_args",
    "fee",
    "candidate_artifact",
    "truncated",
    "trailing_byte",
)
RETAINED_OPENING_SURFACE_FIELDS = {
    "total_inner_proof_bytes",
    "transcript_bytes",
    "commitment_bytes",
    "opened_values_bytes",
    "opening_payload_bytes",
    "opened_witness_bytes",
    "pcs_rcombi_tails_bytes",
    "pcs_subset_evals_bytes",
    "pcs_partial_evals_bytes",
    "decs_auth_paths_bytes",
    "decs_leaf_tapes_bytes",
    "decs_masking_evals_bytes",
    "decs_high_coeffs_bytes",
    "nb_polys",
    "nb_unstacked_cols",
    "nb_lvcs_rows",
    "nb_lvcs_cols",
    "nb_lvcs_opened_combi",
    "opened_row_count",
    "opened_row_width",
    "pcs_rcombi_tail_width",
    "pcs_subset_eval_width",
    "pcs_partial_eval_width",
    "opened_witness_invariant_column_count",
    "pcs_subset_invariant_column_count",
    "pcs_partial_invariant_column_count",
    "opened_witness_invariant_compaction_raw_bytes",
    "pcs_subset_invariant_compaction_raw_bytes",
    "pcs_partial_invariant_compaction_raw_bytes",
    "opened_witness_row_scalar_floor_raw_bytes",
    "opened_witness_partial_extra_slot_count",
    "opened_witness_partial_poly_count",
    "opened_witness_partial_raw_bytes",
    "subset_eval_shape_floor_raw_bytes",
    "subset_eval_shape_matches_beta_packing_identity",
    "decs_opened_leaf_count",
    "decs_distinct_leaf_count",
    "decs_duplicate_leaf_count",
    "decs_total_auth_nodes",
    "decs_unique_auth_nodes",
    "decs_duplicate_auth_nodes",
    "decs_min_auth_path_len",
    "decs_max_auth_path_len",
}
RETAINED_HONEST_MAP_AUDIT = {
    "exact_square_full_rank": True,
    "witness_interpolation_coin_count": 4_116,
    "witness_opening_view_count": 4_116,
    "witness_interpolation_rank": 6,
    "pcs_unstack_coin_count": 240,
    "pcs_partial_view_count": 240,
    "pcs_unstack_block_count": 40,
    "pcs_unstack_min_block_rank": 6,
    "pcs_unstack_total_rank": 240,
    "nonlinear_piop_coin_count": 2_445,
    "nonlinear_piop_view_count": 2_445,
    "nonlinear_piop_low_rank": 6,
    "linear_piop_coin_count": 660,
    "linear_piop_view_count": 660,
    "linear_piop_low_rank": 6,
    "lvcs_tail_coin_count": 2_800,
    "lvcs_joint_view_count": 2_800,
    "lvcs_tail_evaluation_rank": 20,
    "lvcs_selected_combination_rank": 12,
    "decs_mask_coin_count": 1_940,
    "decs_evaluation_high_view_count": 1_940,
    "decs_low_coefficient_rank": 20,
}
RETAINED_HONEST_MAP_AUDIT_FIELDS = set(RETAINED_HONEST_MAP_AUDIT)
RETAINED_ACCEPTED_PROOF_REFINEMENT = {
    "accepted_proof_refinement_schema": (
        "hegemon.smallwood.poseidon2-v8.smz9.accepted-proof-refinement.v1"
    ),
    "lean_wire_model": "HegemonCrypto.SmallWoodSmz9ProofWire.decodeProofExact",
    "canonical_decode_reencode_exact": True,
    "verifier_trace_replay_exact": True,
    "production_verifier_accepts": True,
    "auxiliary_witness_words": 0,
    "auxiliary_witness_limbs": 0,
    "external_sha512_qrom_claim": False,
    "external_poseidon2_security_claim": False,
    "production_eligible": False,
}
RETAINED_ACCEPTED_PROOF_REFINEMENT_DYNAMIC_FIELDS = {
    "proof_bytes",
    "proof_sha512",
}
RETAINED_ACCEPTED_PROOF_REFINEMENT_FIELDS = (
    set(RETAINED_ACCEPTED_PROOF_REFINEMENT)
    | RETAINED_ACCEPTED_PROOF_REFINEMENT_DYNAMIC_FIELDS
)
RETAINED_ARTIFACT_FILES = frozenset(
    {
        "artifact-report.json",
        "proof.bin",
        "public-statement.bin",
        "relation-digest.bin",
        "relation-binding.bin",
        "network-id.bin",
        "relation-program.bin",
        "ciphertexts.bin",
        "transcript-preamble.bin",
        "native-leaf.bin",
        "rpc-envelope.bin",
        "scale-inline-args.bin",
        "pending-action.bin",
    }
)
RETAINED_RESEALED_ARTIFACT_FILES = RETAINED_ARTIFACT_FILES | {
    "parent-artifact-report-v4.json"
}
ArtifactCommandRunner = Callable[[list[str], Path], tuple[int, str]]


@dataclass(frozen=True)
class AuthorizedProfile:
    """Source-owned authorization record added only after independent review."""

    profile_id: str
    identity: Mapping[str, object]
    evidence_bundle_path: str
    evidence_bundle_sha512: str
    max_proof_bytes: int
    max_evidence_file_bytes: int = MAX_EVIDENCE_FILE_BYTES
    required_evidence: tuple[tuple[str, str], ...] = tuple(
        REQUIRED_EVIDENCE_KINDS.items()
    )


@dataclass(frozen=True)
class SourceReleaseVerifierBuild:
    artifact_path: Path
    artifact_bytes: int
    artifact_sha512: str
    security_path: Path
    security_bytes: int
    security_sha512: str


class SuccessorAuthorizationError(ValueError):
    """The successor selection or its exact evidence is not authorized."""


def reject(message: str) -> NoReturn:
    raise SuccessorAuthorizationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            reject(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> NoReturn:
    reject(f"non-standard JSON numeric constant {value!r}")


def canonical_json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise SuccessorAuthorizationError(f"JSON value is not canonicalizable: {exc}") from exc
    return (encoded + "\n").encode("utf-8")


def proof_source_inventory_root_sha512(
    entries: list[dict[str, object]], domain: bytes
) -> str:
    """Hash one ordered source inventory under an explicit schema domain."""

    if not isinstance(domain, bytes) or not domain:
        reject("proof source inventory domain must be nonempty bytes")
    root_hasher = hashlib.sha512(domain)
    for index, entry_raw in enumerate(entries):
        entry = require_object(entry_raw, f"proof source inventory entry {index}")
        relative = require_relative_path(
            require_string(
                entry.get("path"), f"proof source inventory entry {index} path"
            ),
            f"proof source inventory entry {index} path",
        )
        byte_count = entry.get("bytes")
        if (
            not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or not 0 <= byte_count < 1 << 64
        ):
            reject(f"proof source inventory entry {index} byte count is invalid")
        digest_hex = require_sha512(
            entry.get("sha512"), f"proof source inventory entry {index} SHA-512"
        )
        path_bytes = relative.encode("utf-8")
        if len(path_bytes) >= 1 << 32:
            reject("proof source inventory path length exceeds u32")
        root_hasher.update(len(path_bytes).to_bytes(4, "little"))
        root_hasher.update(path_bytes)
        root_hasher.update(byte_count.to_bytes(8, "little"))
        root_hasher.update(bytes.fromhex(digest_hex))
    return root_hasher.hexdigest()


def recompute_retained_proof_source_inventory(root: Path) -> dict[str, object]:
    """Rebuild the local Cargo source closure without trusting artifact JSON."""

    repository_root = root.resolve(strict=True)
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--no-deps",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        reject(f"proof source inventory cargo metadata failed: {exc}")
    if completed.returncode != 0:
        reject(
            "proof source inventory cargo metadata failed: "
            + completed.stderr.decode("utf-8", errors="replace")[-2000:].replace("\n", " ")
        )
    try:
        metadata = json.loads(
            completed.stdout,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        reject(f"proof source inventory cargo metadata is invalid: {exc}")
    metadata = require_object(metadata, "proof source cargo metadata")
    metadata_root = Path(require_string(metadata.get("workspace_root"), "workspace_root"))
    if metadata_root.resolve(strict=True) != repository_root:
        reject("proof source cargo workspace root differs from release root")
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        reject("proof source cargo metadata packages must be an array")
    packages_by_root: dict[Path, dict[str, object]] = {}
    root_packages: dict[str, Path] = {}
    for index, raw_package in enumerate(packages):
        package = require_object(raw_package, f"cargo package {index}")
        manifest = Path(
            require_string(package.get("manifest_path"), f"cargo package {index} manifest")
        )
        package_root = manifest.parent
        try:
            package_root.relative_to(repository_root)
        except ValueError:
            continue
        if package_root in packages_by_root:
            reject("proof source cargo metadata contains duplicate local package roots")
        packages_by_root[package_root] = package
        package_name = package.get("name")
        if package_name in RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES:
            if package_name in root_packages:
                reject("proof source cargo metadata contains duplicate root packages")
            root_packages[str(package_name)] = package_root
    if set(root_packages) != set(RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES):
        reject("proof source cargo metadata omitted a required release root package")

    def load_excluded_local_package(package_root: Path) -> None:
        """Load one active workspace-excluded path package without resolving crates.io."""

        if package_root in packages_by_root:
            return
        try:
            canonical_root = package_root.resolve(strict=True)
            canonical_root.relative_to(repository_root)
        except (OSError, ValueError) as exc:
            raise SuccessorAuthorizationError(
                "active proof source local dependency escaped the release root"
            ) from exc
        if canonical_root != package_root or package_root.is_symlink():
            reject("active proof source local dependency path is noncanonical or symlinked")
        manifest_path = package_root / "Cargo.toml"
        command = [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
            str(manifest_path),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=repository_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            reject(f"excluded local package metadata failed: {exc}")
        if completed.returncode != 0:
            reject(
                "excluded local package metadata failed: "
                + completed.stderr.decode("utf-8", errors="replace")[-2000:].replace(
                    "\n", " "
                )
            )
        try:
            excluded_metadata = json.loads(
                completed.stdout,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonstandard_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            reject(f"excluded local package metadata is invalid: {exc}")
        excluded_metadata = require_object(
            excluded_metadata, "excluded local package metadata"
        )
        excluded_packages = excluded_metadata.get("packages")
        if not isinstance(excluded_packages, list):
            reject("excluded local package metadata packages must be an array")
        matches: list[dict[str, object]] = []
        for index, raw_package in enumerate(excluded_packages):
            package = require_object(
                raw_package, f"excluded cargo package {index}"
            )
            observed_manifest = Path(
                require_string(
                    package.get("manifest_path"),
                    f"excluded cargo package {index} manifest",
                )
            )
            if observed_manifest == manifest_path:
                matches.append(package)
        if len(matches) != 1:
            reject("excluded local package metadata did not identify one exact manifest")
        packages_by_root[package_root] = matches[0]
    requested_features: dict[Path, set[str]] = {
        package_root: set(RETAINED_SOURCE_INVENTORY_ROOT_FEATURES[package_name])
        for package_name, package_root in root_packages.items()
    }
    expanded_features: dict[Path, set[str]] = {}
    enabled_optional_dependencies: dict[Path, set[str]] = {}
    forwarded_dependency_features: dict[Path, dict[str, set[str]]] = {}
    pending = list(root_packages.values())
    closure: set[Path] = set()

    def expand_features(
        package: Mapping[str, object], seeds: set[str]
    ) -> tuple[set[str], set[str], dict[str, set[str]]]:
        feature_table_raw = package.get("features")
        if not isinstance(feature_table_raw, dict):
            reject("proof source cargo package features must be an object")
        feature_table: dict[str, list[str]] = {}
        for name_raw, members_raw in feature_table_raw.items():
            if not isinstance(name_raw, str) or not isinstance(members_raw, list):
                reject("proof source cargo feature table is malformed")
            if any(not isinstance(member, str) for member in members_raw):
                reject("proof source cargo feature members must be strings")
            feature_table[name_raw] = list(members_raw)
        dependencies_raw = package.get("dependencies")
        if not isinstance(dependencies_raw, list):
            reject("proof source cargo package dependencies must be an array")
        dependency_names = {
            str(dependency.get("rename") or dependency.get("name"))
            for dependency in dependencies_raw
            if isinstance(dependency, dict)
            and isinstance(dependency.get("name"), str)
        }
        active_features: set[str] = set()
        enabled_dependencies: set[str] = set()
        forwarded: dict[str, set[str]] = {}
        feature_queue = list(seeds)
        deferred_conditional: list[tuple[str, str]] = []
        while feature_queue:
            token = feature_queue.pop()
            if token.startswith("dep:"):
                dependency_name = token[4:]
                if dependency_name not in dependency_names:
                    reject("proof source Cargo feature enables an unknown dependency")
                enabled_dependencies.add(dependency_name)
                continue
            if "/" in token:
                dependency_name, dependency_feature = token.split("/", 1)
                conditional = dependency_name.endswith("?")
                dependency_name = dependency_name.removesuffix("?")
                if dependency_name not in dependency_names:
                    reject("proof source Cargo feature forwards to an unknown dependency")
                if conditional and dependency_name not in enabled_dependencies:
                    deferred_conditional.append((dependency_name, dependency_feature))
                    continue
                enabled_dependencies.add(dependency_name)
                forwarded.setdefault(dependency_name, set()).add(dependency_feature)
                continue
            if token in feature_table:
                if token in active_features:
                    continue
                active_features.add(token)
                feature_queue.extend(feature_table[token])
                continue
            if token == "default":
                # Cargo treats an omitted `default` feature as an empty set.
                continue
            if token in dependency_names:
                enabled_dependencies.add(token)
                continue
            reject(f"proof source Cargo feature references unknown token {token!r}")
        changed = True
        while changed:
            changed = False
            remaining: list[tuple[str, str]] = []
            for dependency_name, dependency_feature in deferred_conditional:
                if dependency_name in enabled_dependencies:
                    forwarded.setdefault(dependency_name, set()).add(
                        dependency_feature
                    )
                    changed = True
                else:
                    remaining.append((dependency_name, dependency_feature))
            deferred_conditional = remaining
        return active_features, enabled_dependencies, forwarded

    while pending:
        package_root = pending.pop()
        closure.add(package_root)
        package = packages_by_root.get(package_root)
        if package is None:
            reject("proof source local package closure escaped metadata")
        active_features, enabled_dependencies, forwarded = expand_features(
            package, requested_features.get(package_root, set())
        )
        if (
            expanded_features.get(package_root) == active_features
            and enabled_optional_dependencies.get(package_root)
            == enabled_dependencies
            and forwarded_dependency_features.get(package_root) == forwarded
        ):
            continue
        expanded_features[package_root] = active_features
        enabled_optional_dependencies[package_root] = enabled_dependencies
        forwarded_dependency_features[package_root] = forwarded
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            reject("proof source cargo package dependencies must be an array")
        for dependency_raw in dependencies:
            dependency = require_object(dependency_raw, "cargo dependency")
            dependency_path_raw = dependency.get("path")
            if dependency_path_raw is None:
                continue
            dependency_path = Path(
                require_string(dependency_path_raw, "cargo dependency path")
            )
            try:
                dependency_path.relative_to(repository_root)
            except ValueError:
                continue
            dependency_name = require_string(
                dependency.get("rename") or dependency.get("name"),
                "cargo dependency name",
            )
            optional = dependency.get("optional")
            if not isinstance(optional, bool):
                reject("proof source cargo dependency optional flag must be Boolean")
            if optional and dependency_name not in enabled_dependencies:
                continue
            if dependency_path not in packages_by_root:
                load_excluded_local_package(dependency_path)
            child_features = set()
            dependency_features = dependency.get("features")
            if not isinstance(dependency_features, list) or any(
                not isinstance(feature, str) for feature in dependency_features
            ):
                reject("proof source cargo dependency features must be strings")
            child_features.update(dependency_features)
            child_features.update(forwarded.get(dependency_name, set()))
            uses_default_features = dependency.get("uses_default_features")
            if not isinstance(uses_default_features, bool):
                reject(
                    "proof source cargo dependency default-feature flag must be Boolean"
                )
            if uses_default_features:
                child_features.add("default")
            observed = requested_features.setdefault(dependency_path, set())
            if dependency_path not in closure or not child_features.issubset(observed):
                observed.update(child_features)
                pending.append(dependency_path)

    inactive_optional_local_dependencies: list[dict[str, str]] = []
    for package_root in sorted(closure):
        package = packages_by_root[package_root]
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            reject("proof source cargo package dependencies must be an array")
        enabled_dependencies = enabled_optional_dependencies.get(package_root, set())
        for dependency_raw in dependencies:
            dependency = require_object(dependency_raw, "cargo dependency")
            dependency_path_raw = dependency.get("path")
            if dependency_path_raw is None:
                continue
            dependency_path = Path(
                require_string(dependency_path_raw, "cargo dependency path")
            )
            try:
                dependency_relative = dependency_path.relative_to(repository_root).as_posix()
            except ValueError:
                continue
            dependency_name = require_string(
                dependency.get("rename") or dependency.get("name"),
                "cargo dependency name",
            )
            if dependency.get("optional") is True and dependency_name not in enabled_dependencies:
                inactive_optional_local_dependencies.append(
                    {
                        "package_manifest": (
                            package_root / "Cargo.toml"
                        ).relative_to(repository_root).as_posix(),
                        "dependency_name": dependency_name,
                        "dependency_path": dependency_relative,
                        "reason": "inactive_in_source_owned_default_feature_graph",
                    }
                )

    files: set[Path] = {
        repository_root / relative
        for relative in RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_FILES
    }
    excluded_names = {".agent", ".git", ".lake", "target"}
    source_roots = set(closure)
    source_roots.update(
        repository_root / relative
        for relative in RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES
    )
    for source_root in sorted(source_roots):
        stack = [source_root]
        while stack:
            directory = stack.pop()
            try:
                directory_entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
            except OSError as exc:
                reject(f"proof source directory {directory} is unreadable: {exc}")
            for entry in directory_entries:
                path = Path(entry.path)
                if entry.is_symlink():
                    reject(f"proof source inventory rejects symlink {path}")
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in excluded_names:
                        stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.add(path)
                    if len(files) > RETAINED_SOURCE_INVENTORY_MAX_FILES:
                        reject("proof source inventory file cap exceeded")
                else:
                    reject(f"proof source inventory rejects non-regular entry {path}")

    entries: list[dict[str, object]] = []
    total_bytes = 0
    ordered_files = sorted(
        files, key=lambda value: value.relative_to(repository_root).as_posix()
    )
    for path in ordered_files:
        relative = path.relative_to(repository_root).as_posix()
        canonical = require_relative_path(relative, "proof source inventory path")
        _, payload = read_regular_file_beneath(
            repository_root,
            canonical,
            f"proof source file {canonical}",
            RETAINED_SOURCE_INVENTORY_MAX_FILE_BYTES,
        )
        total_bytes += len(payload)
        if total_bytes > RETAINED_SOURCE_INVENTORY_MAX_TOTAL_BYTES:
            reject("proof source inventory total byte cap exceeded")
        digest = hashlib.sha512(payload).digest()
        entries.append(
            {"path": canonical, "bytes": len(payload), "sha512": digest.hex()}
        )
    package_manifests = [
        (package_root / "Cargo.toml").relative_to(repository_root).as_posix()
        for package_root in sorted(closure)
    ]
    return {
        "schema": RETAINED_SOURCE_INVENTORY_SCHEMA,
        "root_package": RETAINED_SOURCE_INVENTORY_ROOT_PACKAGE,
        "root_packages": list(RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES),
        "root_features": {
            package: list(RETAINED_SOURCE_INVENTORY_ROOT_FEATURES[package])
            for package in RETAINED_SOURCE_INVENTORY_ROOT_PACKAGES
        },
        "required_root_directories": list(
            RETAINED_SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES
        ),
        "cargo_metadata_arguments": [
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--no-deps",
        ],
        "excluded_directory_names": [".agent", ".git", ".lake", "target"],
        "maximum_files": RETAINED_SOURCE_INVENTORY_MAX_FILES,
        "maximum_file_bytes": RETAINED_SOURCE_INVENTORY_MAX_FILE_BYTES,
        "maximum_total_bytes": RETAINED_SOURCE_INVENTORY_MAX_TOTAL_BYTES,
        "package_manifests": package_manifests,
        "activated_features": [
            {
                "package_manifest": (
                    package_root / "Cargo.toml"
                ).relative_to(repository_root).as_posix(),
                "features": sorted(expanded_features.get(package_root, set())),
            }
            for package_root in sorted(closure)
        ],
        "inactive_optional_local_dependencies": sorted(
            inactive_optional_local_dependencies,
            key=lambda item: (
                item["package_manifest"],
                item["dependency_name"],
                item["dependency_path"],
            ),
        ),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "root_sha512": proof_source_inventory_root_sha512(
            entries, RETAINED_SOURCE_INVENTORY_DOMAIN
        ),
        "entries": entries,
    }


def run_with_source_inventory_guard(
    argv: list[str],
    root: Path,
    command_runner: ArtifactCommandRunner,
    expected_source_inventory_sha512: str,
    expected_source_revision: str,
    label: str,
) -> tuple[int, str]:
    """Execute only while the clean revision and release closure stay unchanged."""

    if resolve_checkout_source_revision(root) != expected_source_revision:
        reject(f"{label} source revision differs before execution")
    before = recompute_retained_proof_source_inventory(root)
    if before.get("root_sha512") != expected_source_inventory_sha512:
        reject(f"{label} source inventory differs before execution")
    result = command_runner(argv, root)
    after = recompute_retained_proof_source_inventory(root)
    if after.get("root_sha512") != expected_source_inventory_sha512:
        reject(f"{label} source inventory changed during execution")
    if resolve_checkout_source_revision(root) != expected_source_revision:
        reject(f"{label} source revision changed during execution")
    return result


def load_canonical_json_bytes(payload: bytes, label: str, maximum: int) -> object:
    if len(payload) > maximum:
        reject(f"{label} exceeds {maximum} bytes")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SuccessorAuthorizationError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if payload != canonical_json_bytes(document):
        reject(f"{label} is not exact canonical JSON or contains trailing bytes")
    return document


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        reject(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        reject(
            f"{label} keys mismatch; missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        reject(f"{label} must be a nonempty string")
    return value


def require_positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        reject(f"{label} must be a positive integer")
    return value


def require_nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        reject(f"{label} must be a nonnegative integer")
    return value


def require_goldilocks_root(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or len(value) != 7:
        reject(f"{label} must be an array of exactly 7 canonical field limbs")
    for index, limb in enumerate(value):
        if (
            isinstance(limb, bool)
            or not isinstance(limb, int)
            or limb < 0
            or limb >= GOLDILOCKS_MODULUS
        ):
            reject(
                f"{label}[{index}] must be a canonical Goldilocks field limb"
            )
    return value


def require_true(value: object, label: str) -> None:
    if value is not True:
        reject(f"{label} must equal true")


def require_false(value: object, label: str) -> None:
    if value is not False:
        reject(f"{label} must equal false")


def require_rejected_mutations(
    value: object,
    expected_names: tuple[str, ...],
    label: str,
    *,
    includes_error: bool,
) -> None:
    if not isinstance(value, list) or len(value) != len(expected_names):
        reject(f"{label} must contain the exact ordered mutation inventory")
    expected_keys = {"name", "rejected", "error"} if includes_error else {
        "name",
        "rejected",
    }
    for index, (entry_value, expected_name) in enumerate(zip(value, expected_names)):
        entry = require_object(entry_value, f"{label}[{index}]")
        require_exact_keys(entry, expected_keys, f"{label}[{index}]")
        if entry.get("name") != expected_name:
            reject(f"{label}[{index}] mutation name mismatch")
        require_true(entry.get("rejected"), f"{label}[{index}].rejected")
        if includes_error:
            require_string(
                entry.get("error"), f"{label}[{index}].error"
            )


def require_sha512(value: object, label: str) -> str:
    digest = require_string(value, label)
    if len(digest) != SHA512_HEX_BYTES:
        reject(f"{label} must be exactly 128 lowercase SHA-512 hexadecimal characters")
    if digest != digest.lower() or any(character not in "0123456789abcdef" for character in digest):
        reject(f"{label} must be exactly 128 lowercase SHA-512 hexadecimal characters")
    return digest


def require_nonzero_sha512(value: object, label: str) -> str:
    digest = require_sha512(value, label)
    if set(digest) == {"0"}:
        reject(f"{label} must not be the all-zero SHA-512 value")
    return digest


def require_u32(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF:
        reject(f"{label} must be an integer in 0..=4294967295")
    return value


def require_fixed_width_nonzero_hex(
    value: object, label: str, digest_bytes: int, width_label: str
) -> str:
    encoded = require_string(value, label)
    expected_characters = digest_bytes * 2
    if (
        len(encoded) != expected_characters
        or encoded != encoded.lower()
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        reject(
            f"{label} must be exactly {digest_bytes} bytes of lowercase hexadecimal "
            f"to match {width_label}"
        )
    if set(encoded) == {"0"}:
        reject(f"{label} must not be the all-zero {digest_bytes}-byte value")
    return encoded


def require_magic_hex(value: object, label: str) -> str:
    encoded = require_string(value, label)
    if (
        len(encoded) % 2 != 0
        or len(encoded) < 2
        or len(encoded) > 64
        or encoded != encoded.lower()
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        reject(f"{label} must be 1..32 bytes of lowercase hexadecimal")
    return encoded


def load_evidence_manifest(payload: bytes, label: str) -> dict[str, object]:
    """Parse a digest-pinned manifest while still rejecting ambiguous JSON."""

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SuccessorAuthorizationError(
            f"{label} is not valid UTF-8 JSON: {exc}"
        ) from exc
    return require_object(document, label)


def validate_executable_zk_refinement_report(
    payload: bytes,
    identity: Mapping[str, object],
) -> None:
    """Validate the source-pinned raw executable-ZK report without wrapping it.

    This report deliberately records a non-authorizing simulator/refinement
    result. It is not shaped like a positive release receipt, so accepting a
    synthetic generic wrapper would erase its fail-closed claim boundary. The
    source checker instead pins its one canonical path (at bundle admission),
    exact bytes and full SHA-512, then reads the raw fields that exclude the
    omitted salt-only programming route.
    """

    label = f"evidence {EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID}"
    document = load_evidence_manifest(payload, label)
    if document.get("schema") != EXECUTABLE_ZK_REFINEMENT_SCHEMA:
        reject(f"{label} schema mismatch")
    if document.get("relation_program_sha512_hex") != identity[
        "relation_program_sha512"
    ]:
        reject(f"{label} relation-program pin mismatch")
    if document.get("relation_digest_hex") != identity["relation_digest_hex"]:
        reject(f"{label} relation digest mismatch")
    if document.get("profile_wire_id") != identity["profile_wire_id"]:
        reject(f"{label} profile wire id mismatch")
    expected_magic = bytes.fromhex(str(identity["inner_proof_wire_magic_hex"])).decode(
        "ascii"
    )
    if document.get("proof_wire_magic_ascii") != expected_magic:
        reject(f"{label} proof wire magic mismatch")
    salt_only_count = document.get("salt_only_oracle_program_count")
    if isinstance(salt_only_count, bool) or salt_only_count != 0:
        reject(f"{label}.salt_only_oracle_program_count must equal integer zero")
    require_true(
        document.get("exact_lazy_program_keys_exclude_salt_only_point"),
        f"{label}.exact_lazy_program_keys_exclude_salt_only_point",
    )
    require_false(
        document.get("direct_256_bit_first_program_route_used"),
        f"{label}.direct_256_bit_first_program_route_used",
    )
    require_false(
        document.get("production_eligible"),
        f"{label}.production_eligible",
    )
    if len(payload) != EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES:
        reject(
            f"{label} byte length must equal the source-pinned "
            f"{EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES} bytes"
        )
    if sha512_bytes(payload) != EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512:
        reject(f"{label} SHA-512 does not match the source-pinned raw report")


def validate_release_evidence_document(
    evidence_id: str,
    kind: str,
    payload: bytes,
    profile: "AuthorizedProfile",
    identity: Mapping[str, object],
    expected_source_files: list[dict[str, str]],
    expected_source_revision: str,
    expected_source_inventory_sha512: str,
    expected_primary_proof_sha512: str,
    expected_primary_proof_bytes: int,
    expected_independent_proof_sha512: str,
    root: Path,
    command_runner: ArtifactCommandRunner,
) -> None:
    """Require a positive, identity-bound schema for non-source release evidence."""

    document = load_evidence_manifest(payload, f"evidence {evidence_id}")
    require_exact_keys(document, RELEASE_EVIDENCE_BASE_KEYS, f"evidence {evidence_id}")
    expected_schema = RELEASE_EVIDENCE_SCHEMA_OVERRIDES.get(
        evidence_id, f"hegemon.smallwood.poseidon2-v8.{evidence_id}.v1"
    )
    if document.get("schema") != expected_schema:
        reject(f"evidence {evidence_id} schema mismatch")
    if document.get("evidence_id") != evidence_id:
        reject(f"evidence {evidence_id} self-identity mismatch")
    if document.get("kind") != kind:
        reject(f"evidence {evidence_id} document kind mismatch")
    if document.get("profile_id") != profile.profile_id:
        reject(f"evidence {evidence_id} document profile mismatch")
    if document.get("relation_program_sha512") != identity["relation_program_sha512"]:
        reject(f"evidence {evidence_id} document relation-program pin mismatch")
    source_revision = require_string(
        document.get("source_revision"), f"evidence {evidence_id}.source_revision"
    )
    if source_revision != expected_source_revision:
        reject(f"evidence {evidence_id}.source_revision differs from the release bundle")
    if document.get("source_files") != expected_source_files:
        reject(f"evidence {evidence_id} source-file inventory mismatch")
    require_true(
        document.get("release_gate_passed"),
        f"evidence {evidence_id}.release_gate_passed",
    )
    if document.get("authority_conferred") is not False:
        reject(f"evidence {evidence_id}.authority_conferred must equal false")
    claim_boundary = require_string(
        document.get("claim_boundary"), f"evidence {evidence_id}.claim_boundary"
    )
    if not claim_boundary.strip():
        reject(f"evidence {evidence_id}.claim_boundary must contain non-whitespace text")

    result = require_object(document.get("result"), f"evidence {evidence_id}.result")
    expected_result_keys = set(RELEASE_EVIDENCE_RESULT_KEYS)
    if evidence_id in LIFECYCLE_INTEGRATION_EVIDENCE:
        expected_result_keys.add("integration")
    if evidence_id == PRODUCTION_CAPABILITY_MANIFEST_EVIDENCE_ID:
        expected_result_keys.add("capability")
    if evidence_id == PRODUCTION_VALUE_BALANCE_EVIDENCE_ID:
        expected_result_keys.add("projection")
    if evidence_id == PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID:
        expected_result_keys.add("proof_lifetime_accounting")
    if evidence_id == INDEPENDENT_REVIEW_EVIDENCE_ID:
        expected_result_keys.add("review_attestation")
    if evidence_id in FORMAL_SECURITY_RECEIPT_BINDINGS:
        expected_result_keys.add("formal_receipt")
    require_exact_keys(result, expected_result_keys, f"evidence {evidence_id}.result")
    if result.get("status") != "passed":
        reject(f"evidence {evidence_id}.result.status must equal passed")
    require_true(result.get("passed"), f"evidence {evidence_id}.result.passed")
    if result.get("profile_id") != profile.profile_id:
        reject(f"evidence {evidence_id}.result profile mismatch")
    if result.get("semantic_relation") != RETAINED_SEMANTIC_RELATION:
        reject(f"evidence {evidence_id}.result semantic relation mismatch")
    if result.get("relation_program_sha512") != identity["relation_program_sha512"]:
        reject(f"evidence {evidence_id}.result relation-program pin mismatch")
    if result.get("source_revision") != source_revision:
        reject(f"evidence {evidence_id}.result source revision mismatch")
    if result.get("unresolved_premises") != []:
        reject(f"evidence {evidence_id}.result unresolved premises must be empty")
    checks = result.get("checks")
    if not isinstance(checks, list) or not checks:
        reject(f"evidence {evidence_id}.result.checks must be a nonempty array")
    observed_check_names: set[str] = set()
    check_output_by_command: dict[str, str] = {}
    for index, check_value in enumerate(checks):
        check = require_object(check_value, f"evidence {evidence_id}.result.checks[{index}]")
        require_exact_keys(
            check,
            RELEASE_EVIDENCE_CHECK_KEYS,
            f"evidence {evidence_id}.result.checks[{index}]",
        )
        name = require_string(
            check.get("name"), f"evidence {evidence_id}.result.checks[{index}].name"
        )
        if not name.strip() or name in observed_check_names:
            reject(f"evidence {evidence_id}.result checks must have unique nonempty names")
        observed_check_names.add(name)
        command = require_string(
            check.get("command"),
            f"evidence {evidence_id}.result.checks[{index}].command",
        )
        if not command.strip():
            reject(f"evidence {evidence_id}.result check command must be nonempty")
        if command in check_output_by_command:
            reject(f"evidence {evidence_id}.result checks must not repeat a command")
        if check.get("exit_code") != 0:
            reject(f"evidence {evidence_id}.result check exit_code must equal zero")
        require_true(
            check.get("passed"), f"evidence {evidence_id}.result.checks[{index}].passed"
        )
        output_sha512 = require_nonzero_sha512(
            check.get("output_sha512"),
            f"evidence {evidence_id}.result.checks[{index}].output_sha512",
        )
        check_output_by_command[command] = output_sha512

    if evidence_id == PRODUCTION_CAPABILITY_MANIFEST_EVIDENCE_ID:
        capability = require_object(
            result.get("capability"),
            f"evidence {evidence_id}.result.capability",
        )
        require_exact_keys(
            capability,
            set(CAPABILITY_IDENTITY_FIELDS),
            f"evidence {evidence_id}.result.capability",
        )
        expected_capability = {
            field: identity[field] for field in CAPABILITY_IDENTITY_FIELDS
        }
        if capability != expected_capability:
            reject(f"evidence {evidence_id} capability tuple mismatch")

    if evidence_id == PRODUCTION_VALUE_BALANCE_EVIDENCE_ID:
        projection = require_object(
            result.get("projection"),
            f"evidence {evidence_id}.result.projection",
        )
        require_exact_keys(
            projection,
            PRODUCTION_VALUE_BALANCE_PROJECTION_KEYS,
            f"evidence {evidence_id}.result.projection",
        )
        require_false(
            projection.get("transparent_pool_enabled"),
            f"evidence {evidence_id}.result.projection.transparent_pool_enabled",
        )
        for field in (
            "relation_enforces_zero",
            "wallet_projection_enforces_zero",
            "native_projection_enforces_zero",
        ):
            require_true(
                projection.get(field),
                f"evidence {evidence_id}.result.projection.{field}",
            )

    if evidence_id == PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID:
        accounting = require_object(
            result.get("proof_lifetime_accounting"),
            f"evidence {evidence_id}.result.proof_lifetime_accounting",
        )
        require_exact_keys(
            accounting,
            PROOF_LIFETIME_ACCOUNTING_KEYS,
            f"evidence {evidence_id}.result.proof_lifetime_accounting",
        )
        expected_scalars = {
            "scope": "canonical_accepted_smallwood_v8_transaction_proofs",
            "conditional_max_proofs_per_block": CONDITIONAL_MAX_V8_PROOFS_PER_BLOCK,
            "conditional_accounting_window_blocks": CONDITIONAL_V8_ACCOUNTING_WINDOW_BLOCKS,
            "conditional_accounting_window_proofs": CONDITIONAL_V8_ACCOUNTING_WINDOW_PROOFS,
            "conditional_max_total_proofs_at_128_bits": (
                CONDITIONAL_MAX_TOTAL_V8_PROOFS_AT_128_BITS
            ),
        }
        for field, expected_value in expected_scalars.items():
            if accounting.get(field) != expected_value:
                reject(
                    f"evidence {evidence_id}.result.proof_lifetime_accounting."
                    f"{field} mismatch"
                )
        for field in (
            "persistent_checked_canonical_count",
            "count_overflow_rejected",
            "lifetime_limit_rejected",
            "restart_deterministic",
            "sync_replay_deterministic",
            "reorg_restores_ancestor_count",
            "fresh_replay_exact_rows",
            "conditional_accounting_only",
        ):
            require_true(
                accounting.get(field),
                f"evidence {evidence_id}.result.proof_lifetime_accounting.{field}",
            )
        for field in (
            "accounting_window_is_cryptographic_reset",
            "counts_all_verifier_invocations",
            "deployed_security_claimed",
        ):
            require_false(
                accounting.get(field),
                f"evidence {evidence_id}.result.proof_lifetime_accounting.{field}",
            )

    if evidence_id in FORMAL_SECURITY_RECEIPT_BINDINGS:
        expected_binding = FORMAL_SECURITY_RECEIPT_BINDINGS[evidence_id]
        formal_receipt = require_object(
            result.get("formal_receipt"),
            f"evidence {evidence_id}.result.formal_receipt",
        )
        require_exact_keys(
            formal_receipt,
            FORMAL_SECURITY_RECEIPT_KEYS,
            f"evidence {evidence_id}.result.formal_receipt",
        )
        for field in ("scope", "formal_source_path", "release_theorem"):
            if formal_receipt.get(field) != expected_binding[field]:
                reject(f"evidence {evidence_id} formal receipt {field} mismatch")
        source_path = require_relative_path(
            formal_receipt.get("formal_source_path"),
            f"evidence {evidence_id}.result.formal_receipt.formal_source_path",
        )
        _, formal_source = read_regular_file_beneath(
            root,
            source_path,
            f"evidence {evidence_id} formal receipt source",
            RETAINED_SOURCE_INVENTORY_MAX_FILE_BYTES,
        )
        formal_source_sha512 = require_nonzero_sha512(
            formal_receipt.get("formal_source_sha512"),
            f"evidence {evidence_id}.result.formal_receipt.formal_source_sha512",
        )
        if sha512_bytes(formal_source) != formal_source_sha512:
            reject(f"evidence {evidence_id} formal receipt source digest mismatch")
        theorem_name = require_string(
            formal_receipt.get("release_theorem"),
            f"evidence {evidence_id}.result.formal_receipt.release_theorem",
        )
        theorem_leaf = theorem_name.rsplit(".", 1)[-1]
        try:
            formal_source_text = formal_source.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SuccessorAuthorizationError(
                f"evidence {evidence_id} formal receipt source is not UTF-8"
            ) from exc
        if re.search(
            rf"(?m)^\s*(?:theorem|lemma)\s+{re.escape(theorem_leaf)}(?:\s|:)",
            formal_source_text,
        ) is None:
            reject(
                f"evidence {evidence_id} exact positive release theorem is absent "
                "from its canonical formal source"
            )
        require_true(
            formal_receipt.get("release_receipt_constructed"),
            f"evidence {evidence_id}.result.formal_receipt.release_receipt_constructed",
        )
        require_true(
            formal_receipt.get("all_release_inputs_instantiated"),
            f"evidence {evidence_id}.result.formal_receipt.all_release_inputs_instantiated",
        )
        concrete_floor = require_positive_integer(
            formal_receipt.get("concrete_security_bits_floor"),
            f"evidence {evidence_id}.result.formal_receipt.concrete_security_bits_floor",
        )
        if concrete_floor < 128:
            reject(f"evidence {evidence_id} formal receipt security floor is below 128 bits")
        expected_formal_binding = {
            "source_inventory_sha512": expected_source_inventory_sha512,
            "capability_identity_sha512": capability_identity_sha512(identity),
            "retained_proof_primary_sha512": expected_primary_proof_sha512,
            "retained_proof_independent_sha512": expected_independent_proof_sha512,
        }
        for field, expected_value in expected_formal_binding.items():
            if formal_receipt.get(field) != expected_value:
                reject(f"evidence {evidence_id} formal receipt {field} mismatch")

    independent_review_verification_command: str | None = None
    if evidence_id == INDEPENDENT_REVIEW_EVIDENCE_ID:
        review = require_object(
            result.get("review_attestation"),
            f"evidence {evidence_id}.result.review_attestation",
        )
        require_exact_keys(
            review,
            INDEPENDENT_REVIEW_ATTESTATION_KEYS,
            f"evidence {evidence_id}.result.review_attestation",
        )
        trust_root_id = require_string(
            review.get("trust_root_id"),
            f"evidence {evidence_id}.result.review_attestation.trust_root_id",
        )
        trust_root = SOURCE_BOUND_INDEPENDENT_REVIEW_TRUST_ROOTS.get(trust_root_id)
        if trust_root is None:
            reject(
                f"evidence {evidence_id} has no source-bound authenticated review trust root"
            )
        require_exact_keys(
            trust_root,
            INDEPENDENT_REVIEW_TRUST_ROOT_KEYS,
            f"source review trust root {trust_root_id}",
        )
        if trust_root.get("trust_root_id") != trust_root_id:
            reject("source review trust-root self-identity mismatch")
        if trust_root.get("signature_scheme") != "ML-DSA-87":
            reject("source review trust root must use ML-DSA-87")
        reviewer_identity = require_string(
            trust_root.get("reviewer_identity"),
            f"source review trust root {trust_root_id}.reviewer_identity",
        )
        public_key_sha512 = require_nonzero_sha512(
            trust_root.get("public_key_sha512"),
            f"source review trust root {trust_root_id}.public_key_sha512",
        )
        public_key_bytes = require_positive_integer(
            trust_root.get("public_key_bytes"),
            f"source review trust root {trust_root_id}.public_key_bytes",
        )
        if public_key_bytes != ML_DSA_87_PUBLIC_KEY_BYTES:
            reject("source review trust root has the wrong ML-DSA-87 public-key size")
        path_fields = ("public_key_path", "review_artifact_path", "signature_path")
        trusted_paths: dict[str, str] = {}
        for field in path_fields:
            trusted_path = require_relative_path(
                trust_root.get(field), f"source review trust root {trust_root_id}.{field}"
            )
            if review.get(field) != trusted_path:
                reject(f"evidence {evidence_id} review {field} mismatch")
            trusted_paths[field] = trusted_path
        if len(set(trusted_paths.values())) != len(trusted_paths):
            reject("source review key, artifact, and signature paths must be distinct")
        if review.get("public_key_bytes") != public_key_bytes:
            reject(f"evidence {evidence_id} review public-key length mismatch")
        if review.get("public_key_sha512") != public_key_sha512:
            reject(f"evidence {evidence_id} review public-key digest mismatch")
        _, public_key_payload = read_regular_file_beneath(
            root,
            trusted_paths["public_key_path"],
            f"evidence {evidence_id} independent review public key",
            ML_DSA_87_PUBLIC_KEY_BYTES,
        )
        if (
            len(public_key_payload) != ML_DSA_87_PUBLIC_KEY_BYTES
            or sha512_bytes(public_key_payload) != public_key_sha512
            or not any(public_key_payload)
        ):
            reject(f"evidence {evidence_id} independent review public key mismatch")
        review_artifact_bytes = require_positive_integer(
            review.get("review_artifact_bytes"),
            f"evidence {evidence_id}.result.review_attestation.review_artifact_bytes",
        )
        review_artifact_sha512 = require_nonzero_sha512(
            review.get("review_artifact_sha512"),
            f"evidence {evidence_id}.result.review_attestation.review_artifact_sha512",
        )
        _, review_artifact_payload = read_regular_file_beneath(
            root,
            trusted_paths["review_artifact_path"],
            f"evidence {evidence_id} independent review artifact",
            MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES,
        )
        if (
            len(review_artifact_payload) != review_artifact_bytes
            or sha512_bytes(review_artifact_payload) != review_artifact_sha512
        ):
            reject(f"evidence {evidence_id} independent review artifact mismatch")
        signature_bytes = require_positive_integer(
            review.get("signature_bytes"),
            f"evidence {evidence_id}.result.review_attestation.signature_bytes",
        )
        if signature_bytes != ML_DSA_87_SIGNATURE_BYTES:
            reject(f"evidence {evidence_id} has the wrong ML-DSA-87 signature size")
        signature_sha512 = require_nonzero_sha512(
            review.get("signature_sha512"),
            f"evidence {evidence_id}.result.review_attestation.signature_sha512",
        )
        _, signature_payload = read_regular_file_beneath(
            root,
            trusted_paths["signature_path"],
            f"evidence {evidence_id} independent review signature",
            ML_DSA_87_SIGNATURE_BYTES,
        )
        if (
            len(signature_payload) != ML_DSA_87_SIGNATURE_BYTES
            or sha512_bytes(signature_payload) != signature_sha512
            or not any(signature_payload)
        ):
            reject(f"evidence {evidence_id} independent review signature mismatch")
        review_artifact = require_object(
            load_canonical_json_bytes(
                review_artifact_payload,
                f"evidence {evidence_id} independent review artifact",
                MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES,
            ),
            f"evidence {evidence_id} independent review artifact",
        )
        require_exact_keys(
            review_artifact,
            INDEPENDENT_REVIEW_ARTIFACT_KEYS,
            f"evidence {evidence_id} independent review artifact",
        )
        if review_artifact.get("schema") != INDEPENDENT_REVIEW_ARTIFACT_SCHEMA:
            reject(f"evidence {evidence_id} independent review artifact schema mismatch")
        if review_artifact.get("review_id") != evidence_id:
            reject(f"evidence {evidence_id} independent review artifact id mismatch")
        if review_artifact.get("reviewer_identity") != reviewer_identity:
            reject(f"evidence {evidence_id} independent reviewer identity mismatch")
        if review_artifact.get("approved_for_production") is not True:
            reject(f"evidence {evidence_id} independent review did not approve production")
        if review_artifact.get("blockers") != []:
            reject(f"evidence {evidence_id} independent review has unresolved blockers")
        if review_artifact.get("security_conclusion") != (
            "independent_review_confirms_release_security_and_implementation"
        ):
            reject(f"evidence {evidence_id} independent review conclusion mismatch")
        if review.get("reviewed_source_revision") != expected_source_revision:
            reject(f"evidence {evidence_id} reviewed source revision mismatch")
        if (
            review.get("reviewed_source_inventory_sha512")
            != expected_source_inventory_sha512
        ):
            reject(f"evidence {evidence_id} reviewed source inventory mismatch")
        if (
            review.get("reviewed_capability_identity_sha512")
            != capability_identity_sha512(identity)
        ):
            reject(f"evidence {evidence_id} reviewed capability identity mismatch")
        if review.get("reviewed_primary_proof_sha512") != expected_primary_proof_sha512:
            reject(f"evidence {evidence_id} reviewed primary proof mismatch")
        if (
            review.get("reviewed_independent_proof_sha512")
            != expected_independent_proof_sha512
        ):
            reject(f"evidence {evidence_id} reviewed independent proof mismatch")
        review_artifact_binding = {
            "reviewed_source_revision": expected_source_revision,
            "reviewed_source_inventory_sha512": expected_source_inventory_sha512,
            "reviewed_capability_identity_sha512": capability_identity_sha512(identity),
            "reviewed_primary_proof_sha512": expected_primary_proof_sha512,
            "reviewed_independent_proof_sha512": expected_independent_proof_sha512,
        }
        for field, expected_value in review_artifact_binding.items():
            if review_artifact.get(field) != expected_value:
                reject(f"evidence {evidence_id} independent review artifact {field} mismatch")
        independent_review_verification_command = require_string(
            review.get("verification_command"),
            f"evidence {evidence_id}.result.review_attestation.verification_command",
        )
        if (
            trust_root.get("verification_command")
            != independent_review_verification_command
        ):
            reject(f"evidence {evidence_id} review verification command mismatch")

    if evidence_id in SOURCE_EXECUTABLE_RELEASE_EVIDENCE_IDS:
        source_commands = SOURCE_BOUND_RELEASE_EVIDENCE_COMMANDS.get(evidence_id)
        if not isinstance(source_commands, tuple) or not source_commands:
            reject(
                f"evidence {evidence_id} has no source-bound executable evidence "
                "command inventory"
            )
        if len(set(source_commands)) != len(source_commands):
            reject(f"evidence {evidence_id} repeats a source-bound evidence command")
        if (
            independent_review_verification_command is not None
            and source_commands != (independent_review_verification_command,)
        ):
            reject(
                f"evidence {evidence_id} source command inventory does not equal "
                "the authenticated review verifier command"
            )
        source_inventory_sha512 = expected_source_inventory_sha512
        for expected_command in source_commands:
            if not isinstance(expected_command, str) or not expected_command:
                reject(
                    f"source-bound evidence command for {evidence_id} must be a "
                    "nonempty string"
                )
            try:
                argv = shlex.split(expected_command, posix=True)
            except ValueError as exc:
                raise SuccessorAuthorizationError(
                    f"source-bound evidence command for {evidence_id} is malformed: {exc}"
                ) from exc
            if not argv or shlex.join(argv) != expected_command:
                reject(
                    f"source-bound evidence command for {evidence_id} must use "
                    "canonical argv spelling"
                )
            try:
                returncode, output = run_with_source_inventory_guard(
                    argv,
                    root,
                    command_runner,
                    expected_source_inventory_sha512,
                    expected_source_revision,
                    f"source-bound evidence command for {evidence_id}",
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                reject(
                    f"source-bound evidence command for {evidence_id} failed to run: {exc}"
                )
            if returncode != 0:
                tail = output[-2000:].replace("\n", " ").strip()
                reject(
                    f"source-bound evidence command for {evidence_id} rejected current "
                    f"source: {tail}"
                )
            output_payload = output.encode("utf-8")
            output_sha512 = sha512_bytes(output_payload)
            if check_output_by_command.get(expected_command) != output_sha512:
                reject(
                    f"evidence {evidence_id} source command output is not bound to "
                    "its positive check receipt"
                )
            command_receipt = require_object(
                load_canonical_json_bytes(
                    output_payload,
                    f"source-bound evidence command receipt for {evidence_id}",
                    MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES,
                ),
                f"source-bound evidence command receipt for {evidence_id}",
            )
            require_exact_keys(
                command_receipt,
                SOURCE_COMMAND_RECEIPT_KEYS,
                f"source-bound evidence command receipt for {evidence_id}",
            )
            expected_receipt = {
                "schema": SOURCE_COMMAND_RECEIPT_SCHEMA,
                "evidence_id": evidence_id,
                "kind": kind,
                "profile_id": profile.profile_id,
                "relation_program_sha512": identity["relation_program_sha512"],
                "source_revision": source_revision,
                "source_inventory_sha512": source_inventory_sha512,
                "retained_proof_primary_sha512": expected_primary_proof_sha512,
                "retained_proof_independent_sha512": expected_independent_proof_sha512,
                "source_derived_security_report_sha512": identity[
                    "source_derived_security_report_sha512"
                ],
                "capability_identity_sha512": capability_identity_sha512(identity),
                "evidence_claim_sha512": release_evidence_claim_sha512(
                    evidence_id, result
                ),
                "release_workflow_sha512": RELEASE_WORKFLOW_SHA512,
                "passed": True,
                "unresolved_premises": [],
            }
            if command_receipt != expected_receipt:
                reject(
                    f"source-bound evidence command receipt for {evidence_id} "
                    "does not match the exact release identity"
                )

    if evidence_id in LIFECYCLE_INTEGRATION_EVIDENCE:
        source_bound_commands = SOURCE_BOUND_LIFECYCLE_INTEGRATION_COMMANDS.get(
            evidence_id
        )
        if source_bound_commands is None:
            reject(
                f"evidence {evidence_id} has no source-bound actual lifecycle "
                "integration command inventory"
            )
        integration = require_object(
            result.get("integration"), f"evidence {evidence_id}.result.integration"
        )
        require_exact_keys(
            integration,
            LIFECYCLE_INTEGRATION_KEYS,
            f"evidence {evidence_id}.result.integration",
        )
        if integration.get("execution_kind") != "actual_subsystem_integration":
            reject(f"evidence {evidence_id} must use actual subsystem integration")
        if integration.get("retained_proof_id") != "retained_proof_primary":
            reject(f"evidence {evidence_id} must exercise retained_proof_primary")
        lifecycle_proof_sha512 = require_sha512(
            integration.get("proof_sha512"),
            f"evidence {evidence_id}.result.integration.proof_sha512",
        )
        if lifecycle_proof_sha512 != expected_primary_proof_sha512:
            reject(f"evidence {evidence_id} lifecycle proof digest is not the retained primary")
        lifecycle_proof_bytes = require_positive_integer(
            integration.get("proof_bytes"),
            f"evidence {evidence_id}.result.integration.proof_bytes",
        )
        if lifecycle_proof_bytes != expected_primary_proof_bytes:
            reject(f"evidence {evidence_id} lifecycle proof byte length mismatch")
        validate_lifecycle_capability(
            integration.get("capability"),
            identity,
            f"evidence {evidence_id}.result.integration.capability",
        )
        if integration.get("capability_identity_sha512") != capability_identity_sha512(
            identity
        ):
            reject(f"evidence {evidence_id} lifecycle capability identity mismatch")
        lifecycle_state_binding = validate_lifecycle_state_binding(
            integration.get("state_binding"),
            identity,
            f"evidence {evidence_id}.result.integration.state_binding",
        )
        require_true(
            integration.get("same_proof_bytes_at_every_stage"),
            f"evidence {evidence_id}.result.integration.same_proof_bytes_at_every_stage",
        )
        require_true(
            integration.get("production_verifier_used"),
            f"evidence {evidence_id}.result.integration.production_verifier_used",
        )
        require_false(
            integration.get("parser_stage_labels_used_as_authority"),
            f"evidence {evidence_id}.result.integration.parser_stage_labels_used_as_authority",
        )
        require_false(
            integration.get("validity_shortcuts_used"),
            f"evidence {evidence_id}.result.integration.validity_shortcuts_used",
        )
        if integration.get("release_workflow_sha512") != RELEASE_WORKFLOW_SHA512:
            reject(f"evidence {evidence_id} release-workflow pin mismatch")
        stage_results = integration.get("stage_results")
        expected_stages = LIFECYCLE_INTEGRATION_EVIDENCE[evidence_id]
        if tuple(stage for stage, _ in source_bound_commands) != expected_stages:
            reject(
                f"source-bound lifecycle command inventory for {evidence_id} is incomplete"
            )
        if not isinstance(stage_results, list) or len(stage_results) != len(expected_stages):
            reject(f"evidence {evidence_id} must cover the exact lifecycle stage inventory")
        assigned_stages_by_command: dict[str, list[str]] = {}
        for expected_stage, expected_command in source_bound_commands:
            assigned_stages_by_command.setdefault(expected_command, []).append(
                expected_stage
            )
        command_outputs: dict[str, str] = {}
        command_stage_bindings: dict[
            tuple[str, str], tuple[str, int, dict[str, object]]
        ] = {}
        for _, expected_command in source_bound_commands:
            if expected_command in command_outputs:
                continue
            try:
                argv = shlex.split(expected_command, posix=True)
            except ValueError as exc:
                raise SuccessorAuthorizationError(
                    f"source-bound lifecycle command for {evidence_id} is malformed: {exc}"
                ) from exc
            if not argv or shlex.join(argv) != expected_command:
                reject(
                    f"source-bound lifecycle command for {evidence_id} must use "
                    "canonical argv spelling"
                )
            try:
                returncode, output = run_with_source_inventory_guard(
                    argv,
                    root,
                    command_runner,
                    expected_source_inventory_sha512,
                    expected_source_revision,
                    f"source-bound lifecycle command for {evidence_id}",
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                reject(
                    f"source-bound lifecycle command for {evidence_id} failed to run: {exc}"
                )
            if returncode != 0:
                tail = output[-2000:].replace("\n", " ").strip()
                reject(
                    f"source-bound lifecycle command for {evidence_id} rejected current "
                    f"source: {tail}"
                )
            output_payload = output.encode("utf-8")
            command_outputs[expected_command] = sha512_bytes(output_payload)
            command_receipt = require_object(
                load_canonical_json_bytes(
                    output_payload,
                    f"source-bound lifecycle command receipt for {evidence_id}",
                    MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES,
                ),
                f"source-bound lifecycle command receipt for {evidence_id}",
            )
            require_exact_keys(
                command_receipt,
                LIFECYCLE_COMMAND_RECEIPT_KEYS,
                f"source-bound lifecycle command receipt for {evidence_id}",
            )
            if command_receipt.get("schema") != LIFECYCLE_COMMAND_RECEIPT_SCHEMA:
                reject(f"source-bound lifecycle command receipt for {evidence_id} schema mismatch")
            if command_receipt.get("evidence_id") != evidence_id:
                reject(f"source-bound lifecycle command receipt for {evidence_id} id mismatch")
            if command_receipt.get("profile_id") != profile.profile_id:
                reject(f"source-bound lifecycle command receipt for {evidence_id} profile mismatch")
            if command_receipt.get("relation_program_sha512") != identity["relation_program_sha512"]:
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "relation-program pin mismatch"
                )
            if command_receipt.get(
                "capability_identity_sha512"
            ) != capability_identity_sha512(identity):
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "capability identity mismatch"
                )
            validate_lifecycle_capability(
                command_receipt.get("capability"),
                identity,
                f"source-bound lifecycle command receipt for {evidence_id}.capability",
            )
            command_state_binding = validate_lifecycle_state_binding(
                command_receipt.get("state_binding"),
                identity,
                f"source-bound lifecycle command receipt for {evidence_id}.state_binding",
            )
            if command_state_binding != lifecycle_state_binding:
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "state binding differs across stages"
                )
            if command_receipt.get("source_revision") != source_revision:
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "source revision mismatch"
                )
            if command_receipt.get("execution_kind") != "actual_subsystem_integration":
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "must use actual subsystem integration"
                )
            if command_receipt.get("retained_proof_id") != "retained_proof_primary":
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "must exercise retained_proof_primary"
                )
            command_proof_sha512 = require_sha512(
                command_receipt.get("proof_sha512"),
                f"source-bound lifecycle command receipt for {evidence_id}.proof_sha512",
            )
            if command_proof_sha512 != lifecycle_proof_sha512:
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "proof digest mismatch"
                )
            command_proof_bytes = require_positive_integer(
                command_receipt.get("proof_bytes"),
                f"source-bound lifecycle command receipt for {evidence_id}.proof_bytes",
            )
            if command_proof_bytes != lifecycle_proof_bytes:
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "proof byte length mismatch"
                )
            require_true(
                command_receipt.get("production_verifier_used"),
                f"source-bound lifecycle command receipt for {evidence_id}.production_verifier_used",
            )
            require_false(
                command_receipt.get("parser_stage_labels_used_as_authority"),
                f"source-bound lifecycle command receipt for {evidence_id}.parser_stage_labels_used_as_authority",
            )
            require_false(
                command_receipt.get("validity_shortcuts_used"),
                f"source-bound lifecycle command receipt for {evidence_id}.validity_shortcuts_used",
            )
            receipt_stages = command_receipt.get("stages")
            assigned_stages = assigned_stages_by_command[expected_command]
            if not isinstance(receipt_stages, list) or len(receipt_stages) != len(
                assigned_stages
            ):
                reject(
                    f"source-bound lifecycle command receipt for {evidence_id} "
                    "stage inventory mismatch"
                )
            for receipt_index, (receipt_stage_value, assigned_stage) in enumerate(
                zip(receipt_stages, assigned_stages)
            ):
                receipt_stage = require_object(
                    receipt_stage_value,
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}]",
                )
                require_exact_keys(
                    receipt_stage,
                    LIFECYCLE_COMMAND_RECEIPT_STAGE_KEYS,
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}]",
                )
                if receipt_stage.get("stage") != assigned_stage:
                    reject(
                        f"source-bound lifecycle command receipt for {evidence_id} "
                        "stage order mismatch"
                    )
                require_true(
                    receipt_stage.get("passed"),
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}].passed",
                )
                receipt_stage_proof_sha512 = require_sha512(
                    receipt_stage.get("proof_sha512"),
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}].proof_sha512",
                )
                if receipt_stage_proof_sha512 != lifecycle_proof_sha512:
                    reject(
                        f"source-bound lifecycle command receipt for {evidence_id} "
                        "stage proof digest mismatch"
                    )
                receipt_stage_proof_bytes = require_positive_integer(
                    receipt_stage.get("proof_bytes"),
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}].proof_bytes",
                )
                if receipt_stage_proof_bytes != lifecycle_proof_bytes:
                    reject(
                        f"source-bound lifecycle command receipt for {evidence_id} "
                        "stage proof byte length mismatch"
                    )
                receipt_stage_state = validate_lifecycle_state_binding(
                    receipt_stage.get("state_binding"),
                    identity,
                    f"source-bound lifecycle command receipt for {evidence_id}.stages[{receipt_index}].state_binding",
                )
                if receipt_stage_state != lifecycle_state_binding:
                    reject(
                        f"source-bound lifecycle command receipt for {evidence_id} "
                        "stage state binding differs across stages"
                    )
                command_stage_bindings[(expected_command, assigned_stage)] = (
                    receipt_stage_proof_sha512,
                    receipt_stage_proof_bytes,
                    receipt_stage_state,
                )

        for index, (stage_value, (expected_stage, expected_command)) in enumerate(
            zip(stage_results, source_bound_commands)
        ):
            stage = require_object(
                stage_value, f"evidence {evidence_id}.result.integration.stage_results[{index}]"
            )
            require_exact_keys(
                stage,
                LIFECYCLE_STAGE_RESULT_KEYS,
                f"evidence {evidence_id}.result.integration.stage_results[{index}]",
            )
            if stage.get("stage") != expected_stage:
                reject(f"evidence {evidence_id} lifecycle stage order mismatch")
            command = require_string(
                stage.get("command"),
                f"evidence {evidence_id}.result.integration.stage_results[{index}].command",
            )
            if not command.strip():
                reject(f"evidence {evidence_id} lifecycle command must be nonempty")
            if command != expected_command:
                reject(f"evidence {evidence_id} lifecycle command mismatch")
            require_true(
                stage.get("passed"),
                f"evidence {evidence_id}.result.integration.stage_results[{index}].passed",
            )
            output_sha512 = require_nonzero_sha512(
                stage.get("output_sha512"),
                f"evidence {evidence_id}.result.integration.stage_results[{index}].output_sha512",
            )
            if output_sha512 != command_outputs[expected_command]:
                reject(f"evidence {evidence_id} lifecycle command output digest mismatch")
            if check_output_by_command.get(command) != output_sha512:
                reject(
                    f"evidence {evidence_id} lifecycle command is not bound to its "
                    "positive check receipt"
                )
            stage_proof_sha512 = require_sha512(
                stage.get("proof_sha512"),
                f"evidence {evidence_id}.result.integration.stage_results[{index}].proof_sha512",
            )
            if stage_proof_sha512 != lifecycle_proof_sha512:
                reject(f"evidence {evidence_id} lifecycle stage proof digest mismatch")
            stage_proof_bytes = require_positive_integer(
                stage.get("proof_bytes"),
                f"evidence {evidence_id}.result.integration.stage_results[{index}].proof_bytes",
            )
            if stage_proof_bytes != lifecycle_proof_bytes:
                reject(f"evidence {evidence_id} lifecycle stage proof byte length mismatch")
            stage_state_binding = validate_lifecycle_state_binding(
                stage.get("state_binding"),
                identity,
                f"evidence {evidence_id}.result.integration.stage_results[{index}].state_binding",
            )
            if stage_state_binding != lifecycle_state_binding:
                reject(f"evidence {evidence_id} lifecycle stage state binding drift")
            if command_stage_bindings.get((expected_command, expected_stage)) != (
                stage_proof_sha512,
                stage_proof_bytes,
                stage_state_binding,
            ):
                reject(
                    f"evidence {evidence_id} lifecycle stage is not present in the "
                    "executed command receipt"
                )


def exact_ratio_security_bits_floor(numerator: int, denominator: int) -> int:
    if numerator <= 0 or denominator <= 0:
        reject("primitive security receipt ratio must be positive")
    return max(0, (denominator // numerator).bit_length() - 1)


def parse_source_security_exact_loss_term(
    value: object,
    *,
    label: str,
    expected_id: str | None = None,
) -> tuple[int, int]:
    term = require_object(value, label)
    require_exact_keys(term, SOURCE_SECURITY_EXACT_LOSS_TERM_KEYS, label)
    term_id = require_string(term.get("id"), f"{label}.id")
    if expected_id is not None and term_id != expected_id:
        reject(f"{label} id mismatch")
    numerator_text = require_string(
        term.get("numerator_decimal"), f"{label}.numerator_decimal"
    )
    denominator_text = require_string(
        term.get("denominator_decimal"), f"{label}.denominator_decimal"
    )
    if (
        not numerator_text.isascii()
        or not numerator_text.isdecimal()
        or not denominator_text.isascii()
        or not denominator_text.isdecimal()
    ):
        reject(f"{label} ratio must use canonical unsigned decimal integers")
    numerator = int(numerator_text)
    denominator = int(denominator_text)
    if (
        numerator <= 0
        or denominator <= 0
        or str(numerator) != numerator_text
        or str(denominator) != denominator_text
    ):
        reject(f"{label} ratio must be positive canonical decimal")
    if term.get("security_bits_floor") != exact_ratio_security_bits_floor(
        numerator, denominator
    ):
        reject(f"{label} security floor does not match its exact ratio")
    approximate = term.get("approximate_security_bits")
    if isinstance(approximate, bool) or not isinstance(approximate, (int, float)):
        reject(f"{label}.approximate_security_bits must be numeric")
    return numerator, denominator


def add_exact_ratios(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    left_numerator, left_denominator = left
    right_numerator, right_denominator = right
    return (
        left_numerator * right_denominator
        + right_numerator * left_denominator,
        left_denominator * right_denominator,
    )


def exact_ratios_equal(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] * right[1] == right[0] * left[1]


def scale_exact_ratio(ratio: tuple[int, int], factor: int) -> tuple[int, int]:
    return ratio[0] * factor, ratio[1]


def sum_exact_ratios(ratios: Iterable[tuple[int, int]]) -> tuple[int, int]:
    total = (0, 1)
    for ratio in ratios:
        total = add_exact_ratios(total, ratio)
    return total


def falling_product(start: int, count: int) -> int:
    product = 1
    for offset in range(count):
        product *= start - offset
    return product


def total_oracle_exposure_log2_ceiling(query_log2: int, proof_views: int) -> int:
    if query_log2 < 0 or proof_views < 0:
        reject("adaptive programming exposure inputs must be nonnegative")
    return ((1 << query_log2) + (1 << 24) * proof_views).bit_length()


def ghhm_adaptive_programming_ratio(
    *, entropy_bits: int, query_log2: int, proof_views: int, programming_events: int
) -> tuple[int, int]:
    exposure_log2_ceiling = total_oracle_exposure_log2_ceiling(
        query_log2, proof_views
    )
    if exposure_log2_ceiling > entropy_bits:
        reject("adaptive programming entropy is below the total-exposure exponent")
    return (
        3 * programming_events,
        1 << (1 + (entropy_bits - exposure_log2_ceiling) // 2),
    )


def lazy_joint_adaptive_programming_ratio(
    *, query_log2: int, proof_views: int
) -> tuple[int, int]:
    leaf_and_final = ghhm_adaptive_programming_ratio(
        entropy_bits=512,
        query_log2=query_log2,
        proof_views=proof_views,
        programming_events=21 * proof_views,
    )
    internal = ghhm_adaptive_programming_ratio(
        entropy_bits=1024,
        query_log2=query_log2,
        proof_views=proof_views,
        programming_events=352 * proof_views,
    )
    return add_exact_ratios(leaf_and_final, internal)


def maximum_lazy_joint_observed_proof_views_for_strict_target(
    *, query_log2: int, target_bits: int
) -> int:
    def supports_target(proof_views: int) -> bool:
        numerator, denominator = lazy_joint_adaptive_programming_ratio(
            query_log2=query_log2, proof_views=proof_views
        )
        return numerator * (1 << target_bits) < denominator

    lower = 0
    upper = 1
    while supports_target(upper):
        lower = upper
        upper *= 2
    while lower + 1 < upper:
        midpoint = lower + (upper - lower) // 2
        if supports_target(midpoint):
            lower = midpoint
        else:
            upper = midpoint
    return lower


def minimum_even_ghhm_entropy_bits(
    *, query_log2: int, proof_views: int, programming_events: int, target_bits: int
) -> int:
    exposure_log2_ceiling = total_oracle_exposure_log2_ceiling(
        query_log2, proof_views
    )
    entropy_bits = exposure_log2_ceiling + exposure_log2_ceiling % 2
    while entropy_bits <= 4096:
        numerator, denominator = ghhm_adaptive_programming_ratio(
            entropy_bits=entropy_bits,
            query_log2=query_log2,
            proof_views=proof_views,
            programming_events=programming_events,
        )
        if numerator * (1 << target_bits) < denominator:
            return entropy_bits
        entropy_bits += 2
    reject("adaptive programming entropy search exceeded the audited range")


def validate_primitive_security_bound_receipt(
    value: object,
    *,
    label: str,
    primitive_id: str,
    profile_identity: str,
    advantage_function: str,
    activation_height: int,
    deactivation_height_exclusive: int,
    max_proof_interactions: int,
    honest_exposures: int,
    sha512_mode: bool,
) -> None:
    receipt = require_object(value, label)
    require_exact_keys(receipt, SOURCE_SECURITY_PRIMITIVE_BOUND_RECEIPT_KEYS, label)
    for digest_field in (
        "source_inventory_sha512_hex",
        "theorem_source_sha512_hex",
        "review_artifact_sha512_hex",
    ):
        require_nonzero_sha512(receipt.get(digest_field), f"{label}.{digest_field}")
    expected_receipt_id = (
        "sha512-smz9-qrom-primitive-bound"
        if sha512_mode
        else "poseidon2-width16-smz9-primitive-bound"
    )
    if (
        receipt.get("schema")
        != "hegemon.smallwood.poseidon2-v8.primitive-security-bound.v2"
        or receipt.get("receipt_id") != expected_receipt_id
        or receipt.get("primitive_id") != primitive_id
        or receipt.get("exact_primitive_profile_identity") != profile_identity
        or not isinstance(receipt.get("theorem_or_reduction_id"), str)
        or not receipt["theorem_or_reduction_id"]
        or receipt.get("advantage_function") != advantage_function
        or receipt.get("advantage_scope") != "global-once"
        or receipt.get("adversarial_query_log2_max") != 143
        or receipt.get("honest_programmed_oracle_exposures_decimal")
        != str(honest_exposures)
        or receipt.get("bound_uses_queries_plus_honest_exposures") is not True
        or receipt.get("max_proof_actions_per_block") != RETAINED_MAX_PROOFS_PER_BLOCK
        or receipt.get("max_proof_interactions") != max_proof_interactions
        or receipt.get("validity_activation_height") != activation_height
        or receipt.get("validity_deactivation_height_exclusive")
        != deactivation_height_exclusive
        or receipt.get("independently_reviewed") is not True
    ):
        reject(f"{label} identity, accounting, validity, or review mismatch")
    screens = receipt.get("work_screens")
    if not isinstance(screens, list) or len(screens) != 4:
        reject(f"{label} work-screen inventory mismatch")
    for index, query_log2 in enumerate((64, 128, 142, 143)):
        screen = require_object(screens[index], f"{label}.work_screens[{index}]")
        require_exact_keys(
            screen,
            SOURCE_SECURITY_PRIMITIVE_WORK_SCREEN_KEYS,
            f"{label}.work_screens[{index}]",
        )
        query_count = 1 << query_log2
        if sha512_mode:
            exposure_count = query_count + honest_exposures
            collision_numerator = 48 * exposure_count**3
            preimage_numerator = exposure_count**2
            denominator = 1 << 512
            prefix = "sha512"
        else:
            exposure_count = query_count + honest_exposures
            collision_numerator = exposure_count**3
            preimage_numerator = exposure_count**2
            denominator = GOLDILOCKS_MODULUS**7
            prefix = "poseidon2_width16"
        expected_terms = (
            (
                "collision_advantage_upper_bound",
                f"{prefix}_collision_at_2pow{query_log2}",
                collision_numerator,
            ),
            (
                "preimage_advantage_upper_bound",
                f"{prefix}_preimage_at_2pow{query_log2}",
                preimage_numerator,
            ),
        )
        if screen.get("quantum_query_log2") != query_log2:
            reject(f"{label} work-screen query exponent mismatch")
        for field, term_id, numerator in expected_terms:
            term = require_object(screen.get(field), f"{label}.{field}")
            require_exact_keys(term, SOURCE_SECURITY_EXACT_LOSS_TERM_KEYS, f"{label}.{field}")
            if (
                term.get("id") != term_id
                or term.get("numerator_decimal") != str(numerator)
                or term.get("denominator_decimal") != str(denominator)
                or term.get("security_bits_floor")
                != exact_ratio_security_bits_floor(numerator, denominator)
            ):
                reject(f"{label} exact primitive work-screen ratio mismatch")


def validate_source_security_primitive_evidence_bindings(
    payload: bytes,
    *,
    root: Path,
    expected_source_inventory_sha512: str,
    independent_review_payload: bytes,
    global_qrom_lifetime_receipt_payload: bytes,
) -> None:
    """Resolve primitive receipt digests to retained source and signed review files."""

    report = require_object(
        load_canonical_json_bytes(
            payload,
            "source-derived composed security report primitive bindings",
            MAX_EVIDENCE_FILE_BYTES,
        ),
        "source-derived composed security report primitive bindings",
    )
    review_document = require_object(
        load_canonical_json_bytes(
            independent_review_payload,
            "authenticated independent security review primitive binding",
            MAX_EVIDENCE_FILE_BYTES,
        ),
        "authenticated independent security review primitive binding",
    )
    review_result = require_object(
        review_document.get("result"),
        "authenticated independent security review primitive binding result",
    )
    review_attestation = require_object(
        review_result.get("review_attestation"),
        "authenticated independent security review primitive binding attestation",
    )
    review_artifact_path = require_relative_path(
        review_attestation.get("review_artifact_path"),
        "authenticated independent security review primitive binding artifact path",
    )
    _, review_artifact = read_regular_file_beneath(
        root,
        review_artifact_path,
        "authenticated independent security review primitive binding artifact",
        MAX_LIFECYCLE_COMMAND_RECEIPT_BYTES,
    )
    review_artifact_sha512 = sha512_bytes(review_artifact)
    if review_artifact_sha512 != require_nonzero_sha512(
        review_attestation.get("review_artifact_sha512"),
        "authenticated independent security review primitive binding artifact digest",
    ):
        reject("primitive receipt review artifact digest differs from its attestation")

    lifetime_document = require_object(
        load_canonical_json_bytes(
            global_qrom_lifetime_receipt_payload,
            "global SHA-512 QROM lifetime primitive binding receipt",
            MAX_EVIDENCE_FILE_BYTES,
        ),
        "global SHA-512 QROM lifetime primitive binding receipt",
    )
    lifetime_result = require_object(
        lifetime_document.get("result"),
        "global SHA-512 QROM lifetime primitive binding result",
    )
    lifetime_formal_receipt = require_object(
        lifetime_result.get("formal_receipt"),
        "global SHA-512 QROM lifetime primitive binding formal receipt",
    )
    require_true(
        lifetime_formal_receipt.get("release_receipt_constructed"),
        "global SHA-512 QROM lifetime primitive binding release receipt",
    )
    require_true(
        lifetime_formal_receipt.get("all_release_inputs_instantiated"),
        "global SHA-512 QROM lifetime primitive binding premise instantiation",
    )
    if (
        lifetime_formal_receipt.get("release_theorem")
        != SOURCE_SECURITY_PRIMITIVE_RECEIPT_BINDINGS[
            "sha512_primitive_security_bound"
        ]["theorem_or_reduction_id"]
        or lifetime_formal_receipt.get("source_inventory_sha512")
        != expected_source_inventory_sha512
    ):
        reject("SHA-512 primitive bound is not cross-bound to its lifetime receipt")

    for receipt_field, binding in SOURCE_SECURITY_PRIMITIVE_RECEIPT_BINDINGS.items():
        label = f"source-derived composed security report {receipt_field} evidence binding"
        receipt = require_object(report.get(receipt_field), label)
        theorem_id = str(binding["theorem_or_reduction_id"])
        theorem_source_path = str(binding["theorem_source_path"])
        if SOURCE_SECURITY_PRIMITIVE_THEOREM_PATHS.get(theorem_id) != theorem_source_path:
            reject(f"{label} source-owned theorem binding is internally inconsistent")
        if receipt.get("theorem_or_reduction_id") != theorem_id:
            reject(f"{label} theorem or reduction identity mismatch")
        _, theorem_source = read_regular_file_beneath(
            root,
            theorem_source_path,
            f"{label} theorem source",
            RETAINED_SOURCE_INVENTORY_MAX_FILE_BYTES,
        )
        theorem_leaf = theorem_id.rsplit(".", 1)[-1]
        try:
            theorem_source_text = theorem_source.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SuccessorAuthorizationError(
                f"{label} theorem source is not UTF-8"
            ) from exc
        if re.search(
            rf"(?m)^\s*(?:theorem|lemma)\s+{re.escape(theorem_leaf)}(?:\s|:)",
            theorem_source_text,
        ) is None:
            reject(f"{label} named theorem is absent from its canonical source")
        if (
            receipt_field == "sha512_primitive_security_bound"
            and "quantitativeBound.failureProbabilityLeTarget" in theorem_source_text
        ):
            reject(
                f"{label} theorem assumes its target inequality instead of deriving "
                "it from hermetically instantiated quantitative premises"
            )
        if (
            receipt.get("source_inventory_sha512_hex")
            != expected_source_inventory_sha512
            or receipt.get("theorem_source_sha512_hex")
            != sha512_bytes(theorem_source)
            or receipt.get("review_artifact_sha512_hex")
            != review_artifact_sha512
        ):
            reject(f"{label} retained source or independent-review digest mismatch")
        if receipt_field == "sha512_primitive_security_bound" and (
            receipt.get("theorem_source_sha512_hex")
            != lifetime_formal_receipt.get("formal_source_sha512")
        ):
            reject(f"{label} differs from the premise-instantiated lifetime receipt")


def validate_source_security_report_document(
    payload: bytes, identity: Mapping[str, object]
) -> None:
    """Validate the exact Rust report shape before executing its source gate."""

    report = require_object(
        load_canonical_json_bytes(
            payload,
            "source-derived composed security report",
            MAX_EVIDENCE_FILE_BYTES,
        ),
        "source-derived composed security report",
    )
    require_exact_keys(
        report,
        SOURCE_SECURITY_REPORT_KEYS,
        "source-derived composed security report",
    )
    if report.get("schema") != SOURCE_SECURITY_REPORT_SCHEMA:
        reject("source-derived composed security report schema mismatch")
    if (
        report.get("program_sha512_hex") != identity["relation_program_sha512"]
        or report.get("program_digest_hex")
        != str(identity["relation_program_sha512"])[: 48 * 2]
        or report.get("proof_wire_magic_ascii") != "SMZ9"
        or report.get("profile_wire_id") != identity["profile_wire_id"]
    ):
        reject("source-derived composed security report identity mismatch")
    if {
        "row_count": report.get("row_count"),
        "proof_columns": report.get("proof_columns"),
        "packing_factor": report.get("packing_factor"),
        "constraint_degree": report.get("constraint_degree"),
        "nonlinear_identity_count": report.get("nonlinear_identity_count"),
        "maximum_linear_identity_count": report.get(
            "maximum_linear_identity_count"
        ),
        "maximum_summed_identity_union": report.get(
            "maximum_summed_identity_union"
        ),
    } != {
        "row_count": 686,
        "proof_columns": 368,
        "packing_factor": 64,
        "constraint_degree": 8,
        "nonlinear_identity_count": 830,
        "maximum_linear_identity_count": 20_509,
        "maximum_summed_identity_union": 21_339,
    }:
        reject("source-derived composed security report relation geometry mismatch")
    if {
        "rho": report.get("rho"),
        "piop_openings": report.get("piop_openings"),
        "beta": report.get("beta"),
        "decs_domain_size": report.get("decs_domain_size"),
        "decs_openings": report.get("decs_openings"),
        "decs_eta": report.get("decs_eta"),
        "piop_linear_correction_degree": report.get(
            "piop_linear_correction_degree"
        ),
        "piop_pcs_unstack_additional_forbidden_values": report.get(
            "piop_pcs_unstack_additional_forbidden_values"
        ),
        "piop_admissibility_bad_tuple_coefficient": report.get(
            "piop_admissibility_bad_tuple_coefficient"
        ),
        "piop_nonce_bad_per_trial": report.get("piop_nonce_bad_per_trial"),
    } != {
        "rho": 5,
        "piop_openings": 6,
        "beta": 2,
        "decs_domain_size": 1 << 23,
        "decs_openings": 20,
        "decs_eta": 5,
        "piop_linear_correction_degree": 6,
        "piop_pcs_unstack_additional_forbidden_values": 68,
        "piop_admissibility_bad_tuple_coefficient": 414,
        "piop_nonce_bad_per_trial": 813,
    }:
        reject("source-derived composed security report SMZ9 profile mismatch")
    canonical_abort = require_object(
        report.get("canonical_piop_opening_abort"),
        "source-derived composed security report canonical opening abort",
    )
    require_exact_keys(
        canonical_abort,
        {
            "approximate_security_bits",
            "denominator_decimal",
            "id",
            "numerator_decimal",
            "security_bits_floor",
        },
        "source-derived composed security report canonical opening abort",
    )
    if (
        canonical_abort.get("id") != "canonical_piop_opening_abort"
        or canonical_abort.get("numerator_decimal") != str(813**16)
        or canonical_abort.get("denominator_decimal")
        != str(GOLDILOCKS_MODULUS**16)
    ):
        reject("source-derived composed security report opening-abort ratio mismatch")
    interactive_terms = report.get("interactive_terms")
    if not isinstance(interactive_terms, list) or len(interactive_terms) != 4:
        reject("source-derived composed security report interactive term inventory mismatch")
    conditioned_opening = require_object(
        interactive_terms[2],
        "source-derived composed security report conditioned opening term",
    )
    expected_opening_numerator = 1
    expected_opening_denominator = 1
    for offset in range(6):
        expected_opening_numerator *= 552 - offset
        expected_opening_denominator *= GOLDILOCKS_MODULUS - 64 - offset
    expected_opening_denominator -= 414 * GOLDILOCKS_MODULUS**5
    if (
        conditioned_opening.get("id")
        != "iop_opening_consistency_conditioned_on_full_admissibility"
        or conditioned_opening.get("numerator_decimal")
        != str(expected_opening_numerator)
        or conditioned_opening.get("denominator_decimal")
        != str(expected_opening_denominator)
    ):
        reject("source-derived composed security report conditioned-opening ratio mismatch")
    interactive_ratio_ids = (
        "pcs_decs_uniform_batching",
        "iop_constraint_batching",
        "iop_opening_consistency_conditioned_on_full_admissibility",
        "pcs_decs_low_degree_opening",
    )
    interactive_ratios = [
        parse_source_security_exact_loss_term(
            term,
            label=f"source-derived composed security report interactive terms[{index}]",
            expected_id=term_id,
        )
        for index, (term, term_id) in enumerate(
            zip(interactive_terms, interactive_ratio_ids)
        )
    ]
    if (
        report.get("projected_inner_proof_bytes") != identity["max_proof_bytes"]
        or report.get("projected_two_output_action_bytes") != 128_297
        or report.get("projected_pending_action_bytes") != 128_522
    ):
        reject("source-derived composed security report byte projection mismatch")
    budget = require_object(
        report.get("budget"), "source-derived composed security report budget"
    )
    require_exact_keys(
        budget,
        SOURCE_SECURITY_BUDGET_KEYS,
        "source-derived composed security report budget",
    )
    expected_activation = identity["activation_height"]
    expected_deactivation = identity["deactivation_height_exclusive"]
    if budget != {
        "capability_activation_height": expected_activation,
        "capability_deactivation_height_exclusive": expected_deactivation,
        "max_proofs_per_block": identity["max_proofs_per_block"],
        "quantum_hash_query_log2": 64,
        "security_epoch_blocks": RETAINED_SECURITY_EPOCH_BLOCKS,
        "security_epoch_max_proofs": identity["security_epoch_max_proofs"],
    }:
        reject("source-derived composed security report budget mismatch")
    byte_quotient_diagnostic = require_object(
        report.get("byte_quotient_diagnostic"),
        "source-derived composed security report byte-quotient diagnostic",
    )
    require_exact_keys(
        byte_quotient_diagnostic,
        SOURCE_SECURITY_BYTE_QUOTIENT_DIAGNOSTIC_KEYS,
        "source-derived composed security report byte-quotient diagnostic",
    )
    if byte_quotient_diagnostic != {
        "block_action_byte_cap": 64 * 1024 * 1024,
        "projected_pending_action_bytes": RETAINED_PROJECTED_PENDING_ACTION_BYTES,
        "complete_projected_records_per_block": (
            RETAINED_MAXIMUM_RECORD_BYTE_QUOTIENT_DIAGNOSTIC
        ),
        "is_upper_bound_on_proof_interactions": False,
        "used_in_security_loss_terms": False,
    }:
        reject("source-derived composed security report byte-quotient diagnostic mismatch")
    lifetime = require_object(
        report.get("lifetime_binding"),
        "source-derived composed security report lifetime binding",
    )
    require_exact_keys(
        lifetime,
        SOURCE_SECURITY_LIFETIME_BINDING_KEYS,
        "source-derived composed security report lifetime binding",
    )
    if lifetime != {
        "analysis_max_proof_interactions": identity["security_epoch_max_proofs"],
        "analysis_window_blocks": RETAINED_SECURITY_EPOCH_BLOCKS,
        "analysis_window_is_cryptographic_reset": False,
        "capability_activation_height": expected_activation,
        "capability_deactivation_height_exclusive": expected_deactivation,
        "capability_max_proof_interactions": identity["security_epoch_max_proofs"],
        "capability_window_blocks": RETAINED_SECURITY_EPOCH_BLOCKS,
        "capability_window_within_analysis_budget": True,
        "consensus_budget_binding_receipt_present": True,
    }:
        reject("source-derived composed security report lifetime binding mismatch")
    exposure = require_object(
        report.get("proof_exposure_accounting"),
        "source-derived composed security report proof-exposure accounting",
    )
    require_exact_keys(
        exposure,
        SOURCE_SECURITY_PROOF_EXPOSURE_ACCOUNTING_KEYS,
        "source-derived composed security report proof-exposure accounting",
    )
    observed_proof_views = require_positive_integer(
        exposure.get("observed_honest_proof_views"),
        "source-derived composed security report observed honest proof views",
    )
    active_max_observed_proof_views = 1_537_228_672_809_129_301
    if observed_proof_views > active_max_observed_proof_views:
        reject(
            "source-derived composed security report observed proof views exceed "
            "the exact active eager strict-128 ceiling"
        )
    if (
        exposure.get("canonical_accepted_proofs")
        != identity["security_epoch_max_proofs"]
        or exposure.get("observed_honest_proof_views_model_receipt_present") is not True
        or exposure.get("consensus_counter_bounds_observed_honest_proof_views") is not False
        or exposure.get("analyzed_proof_views") != observed_proof_views
        or exposure.get("analyzed_proof_views_are_canonical_count_diagnostic_only") is not False
        or exposure.get("eager_programs_per_proof") != 1 << 24
        or exposure.get("active_eager_per_proof_security_bits_floor") != 198
        or exposure.get(
            "active_eager_max_observed_proof_views_for_strict_128_decimal"
        )
        != str(active_max_observed_proof_views)
        or exposure.get("active_eager_successor_fails_strict_128") is not True
        or exposure.get("compact448_eager_per_proof_security_bits_floor") != 166
        or exposure.get(
            "compact448_eager_max_observed_proof_views_for_strict_128_decimal"
        )
        != "366503897770"
        or exposure.get("compact448_eager_successor_fails_strict_128") is not True
    ):
        reject("source-derived composed security report proof-exposure boundary mismatch")
    active_per_proof = parse_source_security_exact_loss_term(
        exposure.get("active_eager_per_proof_programming_loss"),
        label="source-derived composed security report active eager per-proof loss",
        expected_id="active_eager_programming_one_observed_proof_view",
    )
    compact_per_proof = parse_source_security_exact_loss_term(
        exposure.get("compact448_eager_per_proof_programming_loss"),
        label="source-derived composed security report compact448 eager per-proof loss",
        expected_id="compact448_eager_programming_one_observed_proof_view",
    )
    if (
        active_per_proof != (3 * (1 << 24), 1 << 224)
        or compact_per_proof
        != add_exact_ratios(
            (3 * ((1 << 24) - 1), 1 << 192),
            (3, 1 << 224),
        )
    ):
        reject("source-derived composed security report per-proof exposure ratio mismatch")
    if {
        "field_xof_requested_words": report.get("field_xof_requested_words"),
        "field_xof_candidate_words": report.get("field_xof_candidate_words"),
        "field_xof_minimum_rejections": report.get("field_xof_minimum_rejections"),
        "field_xof_request_union": report.get("field_xof_request_union"),
    } != {
        "field_xof_requested_words": 102_545,
        "field_xof_candidate_words": 102_584,
        "field_xof_minimum_rejections": 40,
        "field_xof_request_union": 1 << 25,
    }:
        reject("source-derived composed security report field-XOF parameter mismatch")
    exact_loss_fields = (
        "interactive_aggregate",
        "field_xof_abort_union",
        "canonical_piop_opening_abort",
        "fixed_decs_sampler_abort",
        "sha512_collision",
        "sha512_preimage",
        "tape_database_bridge",
        "poseidon2_collision",
        "poseidon2_preimage",
        "ideal_cms_qrom",
        "conditional_fixed_query_baseline_without_honest_program_exposures",
        "conditional_completeness_abort_per_proof",
        "conditional_completeness_abort_finite_history",
        "conditional_global_query_soundness_only",
        "conditional_global_query_composed_reduction_failure",
        "conditional_total_failure_finite_history_diagnostic",
    )
    for field in exact_loss_fields:
        term = require_object(
            report.get(field), f"source-derived composed security report {field}"
        )
        require_exact_keys(
            term,
            SOURCE_SECURITY_EXACT_LOSS_TERM_KEYS,
            f"source-derived composed security report {field}",
        )
        if term.get("id") != field:
            reject(f"source-derived composed security report {field} id mismatch")
    if {
        "field_xof_abort_union": report["field_xof_abort_union"].get(
            "security_bits_floor"
        ),
        "canonical_piop_opening_abort": report["canonical_piop_opening_abort"].get(
            "security_bits_floor"
        ),
        "fixed_decs_sampler_abort": report["fixed_decs_sampler_abort"].get(
            "security_bits_floor"
        ),
        "conditional_completeness_abort_finite_history": report[
            "conditional_completeness_abort_finite_history"
        ].get("security_bits_floor"),
    } != {
        "field_xof_abort_union": 748,
        "canonical_piop_opening_abort": 869,
        "fixed_decs_sampler_abort": 488,
        "conditional_completeness_abort_finite_history": 467,
    }:
        reject("source-derived composed security report completeness-abort floor mismatch")
    no_grinding = require_object(
        report.get("no_grinding"),
        "source-derived composed security report no-grinding status",
    )
    require_exact_keys(
        no_grinding,
        {
            "canonical_first_valid_nonce",
            "decs_pow_bits",
            "exact_grinding_loss_denominator_decimal",
            "exact_grinding_loss_numerator_decimal",
            "nonce_trials_are_abort_handling_not_grinding",
            "piop_pow_bits",
        },
        "source-derived composed security report no-grinding status",
    )
    if no_grinding != {
        "canonical_first_valid_nonce": True,
        "decs_pow_bits": 0,
        "exact_grinding_loss_denominator_decimal": "1",
        "exact_grinding_loss_numerator_decimal": "0",
        "nonce_trials_are_abort_handling_not_grinding": True,
        "piop_pow_bits": 0,
    }:
        reject("source-derived composed security report no-grinding status mismatch")

    global_screens = report.get("conditional_global_query_work_screens")
    if not isinstance(global_screens, list) or len(global_screens) != 4:
        reject("source-derived composed security report global-query screen inventory mismatch")
    honest_exposures = (1 << 24) * observed_proof_views
    poseidon_honest_evaluations = 128 * observed_proof_views
    if report.get("poseidon_honest_evaluations_decimal") != str(
        poseidon_honest_evaluations
    ):
        reject("source-derived composed security report Poseidon exposure count mismatch")
    fixed_poseidon_exposures = (1 << 64) + poseidon_honest_evaluations
    for field, exponent in (("poseidon2_collision", 3), ("poseidon2_preimage", 2)):
        actual_poseidon_ratio = parse_source_security_exact_loss_term(
            report.get(field),
            label=f"source-derived composed security report {field}",
            expected_id=field,
        )
        expected_poseidon_ratio = (
            fixed_poseidon_exposures**exponent,
            GOLDILOCKS_MODULUS**7,
        )
        if not exact_ratios_equal(actual_poseidon_ratio, expected_poseidon_ratio):
            reject("source-derived composed security report Poseidon ratio mismatch")
    for index, (value, query_log2, expected_pass) in enumerate(
        zip(global_screens, (64, 128, 142, 143), (True, True, True, False))
    ):
        screen = require_object(
            value,
            f"source-derived composed security report global-query screens[{index}]",
        )
        require_exact_keys(
            screen,
            SOURCE_SECURITY_GLOBAL_QUERY_SCREEN_KEYS,
            f"source-derived composed security report global-query screens[{index}]",
        )
        parsed_screen_ratios = {}
        for ratio_field in (
            "conditional_soundness_only",
            "conditional_composed_reduction_failure",
            "conditional_total_failure_diagnostic",
        ):
            parsed_screen_ratios[ratio_field] = parse_source_security_exact_loss_term(
                screen.get(ratio_field),
                label=(
                    "source-derived composed security report global-query "
                    f"screens[{index}].{ratio_field}"
                ),
            )
        expected_adaptive_exponent = total_oracle_exposure_log2_ceiling(
            query_log2, observed_proof_views
        )
        queries = 1 << query_log2
        total_sha_exposures = queries + honest_exposures
        expected_cms = sum_exact_ratios(
            (
                scale_exact_ratio(
                    sum_exact_ratios(interactive_ratios),
                    12 * total_sha_exposures**2,
                ),
                (48 * total_sha_exposures**3, 1 << 512),
                (2 * (1 << 23) ** 2, 1 << 512),
            )
        )
        total_poseidon_exposures = queries + poseidon_honest_evaluations
        expected_soundness = sum_exact_ratios(
            (
                expected_cms,
                (total_sha_exposures**2, 1 << 512),
                (total_poseidon_exposures**3, GOLDILOCKS_MODULUS**7),
                (total_poseidon_exposures**2, GOLDILOCKS_MODULUS**7),
            )
        )
        expected_composed = add_exact_ratios(
            expected_soundness,
            ghhm_adaptive_programming_ratio(
                entropy_bits=512,
                query_log2=query_log2,
                proof_views=observed_proof_views,
                programming_events=observed_proof_views,
            ),
        )
        expected_composed = add_exact_ratios(
            expected_composed,
            ghhm_adaptive_programming_ratio(
                entropy_bits=512,
                query_log2=query_log2,
                proof_views=observed_proof_views,
                programming_events=((1 << 24) - 1) * observed_proof_views,
            ),
        )
        actual_composed = parsed_screen_ratios[
            "conditional_composed_reduction_failure"
        ]
        if (
            screen.get("quantum_hash_query_log2") != query_log2
            or screen.get("accepted_proof_interactions") != observed_proof_views
            or screen.get("honest_programmed_oracle_exposures_decimal")
            != str(honest_exposures)
            or screen.get("total_oracle_exposures_decimal")
            != str((1 << query_log2) + honest_exposures)
            or not exact_ratios_equal(
                parsed_screen_ratios["conditional_soundness_only"],
                expected_soundness,
            )
            or not exact_ratios_equal(actual_composed, expected_composed)
            or screen.get("certified_reduction_upper_bound_strictly_below_half")
            is not expected_pass
            or screen.get("query_dependent_terms_charged_once") is not True
            or screen.get(
                "sha512_collision_uses_queries_plus_honest_programmed_exposures"
            )
            is not True
            or screen.get(
                "cms_instability_uses_queries_plus_honest_programmed_exposures"
            )
            is not True
            or screen.get("abort_terms_excluded_from_soundness_and_reduction_failure")
            is not True
            or screen.get(
                "final_piop_and_full_tree_adaptive_programming_terms_included"
            )
            is not True
            or screen.get("adaptive_programming_uses_conditional_512_bit_entropy")
            is not True
            or screen.get("adaptive_programming_uses_total_step_log2_ceiling")
            is not True
            or screen.get("adaptive_programming_query_log2_ceiling")
            != expected_adaptive_exponent
            or screen.get(
                "exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated"
            )
            is not True
            or screen.get("is_known_attack") is not False
        ):
            reject("source-derived composed security report global-query screen mismatch")
    if (
        report.get("strongest_conditional_global_query_work_factor_log2") != 142
        or report.get("first_failing_conditional_global_query_work_factor_log2") != 143
    ):
        reject("source-derived composed security report certified-query frontier mismatch")

    candidates = report.get("candidate_parameter_screens")
    expected_candidates = (
        ("q19-sha512", 19, 386, 512, 134, 135),
        ("q19-compact448", 19, 386, 448, 134, 135),
        ("q20-compact448", 20, 387, 448, 142, 143),
    )
    if not isinstance(candidates, list) or len(candidates) != len(expected_candidates):
        reject("source-derived composed security report candidate-screen inventory mismatch")

    def expected_candidate_ratios(
        *, openings: int, degree: int, entropy_bits: int, query_log2: int
    ) -> tuple[tuple[int, int], tuple[int, int]]:
        if openings == 20:
            instability = sum_exact_ratios(interactive_ratios)
        else:
            instability = sum_exact_ratios(
                interactive_ratios[:3]
                + [
                    (
                        falling_product(degree, openings),
                        falling_product(1 << 23, openings),
                    )
                ]
            )
        queries = 1 << query_log2
        tree_events = ((1 << 24) - 1) * observed_proof_views
        final_events = observed_proof_views
        total_exposures = queries + tree_events + final_events
        commitment_space = 1 << entropy_bits
        if entropy_bits == 512:
            sha_collision = (total_exposures**3, commitment_space)
            sha_preimage = (total_exposures**2, commitment_space)
        else:
            tree_exposures = queries + tree_events
            final_exposures = queries + final_events
            sha_collision = add_exact_ratios(
                (tree_exposures**3, commitment_space),
                (final_exposures**3, 1 << 512),
            )
            sha_preimage = add_exact_ratios(
                (tree_exposures**2, commitment_space),
                (final_exposures**2, 1 << 512),
            )
        cms = sum_exact_ratios(
            (
                scale_exact_ratio(instability, 12 * total_exposures**2),
                scale_exact_ratio(sha_collision, 48),
                (2 * (1 << 23) ** 2, commitment_space),
            )
        )
        poseidon_space = GOLDILOCKS_MODULUS**7
        poseidon_exposures = queries + 128 * observed_proof_views
        soundness = sum_exact_ratios(
            (
                cms,
                sha_preimage,
                (poseidon_exposures**3, poseidon_space),
                (poseidon_exposures**2, poseidon_space),
            )
        )
        composed = sum_exact_ratios(
            (
                soundness,
                ghhm_adaptive_programming_ratio(
                    entropy_bits=512,
                    query_log2=query_log2,
                    proof_views=observed_proof_views,
                    programming_events=final_events,
                ),
                ghhm_adaptive_programming_ratio(
                    entropy_bits=entropy_bits,
                    query_log2=query_log2,
                    proof_views=observed_proof_views,
                    programming_events=tree_events,
                ),
            )
        )
        return soundness, composed

    for index, (value, expected) in enumerate(zip(candidates, expected_candidates)):
        candidate = require_object(
            value,
            f"source-derived composed security report candidate screens[{index}]",
        )
        require_exact_keys(
            candidate,
            SOURCE_SECURITY_CANDIDATE_SCREEN_KEYS,
            f"source-derived composed security report candidate screens[{index}]",
        )
        candidate_ratios = {}
        for ratio_field in (
            "fixed_query_conditional_soundness_only",
            "fixed_query_conditional_composed_reduction_failure",
            "strongest_screen",
            "first_failing_screen",
        ):
            candidate_ratios[ratio_field] = parse_source_security_exact_loss_term(
                candidate.get(ratio_field),
                label=(
                    "source-derived composed security report candidate "
                    f"screens[{index}].{ratio_field}"
                ),
            )
        expected_id, openings, degree, entropy, strongest, failing = expected
        expected_fixed_soundness, expected_fixed_composed = expected_candidate_ratios(
            openings=openings,
            degree=degree,
            entropy_bits=entropy,
            query_log2=64,
        )
        _, expected_strongest = expected_candidate_ratios(
            openings=openings,
            degree=degree,
            entropy_bits=entropy,
            query_log2=strongest,
        )
        _, expected_first_failing = expected_candidate_ratios(
            openings=openings,
            degree=degree,
            entropy_bits=entropy,
            query_log2=failing,
        )
        if (
            candidate.get("id") != expected_id
            or candidate.get("active_wire") is not False
            or candidate.get("requires_new_backend_wire_and_layout_theorem") is not True
            or candidate.get("piop_openings") != 6
            or candidate.get("decs_openings") != openings
            or candidate.get("decs_polynomial_degree") != degree
            or candidate.get("merkle_conditional_entropy_bits") != entropy
            or candidate.get("quantum_hash_query_log2") != 64
            or candidate.get("accepted_proof_interactions") != observed_proof_views
            or not exact_ratios_equal(
                candidate_ratios["fixed_query_conditional_soundness_only"],
                expected_fixed_soundness,
            )
            or not exact_ratios_equal(
                candidate_ratios[
                    "fixed_query_conditional_composed_reduction_failure"
                ],
                expected_fixed_composed,
            )
            or candidate.get("strongest_certified_reduction_query_log2") != strongest
            or candidate.get("first_failing_certified_reduction_query_log2") != failing
            or not exact_ratios_equal(
                candidate_ratios["strongest_screen"], expected_strongest
            )
            or not exact_ratios_equal(
                candidate_ratios["first_failing_screen"], expected_first_failing
            )
            or candidate.get("strongest_screen_strictly_below_half") is not True
            or candidate.get("first_failing_screen_strictly_below_half") is not False
            or candidate.get("completeness_aborts_excluded") is not True
            or candidate.get("theorem_hypotheses_instantiated") is not False
        ):
            reject("source-derived composed security report candidate screen mismatch")

    first_program = require_object(
        report.get("adaptive_first_program_no_go"),
        "source-derived composed security report adaptive first-program screen",
    )
    require_exact_keys(
        first_program,
        SOURCE_SECURITY_FIRST_PROGRAM_KEYS,
        "source-derived composed security report adaptive first-program screen",
    )
    first_program_ratios = {}
    for field in (
        "current_single_proof_loss",
        "current_finite_history_loss",
        "minimum_even_entropy_loss",
        "previous_even_entropy_loss",
    ):
        first_program_ratios[field] = parse_source_security_exact_loss_term(
            first_program.get(field), label=f"adaptive first-program {field}"
        )
    first_minimum_even_entropy = minimum_even_ghhm_entropy_bits(
        query_log2=64,
        proof_views=observed_proof_views,
        programming_events=observed_proof_views,
        target_bits=128,
    )
    first_minimum_byte_entropy = ((first_minimum_even_entropy + 7) // 8) * 8
    first_minimum_wire_entropy = ((first_minimum_byte_entropy + 63) // 64) * 64
    expected_first_ratios = {
        "current_single_proof_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=256,
            query_log2=64,
            proof_views=1,
            programming_events=1,
        ),
        "current_finite_history_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=256,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=observed_proof_views,
        ),
        "minimum_even_entropy_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=first_minimum_even_entropy,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=observed_proof_views,
        ),
        "previous_even_entropy_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=first_minimum_even_entropy - 2,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=observed_proof_views,
        ),
    }
    if (
        first_program.get("route_id")
        != "ghhm-2020-proposition-2-direct-dyadic-first-program"
        or first_program.get("salt_only_oracle_program_count") != 0
        or first_program.get("exact_lazy_program_keys_exclude_salt_only_point")
        is not True
        or first_program.get("direct_256_bit_first_program_route_used") is not False
        or first_program.get("paper_hypotheses_instantiated_for_exact_smz9_program_point")
        is not False
        or first_program.get("quantum_hash_query_log2") != 64
        or first_program.get("accepted_proof_interactions") != observed_proof_views
        or first_program.get("current_entropy_bits") != 256
        or first_program.get("current_entropy_bytes") != 32
        or any(
            not exact_ratios_equal(first_program_ratios[field], ratio)
            for field, ratio in expected_first_ratios.items()
        )
        or first_program.get("current_single_proof_supports_strict_128_bits") is not False
        or first_program.get("current_finite_history_supports_strict_128_bits") is not False
        or first_program.get("minimum_even_entropy_bits_for_finite_history")
        != first_minimum_even_entropy
        or first_program.get("previous_even_entropy_bits")
        != first_minimum_even_entropy - 2
        or first_program.get("minimum_byte_entropy_bits")
        != first_minimum_byte_entropy
        or first_program.get("minimum_byte_entropy_bytes")
        != first_minimum_byte_entropy // 8
        or first_program.get("salt_word_alignment_bytes") != 8
        or first_program.get("minimum_wire_entropy_bits")
        != first_minimum_wire_entropy
        or first_program.get("minimum_wire_entropy_bytes")
        != first_minimum_wire_entropy // 8
        or first_program.get("additional_wire_entropy_bytes")
        != first_minimum_wire_entropy // 8 - 32
        or first_program.get("wire_change_required_only_if_this_route_applies") is not True
        or first_program.get("alternative_reduction_may_avoid_wire_change") is not True
    ):
        reject("source-derived composed security report adaptive first-program mismatch")

    final_piop = require_object(
        report.get("adaptive_final_piop_programming_screen"),
        "source-derived composed security report final-PIOP programming screen",
    )
    require_exact_keys(
        final_piop,
        SOURCE_SECURITY_FINAL_PIOP_KEYS,
        "source-derived composed security report final-PIOP programming screen",
    )
    final_piop_ratio = parse_source_security_exact_loss_term(
        final_piop.get("conditional_loss"), label="final-PIOP conditional loss"
    )
    expected_final_piop_ratio = ghhm_adaptive_programming_ratio(
        entropy_bits=512,
        query_log2=64,
        proof_views=observed_proof_views,
        programming_events=observed_proof_views,
    )
    final_piop_supports_128 = (
        expected_final_piop_ratio[0] * (1 << 128) < expected_final_piop_ratio[1]
    )
    if (
        final_piop.get("program_point_scope")
        != "exact_final_piop_only_not_merkle_root_leaf_or_first_program"
        or final_piop.get("paper_and_executable_hypotheses_instantiated") is not True
        or final_piop.get("entropy_bits") != 512
        or final_piop.get("quantum_hash_query_log2") != 64
        or final_piop.get("accepted_proof_interactions") != observed_proof_views
        or not exact_ratios_equal(final_piop_ratio, expected_final_piop_ratio)
        or final_piop.get("supports_strict_128_bits") is not final_piop_supports_128
    ):
        reject("source-derived composed security report final-PIOP screen mismatch")

    full_tree = require_object(
        report.get("adaptive_full_tree_programming_screen"),
        "source-derived composed security report full-tree programming screen",
    )
    require_exact_keys(
        full_tree,
        SOURCE_SECURITY_FULL_TREE_KEYS,
        "source-derived composed security report full-tree programming screen",
    )
    full_tree_ratios = {}
    for field in (
        "conditional_loss",
        "minimum_even_entropy_loss",
        "previous_even_entropy_loss",
        "minimum_wire_entropy_loss",
    ):
        full_tree_ratios[field] = parse_source_security_exact_loss_term(
            full_tree.get(field), label=f"full-tree {field}"
        )
    full_tree_programs = 2 * (1 << 23) - 1
    full_tree_events = full_tree_programs * observed_proof_views
    full_tree_minimum_even_entropy = minimum_even_ghhm_entropy_bits(
        query_log2=64,
        proof_views=observed_proof_views,
        programming_events=full_tree_events,
        target_bits=128,
    )
    full_tree_minimum_byte_entropy = ((full_tree_minimum_even_entropy + 7) // 8) * 8
    full_tree_minimum_wire_entropy = ((full_tree_minimum_byte_entropy + 63) // 64) * 64
    expected_full_tree_ratios = {
        "conditional_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=512,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=full_tree_events,
        ),
        "minimum_even_entropy_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=full_tree_minimum_even_entropy,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=full_tree_events,
        ),
        "previous_even_entropy_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=full_tree_minimum_even_entropy - 2,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=full_tree_events,
        ),
        "minimum_wire_entropy_loss": ghhm_adaptive_programming_ratio(
            entropy_bits=full_tree_minimum_wire_entropy,
            query_log2=64,
            proof_views=observed_proof_views,
            programming_events=full_tree_events,
        ),
    }
    full_tree_supports_128 = (
        expected_full_tree_ratios["conditional_loss"][0] * (1 << 128)
        < expected_full_tree_ratios["conditional_loss"][1]
    )
    if (
        full_tree.get("paper_and_all_points_hypotheses_instantiated") is not True
        or full_tree.get("programs_per_proof") != full_tree_programs
        or full_tree.get("accepted_proof_interactions") != observed_proof_views
        or full_tree.get("total_programming_events_decimal")
        != str(full_tree_events)
        or full_tree.get("conditional_entropy_bits_per_program") != 512
        or any(
            not exact_ratios_equal(full_tree_ratios[field], ratio)
            for field, ratio in expected_full_tree_ratios.items()
        )
        or full_tree.get("supports_strict_128_bits") is not full_tree_supports_128
        or full_tree.get("minimum_even_entropy_bits_for_strict_128")
        != full_tree_minimum_even_entropy
        or full_tree.get("previous_even_entropy_bits")
        != full_tree_minimum_even_entropy - 2
        or full_tree.get("previous_even_entropy_supports_strict_128_bits") is not False
        or full_tree.get("minimum_whole_byte_entropy_bits")
        != full_tree_minimum_byte_entropy
        or full_tree.get("minimum_whole_byte_entropy_bytes")
        != full_tree_minimum_byte_entropy // 8
        or full_tree.get("salt_word_alignment_bytes") != 8
        or full_tree.get("minimum_wire_entropy_bits")
        != full_tree_minimum_wire_entropy
        or full_tree.get("minimum_wire_entropy_bytes")
        != full_tree_minimum_wire_entropy // 8
        or full_tree.get("additional_wire_entropy_bytes")
        != full_tree_minimum_wire_entropy // 8 - 32
        or full_tree.get("current_leaf_tape_entropy_bits") != 512
        or full_tree.get("leaf_input_fiber_refinement_instantiated") is not True
        or full_tree.get("hidden_child_internal_node_propagation_instantiated") is not True
    ):
        reject("source-derived composed security report full-tree screen mismatch")

    lazy = require_object(
        report.get("adaptive_lazy_merkle_programming_screen"),
        "source-derived composed security report lazy-Merkle programming screen",
    )
    require_exact_keys(
        lazy,
        SOURCE_SECURITY_LAZY_MERKLE_KEYS,
        "source-derived composed security report lazy-Merkle programming screen",
    )
    lazy_ratios = {}
    for field in (
        "conditional_leaf_and_final_loss",
        "conditional_internal_node_loss",
        "conditional_combined_loss",
    ):
        lazy_ratios[field] = parse_source_security_exact_loss_term(
            lazy.get(field), label=f"lazy-Merkle {field}"
        )
    expected_lazy_leaf_and_final = ghhm_adaptive_programming_ratio(
        entropy_bits=512,
        query_log2=64,
        proof_views=observed_proof_views,
        programming_events=21 * observed_proof_views,
    )
    expected_lazy_internal = ghhm_adaptive_programming_ratio(
        entropy_bits=1024,
        query_log2=64,
        proof_views=observed_proof_views,
        programming_events=352 * observed_proof_views,
    )
    expected_lazy_combined = add_exact_ratios(
        expected_lazy_leaf_and_final, expected_lazy_internal
    )
    lazy_supports_128 = (
        expected_lazy_combined[0] * (1 << 128) < expected_lazy_combined[1]
    )
    maximum_lazy_observed_views = (
        maximum_lazy_joint_observed_proof_views_for_strict_target(
            query_log2=64, target_bits=128
        )
    )
    first_failing_lazy_observed_views = maximum_lazy_observed_views + 1
    maximum_lazy_ratio = lazy_joint_adaptive_programming_ratio(
        query_log2=64, proof_views=maximum_lazy_observed_views
    )
    first_failing_lazy_ratio = lazy_joint_adaptive_programming_ratio(
        query_log2=64, proof_views=first_failing_lazy_observed_views
    )
    maximum_lazy_supports_128 = (
        maximum_lazy_ratio[0] * (1 << 128) < maximum_lazy_ratio[1]
    )
    first_failing_lazy_supports_128 = (
        first_failing_lazy_ratio[0] * (1 << 128) < first_failing_lazy_ratio[1]
    )
    if (
        lazy.get("source_records_exact_input_output_pairs_for_each_lazy_program") is not True
        or lazy.get("maximum_compact_authentication_nodes") != 372
        or lazy.get("maximum_abstract_programs_per_proof_including_final_piop") != 373
        or lazy.get("fixture_abstract_programs_per_proof_including_final_piop") != 354
        or lazy.get("accepted_proof_interactions") != observed_proof_views
        or lazy.get("maximum_abstract_programming_events_decimal")
        != str(373 * observed_proof_views)
        or lazy.get("maximum_leaf_programs_per_proof") != 20
        or lazy.get("maximum_internal_node_programs_per_proof") != 372
        or lazy.get("internal_node_program_cap_when_leaf_programs_equal_20") != 352
        or lazy.get("joint_leaf_plus_internal_program_cap") != 372
        or lazy.get("weighted_upper_bound_leaf_and_final_program_cap") != 21
        or lazy.get("weighted_upper_bound_internal_node_program_cap") != 352
        or lazy.get("leaf_and_final_conditional_entropy_bits") != 512
        or lazy.get("internal_node_conditional_entropy_bits") != 1024
        or not exact_ratios_equal(
            lazy_ratios["conditional_leaf_and_final_loss"],
            expected_lazy_leaf_and_final,
        )
        or not exact_ratios_equal(
            lazy_ratios["conditional_internal_node_loss"], expected_lazy_internal
        )
        or not exact_ratios_equal(
            lazy_ratios["conditional_combined_loss"], expected_lazy_combined
        )
        or lazy.get("supports_strict_128_bits") is not lazy_supports_128
        or lazy.get("maximum_observed_honest_proof_views_for_strict_128_decimal")
        != str(maximum_lazy_observed_views)
        or lazy.get("first_failing_observed_honest_proof_views_decimal")
        != str(first_failing_lazy_observed_views)
        or lazy.get("maximum_observed_honest_proof_views_supports_strict_128")
        is not maximum_lazy_supports_128
        or lazy.get("first_failing_observed_honest_proof_views_supports_strict_128")
        is not first_failing_lazy_supports_128
        or maximum_lazy_observed_views != 18_889_465_930_379_069_227_007
        or maximum_lazy_supports_128 is not True
        or first_failing_lazy_supports_128 is not False
        or lazy.get("source_role_framed_io_recording_refinement_instantiated") is not True
        or lazy.get("source_duplicate_program_input_rejection_instantiated") is not True
        or lazy.get("executable_rng_to_ideal_fresh_inputs_refinement_instantiated") is not True
        or lazy.get("adaptive_lazy_completion_qrom_reduction_instantiated") is not True
        or lazy.get("concrete_sha512_qro_instantiated") is not True
        or lazy.get("global_prior_query_schedule_instantiated") is not True
    ):
        reject("source-derived composed security report lazy-Merkle screen mismatch")

    claim_ledger = require_object(
        report.get("claim_ledger"), "source-derived composed security report claim ledger"
    )
    require_exact_keys(
        claim_ledger,
        SOURCE_SECURITY_CLAIM_LEDGER_KEYS,
        "source-derived composed security report claim ledger",
    )
    if (
        claim_ledger.get("absent_reductions") != []
        or claim_ledger.get("strongest_quantified_attack_id")
        != "generic-quantum-poseidon2-seven-limb-collision"
        or claim_ledger.get("public_attack_inventory_complete") is not True
    ):
        reject("source-derived composed security report claim ledger mismatch")
    known_attacks = report.get("known_attacks")
    if not isinstance(known_attacks, list) or len(known_attacks) != 7:
        reject("source-derived composed security report known-attack inventory mismatch")
    attack_ids = []
    for index, value in enumerate(known_attacks):
        attack = require_object(value, f"known attacks[{index}]")
        require_exact_keys(
            attack, SOURCE_SECURITY_KNOWN_ATTACK_KEYS, f"known attacks[{index}]"
        )
        attack_ids.append(attack.get("id"))
        if (
            attack.get("end_to_end_forgery_reduction_available") is not False
            or attack.get("independently_reviewed") is not True
        ):
            reject("source-derived composed security report known-attack classification mismatch")
    if attack_ids[0] != claim_ledger["strongest_quantified_attack_id"]:
        reject("source-derived composed security report strongest known-attack mismatch")

    validate_primitive_security_bound_receipt(
        report.get("sha512_primitive_security_bound"),
        label="source-derived composed security report SHA-512 primitive bound",
        primitive_id="SHA-512",
        profile_identity="sha512-fips180-4-full-64-byte-output-role-framed-smz9",
        advantage_function="cms-collision=48*T^3/2^512;preimage=T^2/2^512;T=Q+H",
        activation_height=expected_activation,
        deactivation_height_exclusive=expected_deactivation,
        max_proof_interactions=observed_proof_views,
        honest_exposures=honest_exposures,
        sha512_mode=True,
    )
    validate_primitive_security_bound_receipt(
        report.get("poseidon2_primitive_security_bound"),
        label="source-derived composed security report Poseidon2 primitive bound",
        primitive_id="hegemon-p2w16-v1-114a4e7eb2684d29",
        profile_identity=(
            "hegemon-p2w16-v1-114a4e7eb2684d29;"
            "sha256=114a4e7eb2684d293d13d306a756b03fc734f19edbfb80a07126ab1b2ad9e529"
        ),
        advantage_function=(
            "collision=T^3/p^7;preimage=T^2/p^7;"
            "T=Q+128*V;p=2^64-2^32+1"
        ),
        activation_height=expected_activation,
        deactivation_height_exclusive=expected_deactivation,
        max_proof_interactions=observed_proof_views,
        honest_exposures=poseidon_honest_evaluations,
        sha512_mode=False,
    )
    sha_product_ratio = parse_source_security_exact_loss_term(
        report.get("sha512_to_indexed_product_oracle_reduction_bound"),
        label=(
            "source-derived composed security report SHA-512/product-oracle "
            "reduction bound"
        ),
        expected_id="sha512_to_indexed_product_oracle_reduction",
    )

    assumptions = report.get("assumptions")
    if not isinstance(assumptions, list) or len(assumptions) != len(
        SOURCE_SECURITY_REQUIRED_ASSUMPTIONS
    ):
        reject("source-derived composed security report assumption inventory mismatch")
    for index, (value, expected_id) in enumerate(
        zip(assumptions, SOURCE_SECURITY_REQUIRED_ASSUMPTIONS)
    ):
        assumption = require_object(
            value, f"source-derived composed security report assumptions[{index}]"
        )
        require_exact_keys(
            assumption,
            {"id", "satisfied"},
            f"source-derived composed security report assumptions[{index}]",
        )
        if assumption.get("id") != expected_id:
            reject("source-derived composed security report assumption order mismatch")
        require_true(
            assumption.get("satisfied"),
            f"source-derived composed security report assumptions[{index}].satisfied",
        )
    if report.get("production_eligible") is not True:
        reject("source-derived composed security report production_eligible must equal true")
    if report.get("meets_128_bit_deployed_floor") is not True:
        reject(
            "source-derived composed security report meets_128_bit_deployed_floor "
            "must equal true"
        )
    deployed_floor = require_positive_integer(
        report.get("deployed_composed_security_bits_floor"),
        "source-derived composed security report deployed security floor",
    )
    if deployed_floor < 128:
        reject("source-derived composed security report deployed floor is below 128 bits")
    if deployed_floor < identity["claimed_security_bits"]:
        reject(
            "source-derived composed security report deployed floor is below the "
            "capability claimed_security_bits"
        )
    if report.get("blockers") != []:
        reject("source-derived composed security report blockers must be empty")
    if report.get("security_epoch_is_cryptographic_reset") is not False:
        reject("source-derived composed security report may not treat an epoch as a reset")
    if report.get("unbounded_history_theorem_required") != GLOBAL_QROM_LIFETIME_SCHEMA:
        reject(
            "source-derived composed security report unbounded-history theorem "
            "must name the exact required global QROM lifetime receipt"
        )
    external_terms = report.get("external_whole_view_terms")
    if (
        not isinstance(external_terms, list)
        or len(external_terms) != 4
        or any(term is None for term in external_terms)
    ):
        reject("source-derived composed security report external loss terms are incomplete")
    expected_external_ids = (
        "adaptive_merkle_programming",
        "adaptive_final_piop_programming",
        "concrete_sha512_instantiation",
        "residual_whole_view",
    )
    external_ratios = [
        parse_source_security_exact_loss_term(
            term,
            label=(
                "source-derived composed security report external loss term "
                f"{index}"
            ),
            expected_id=expected_id,
        )
        for index, (term, expected_id) in enumerate(
            zip(external_terms, expected_external_ids)
        )
    ]
    composed_ratio = parse_source_security_exact_loss_term(
        report.get("conditional_global_query_composed_reduction_failure"),
        label=(
            "source-derived composed security report conditional global-query "
            "composed reduction failure"
        ),
        expected_id="conditional_global_query_composed_reduction_failure",
    )
    composed_ratio = add_exact_ratios(composed_ratio, sha_product_ratio)
    history_interactions = observed_proof_views
    for numerator, denominator in external_ratios:
        composed_ratio = add_exact_ratios(
            composed_ratio,
            (numerator * history_interactions, denominator),
        )
    deployed_ratio = parse_source_security_exact_loss_term(
        report.get("deployed_finite_history_composed"),
        label="source-derived composed security report deployed finite-history composition",
        expected_id="deployed_finite_history_composed",
    )
    if deployed_ratio[0] * composed_ratio[1] != composed_ratio[0] * deployed_ratio[1]:
        reject(
            "source-derived composed security report deployed composition omits, "
            "duplicates, or mis-scales a quantitative loss"
        )
    if deployed_floor != exact_ratio_security_bits_floor(*deployed_ratio):
        reject("source-derived composed security report deployed floor/ratio mismatch")


def validate_relation_profile_manifest_binding(
    profile: AuthorizedProfile,
    identity: Mapping[str, object],
    payloads: Mapping[str, bytes],
    paths: Mapping[str, str],
    digests: Mapping[str, str],
) -> None:
    """Bind the profile manifest to the exact relation manifest and program.

    The evidence bundle already pins each file independently.  This check also
    rejects a self-consistent bundle whose profile names a stale relation
    manifest digest or whose relation manifest names a different executable
    program.  The binding is one-way: relation program -> relation manifest ->
    profile manifest -> evidence bundle -> source registry.
    """

    relation = load_evidence_manifest(
        payloads["relation_manifest"], "relation manifest"
    )
    if relation.get("schema") != "hegemon.smallwood.poseidon2-relation-manifest.v1":
        reject("relation manifest schema mismatch")
    if relation.get("profile_id") != profile.profile_id:
        reject("relation manifest profile_id mismatch")
    compiled = require_object(
        relation.get("compiled_relation"), "relation manifest.compiled_relation"
    )
    program_sha512 = require_sha512(
        compiled.get("program_sha512"),
        "relation manifest.compiled_relation.program_sha512",
    )
    if program_sha512 != identity["relation_program_sha512"]:
        reject("relation manifest program SHA-512 does not match exact identity pin")
    relation_id = require_fixed_width_nonzero_hex(
        compiled.get("relation_id"),
        "relation manifest.compiled_relation.relation_id",
        48,
        "relation program SHA-512 prefix",
    )
    if relation_id != program_sha512[: 48 * 2]:
        reject("relation manifest relation_id is not the program SHA-512 prefix")
    semantic_target = require_object(
        relation.get("semantic_target"), "relation manifest.semantic_target"
    )
    if semantic_target.get("id") != (
        "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
    ):
        reject("relation manifest semantic target must equal the source V8 relation v2")
    if (
        semantic_target.get("statement_words") != 120
        or semantic_target.get("binding_limbs") != 7
        or semantic_target.get("field") != "goldilocks"
    ):
        reject("relation manifest semantic target shape mismatch")

    manifest = load_evidence_manifest(
        payloads["profile_manifest"], "profile manifest"
    )
    if manifest.get("schema") != "hegemon.smallwood.poseidon2-profile-manifest.v1":
        reject("profile manifest schema mismatch")
    if manifest.get("profile_id") != profile.profile_id:
        reject("profile manifest profile_id mismatch")
    consensus = require_object(
        manifest.get("consensus_identity"), "profile manifest.consensus_identity"
    )
    consensus_keys = (
        "circuit_version",
        "crypto_suite",
        "family_id",
        "action_id",
        "backend_wire_id",
        "profile_wire_id",
        "domain_set",
        "proof_mode",
    )
    for key in consensus_keys:
        if consensus.get(key) != identity[key]:
            reject(f"profile manifest consensus identity {key} mismatch")
    transport = require_object(
        manifest.get("transport_identity"), "profile manifest.transport_identity"
    )
    transport_bindings = (
        ("outer_magic_ascii", "envelope_magic_hex"),
        ("native_leaf_magic_ascii", "native_leaf_magic_hex"),
        ("inner_proof_magic_ascii", "inner_proof_wire_magic_hex"),
    )
    for manifest_key, identity_key in transport_bindings:
        value = require_string(
            transport.get(manifest_key), f"profile manifest.transport_identity.{manifest_key}"
        )
        try:
            encoded_magic = value.encode("ascii").hex()
        except UnicodeEncodeError as exc:
            raise SuccessorAuthorizationError(
                f"profile manifest transport identity {manifest_key} is not ASCII"
            ) from exc
        if encoded_magic != identity[identity_key]:
            reject(f"profile manifest transport identity {manifest_key} mismatch")
    if (
        transport.get("outer_grammar") != identity["envelope_version"]
        or transport.get("native_leaf_version") != identity["native_leaf_version"]
        or transport.get("inner_proof_version") != identity["inner_proof_wire_version"]
    ):
        reject("profile manifest transport version mismatch")
    size_posture = require_object(
        manifest.get("size_posture"), "profile manifest.size_posture"
    )
    if (
        size_posture.get("projected_inner_proof_bytes") != identity["max_proof_bytes"]
        or size_posture.get("projected_two_output_outer_envelope_bytes") != 128_293
        or size_posture.get("projected_two_output_inline_route_args_bytes")
        != 128_297
        or size_posture.get("projected_two_output_pending_action_bytes")
        != 128_522
        or size_posture.get("maximum_outer_envelope_cap_bytes")
        != identity["max_outer_envelope_bytes"]
        or size_posture.get("maximum_inline_route_args_cap_bytes")
        != identity["max_inline_route_args_bytes"]
        or size_posture.get("maximum_v8_pending_action_cap_bytes")
        != identity["max_v8_pending_action_bytes"]
    ):
        reject("profile manifest proof/action/envelope byte identity mismatch")
    relation_binding = require_object(
        manifest.get("relation_manifest"), "profile manifest.relation_manifest"
    )
    bound_path = require_relative_path(
        relation_binding.get("path"), "profile manifest.relation_manifest.path"
    )
    if bound_path != paths["relation_manifest"]:
        reject("profile manifest relation path does not match bundled relation manifest")
    bound_digest = require_sha512(
        relation_binding.get("sha512"), "profile manifest.relation_manifest.sha512"
    )
    if bound_digest != digests["relation_manifest"]:
        reject("profile manifest relation SHA-512 does not match recomputed manifest")
    if relation_binding.get("relation_id") != relation_id:
        reject("profile manifest relation_id does not match relation manifest")
    diagnostic_report = require_object(
        manifest.get("diagnostic_source_security_report"),
        "profile manifest.diagnostic_source_security_report",
    )
    require_exact_keys(
        diagnostic_report,
        {"bytes", "path", "production_authorizing", "schema", "sha512"},
        "profile manifest.diagnostic_source_security_report",
    )
    if (
        diagnostic_report.get("bytes")
        != NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_BYTES
        or diagnostic_report.get("path")
        != NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_PATH
        or diagnostic_report.get("production_authorizing") is not False
        or diagnostic_report.get("schema") != SOURCE_SECURITY_REPORT_SCHEMA
        or diagnostic_report.get("sha512")
        != NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512
    ):
        reject("profile manifest diagnostic source-security report pin mismatch")
    executable_zk_report = require_object(
        manifest.get("executable_zk_refinement_report"),
        "profile manifest.executable_zk_refinement_report",
    )
    require_exact_keys(
        executable_zk_report,
        {
            "bytes",
            "direct_256_bit_first_program_route_used",
            "exact_lazy_program_keys_exclude_salt_only_point",
            "path",
            "production_eligible",
            "salt_only_oracle_program_count",
            "schema",
            "sha512",
        },
        "profile manifest.executable_zk_refinement_report",
    )
    if executable_zk_report != {
        "bytes": EXECUTABLE_ZK_REFINEMENT_REPORT_BYTES,
        "direct_256_bit_first_program_route_used": False,
        "exact_lazy_program_keys_exclude_salt_only_point": True,
        "path": EXECUTABLE_ZK_REFINEMENT_REPORT_PATH,
        "production_eligible": False,
        "salt_only_oracle_program_count": 0,
        "schema": EXECUTABLE_ZK_REFINEMENT_SCHEMA,
        "sha512": EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512,
    }:
        reject("profile manifest executable-ZK report pin mismatch")
    receipts = require_object(
        manifest.get("required_release_receipts"),
        "profile manifest.required_release_receipts",
    )
    receipt_digest = require_sha512(
        receipts.get("relation_manifest_sha512"),
        "profile manifest.required_release_receipts.relation_manifest_sha512",
    )
    if receipt_digest != digests["relation_manifest"]:
        reject("profile release receipt does not pin recomputed relation manifest SHA-512")
    if (
        receipts.get("executable_zk_refinement_report_sha512")
        != EXECUTABLE_ZK_REFINEMENT_REPORT_SHA512
    ):
        reject("profile executable-ZK release receipt pin mismatch")
    if receipts.get("source_derived_composed_security_report_sha512") is not None:
        reject("profile diagnostic source-security report cannot authorize release")


def validate_retained_smz9_artifact_report(
    root: Path,
    evidence_id: str,
    proof_path: str,
    proof: bytes,
    identity: Mapping[str, object],
    declared_report_bytes: int,
    declared_report_sha512: str,
    expected_source_revision: str,
) -> dict[str, bytes]:
    """Check report identity before invoking the source verifier on the directory."""

    relative = PurePosixPath(proof_path)
    if relative.name != "proof.bin":
        reject(f"evidence {evidence_id} must name the canonical proof.bin")
    expected_parent = PurePosixPath(
        ".agent/artifacts/smallwood-poseidon2-v8"
    ) / evidence_id
    if relative.parent.parent != expected_parent:
        reject(f"evidence {evidence_id} must use its canonical retained-artifact role path")
    expected_leaf = f"smz9-{sha512_bytes(proof)[:24]}"
    if relative.parent.name != expected_leaf:
        reject(f"evidence {evidence_id} must use canonical smz9-<proof-sha512-prefix> naming")
    artifact_directory = relative.parent.as_posix()
    artifact_path = root / artifact_directory
    try:
        observed_files = {entry.name for entry in os.scandir(artifact_path)}
    except OSError as exc:
        raise SuccessorAuthorizationError(
            f"evidence {evidence_id} artifact directory is unreadable: {exc}"
        ) from exc
    if (
        observed_files != RETAINED_ARTIFACT_FILES
        and observed_files != RETAINED_RESEALED_ARTIFACT_FILES
    ):
        reject(
            f"evidence {evidence_id} artifact file inventory mismatch; "
            f"observed={sorted(observed_files)}"
        )
    artifact_payloads: dict[str, bytes] = {}
    for name in sorted(observed_files):
        _, artifact_payloads[name] = read_regular_file_beneath(
            root,
            f"{artifact_directory}/{name}",
            f"evidence {evidence_id} artifact file {name}",
            MAX_EVIDENCE_FILE_BYTES,
        )
    # Use the single descriptor-bound read above for both Python validation and
    # the immutable Rust-verifier snapshot.  A second pathname read would let a
    # concurrent same-user replacement split the digest-pinned report from the
    # report that the source verifier sees.
    report_payload = artifact_payloads["artifact-report.json"]
    if len(report_payload) != declared_report_bytes:
        reject(f"evidence {evidence_id} artifact report byte length mismatch")
    if sha512_bytes(report_payload) != declared_report_sha512:
        reject(f"evidence {evidence_id} artifact report SHA-512 mismatch")
    report = load_evidence_manifest(
        report_payload, f"evidence {evidence_id} artifact report"
    )
    require_exact_keys(
        report,
        {
            "schema",
            "artifact_role",
            "generation_provenance",
            "proof_source_inventory",
            "provenance_transition",
            "proof_randomness_binding",
            "fixture",
            "identity",
            "geometry",
            "bytes",
            "sha512",
            "successor_evidence",
            "verification",
            "opening_surface",
            "timing_milliseconds",
            "generated_unix_seconds",
            "retains_private_witness",
        },
        f"evidence {evidence_id} artifact report",
    )
    if report.get("schema") != RETAINED_ARTIFACT_SCHEMA:
        reject(f"evidence {evidence_id} artifact report schema mismatch")
    if report.get("artifact_role") != evidence_id:
        reject(f"evidence {evidence_id} artifact role mismatch")
    if report.get("retains_private_witness") is not False:
        reject(f"evidence {evidence_id} must not retain a private witness")
    require_positive_integer(
        report.get("generated_unix_seconds"),
        f"evidence {evidence_id} artifact generated_unix_seconds",
    )
    generation_provenance = require_object(
        report.get("generation_provenance"),
        f"evidence {evidence_id} artifact generation provenance",
    )
    require_exact_keys(
        generation_provenance,
        RETAINED_GENERATION_PROVENANCE_KEYS,
        f"evidence {evidence_id} artifact generation provenance",
    )
    if (
        generation_provenance.get("schema")
        != RETAINED_GENERATION_PROVENANCE_SCHEMA
        or generation_provenance.get("artifact_role") != evidence_id
        or generation_provenance.get("generator_source_path")
        != RETAINED_GENERATOR_SOURCE_PATH
    ):
        reject(f"evidence {evidence_id} artifact generation provenance identity mismatch")
    provenance_revision = require_string(
        generation_provenance.get("source_revision"),
        f"evidence {evidence_id} artifact generation provenance source_revision",
    )
    if (
        len(provenance_revision) not in {40, 64}
        or provenance_revision != provenance_revision.lower()
        or any(character not in "0123456789abcdef" for character in provenance_revision)
    ):
        reject(f"evidence {evidence_id} artifact generation source revision is not canonical")
    require_sha512(
        generation_provenance.get("generator_source_sha512"),
        f"evidence {evidence_id} artifact generator source SHA-512",
    )
    require_positive_integer(
        generation_provenance.get("generator_binary_bytes"),
        f"evidence {evidence_id} artifact generator binary bytes",
    )
    require_nonzero_sha512(
        generation_provenance.get("generator_binary_sha512"),
        f"evidence {evidence_id} artifact generator binary SHA-512",
    )
    require_fixed_width_nonzero_hex(
        generation_provenance.get("run_id_hex"),
        f"evidence {evidence_id} artifact generation run id",
        32,
        "the generation run id",
    )
    require_positive_integer(
        generation_provenance.get("process_id"),
        f"evidence {evidence_id} artifact generation process id",
    )
    started_unix_seconds = require_positive_integer(
        generation_provenance.get("started_unix_seconds"),
        f"evidence {evidence_id} artifact generation start time",
    )
    if started_unix_seconds > report["generated_unix_seconds"]:
        reject(f"evidence {evidence_id} artifact generation starts after publication")
    source_inventory = require_object(
        report.get("proof_source_inventory"),
        f"evidence {evidence_id} artifact proof source inventory",
    )
    recomputed_source_inventory = recompute_retained_proof_source_inventory(root)
    if source_inventory != recomputed_source_inventory:
        reject(
            f"evidence {evidence_id} artifact proof source inventory differs from current source"
        )
    source_inventory_root = require_nonzero_sha512(
        source_inventory.get("root_sha512"),
        f"evidence {evidence_id} artifact proof source inventory root",
    )
    transition = require_object(
        report.get("provenance_transition"),
        f"evidence {evidence_id} artifact provenance transition",
    )
    require_exact_keys(
        transition,
        {
            "schema",
            "kind",
            "source_inventory_scope",
            "source_inventory_root_sha512",
            "parent_artifact_report_path",
            "parent_artifact_report_bytes",
            "parent_artifact_report_sha512",
            "v4_verifier_binary_bytes",
            "v4_verifier_binary_sha512",
            "v4_verifier_output_sha512",
            "proof_bytes_preserved_from_parent",
            "pending_action_bytes_preserved_from_parent",
            "generation_independence_established",
            "claim",
        },
        f"evidence {evidence_id} artifact provenance transition",
    )
    if (
        transition.get("schema") != RETAINED_PROVENANCE_TRANSITION_SCHEMA
        or transition.get("source_inventory_root_sha512") != source_inventory_root
        or transition.get("generation_independence_established") is not False
        or transition.get("claim") != "two_distinct_source_verified_proofs"
    ):
        reject(f"evidence {evidence_id} artifact provenance transition mismatch")
    transition_kind = transition.get("kind")
    if transition_kind == "direct_generation":
        if (
            observed_files != RETAINED_ARTIFACT_FILES
            or generation_provenance.get("independence_scope")
            != RETAINED_GENERATION_METADATA_SCOPE
            or transition.get("source_inventory_scope")
            != "generation_start_and_prepublication"
            or transition.get("parent_artifact_report_path") is not None
            or transition.get("parent_artifact_report_bytes") != 0
            or transition.get("parent_artifact_report_sha512") is not None
            or transition.get("v4_verifier_binary_bytes") != 0
            or transition.get("v4_verifier_binary_sha512") is not None
            or transition.get("v4_verifier_output_sha512") is not None
            or transition.get("proof_bytes_preserved_from_parent") is not False
            or transition.get("pending_action_bytes_preserved_from_parent") is not False
        ):
            reject(f"evidence {evidence_id} direct-generation provenance is malformed")
    elif transition_kind == "verified_v4_reseal":
        if observed_files != RETAINED_RESEALED_ARTIFACT_FILES:
            reject(f"evidence {evidence_id} reseal omitted its parent v4 report")
        parent_payload = artifact_payloads["parent-artifact-report-v4.json"]
        parent_report = load_evidence_manifest(
            parent_payload, f"evidence {evidence_id} parent v4 artifact report"
        )
        if (
            provenance_revision != expected_source_revision
            or generation_provenance.get("independence_scope")
            != RETAINED_LEGACY_GENERATION_INDEPENDENCE_SCOPE
            or transition.get("source_inventory_scope")
            != "source_verification_at_reseal"
            or transition.get("parent_artifact_report_path")
            != "parent-artifact-report-v4.json"
            or transition.get("parent_artifact_report_bytes") != len(parent_payload)
            or transition.get("parent_artifact_report_sha512")
            != sha512_bytes(parent_payload)
            or parent_report.get("schema") != RETAINED_LEGACY_ARTIFACT_SCHEMA
            or parent_report.get("artifact_role") != evidence_id
            or parent_report.get("generation_provenance") != generation_provenance
            or require_object(
                parent_report.get("sha512"),
                f"evidence {evidence_id} parent SHA-512 manifest",
            ).get("proof")
            != sha512_bytes(proof)
            or require_object(
                parent_report.get("sha512"),
                f"evidence {evidence_id} parent SHA-512 manifest",
            ).get("pending_action")
            != sha512_bytes(artifact_payloads["pending-action.bin"])
            or transition.get("v4_verifier_binary_bytes")
            != generation_provenance.get("generator_binary_bytes")
            or transition.get("v4_verifier_binary_sha512")
            != generation_provenance.get("generator_binary_sha512")
            or transition.get("proof_bytes_preserved_from_parent") is not True
            or transition.get("pending_action_bytes_preserved_from_parent") is not True
        ):
            reject(f"evidence {evidence_id} verified-v4 reseal provenance is malformed")
        require_nonzero_sha512(
            transition.get("v4_verifier_output_sha512"),
            f"evidence {evidence_id} v4 verifier output SHA-512",
        )
    else:
        reject(f"evidence {evidence_id} artifact provenance transition kind is unsupported")
    proof_randomness = require_object(
        report.get("proof_randomness_binding"),
        f"evidence {evidence_id} artifact proof randomness binding",
    )
    require_exact_keys(
        proof_randomness,
        {"wire_salt_hex", "decs_transcript_root_hex"},
        f"evidence {evidence_id} artifact proof randomness binding",
    )
    require_fixed_width_nonzero_hex(
        proof_randomness.get("wire_salt_hex"),
        f"evidence {evidence_id} wire salt",
        32,
        "the wire salt",
    )
    require_fixed_width_nonzero_hex(
        proof_randomness.get("decs_transcript_root_hex"),
        f"evidence {evidence_id} DECS transcript root",
        64,
        "the DECS transcript root",
    )
    fixture = require_object(
        report.get("fixture"), f"evidence {evidence_id} artifact fixture"
    )
    require_exact_keys(
        fixture,
        {
            "activity_mask",
            "authorization_mode",
            "active_inputs",
            "active_outputs",
            "ciphertext_bytes_per_output",
            "inline_ciphertext_bytes",
            "fee",
        },
        f"evidence {evidence_id} artifact fixture",
    )
    if {
        key: fixture.get(key)
        for key in (
            "activity_mask",
            "authorization_mode",
            "active_inputs",
            "active_outputs",
            "ciphertext_bytes_per_output",
            "inline_ciphertext_bytes",
        )
    } != {
        "activity_mask": 15,
        "authorization_mode": "SingleKey",
        "active_inputs": 2,
        "active_outputs": 2,
        "ciphertext_bytes_per_output": 2147,
        "inline_ciphertext_bytes": 4294,
    }:
        reject(f"evidence {evidence_id} artifact fixture is not maximum shape")
    require_nonnegative_integer(
        fixture.get("fee"), f"evidence {evidence_id} artifact fixture.fee"
    )
    geometry = require_object(
        report.get("geometry"), f"evidence {evidence_id} artifact geometry"
    )
    require_exact_keys(
        geometry,
        set(RETAINED_ARTIFACT_GEOMETRY),
        f"evidence {evidence_id} artifact geometry",
    )
    if geometry != RETAINED_ARTIFACT_GEOMETRY:
        reject(f"evidence {evidence_id} artifact geometry mismatch")
    report_identity = require_object(
        report.get("identity"), f"evidence {evidence_id} artifact identity"
    )
    require_exact_keys(
        report_identity,
        {
            "inner_magic",
            "network_id",
            "relation_digest_hex",
            "relation_program",
            "semantic_relation",
            "transport",
            "consensus_tuple",
            "profile",
        },
        f"evidence {evidence_id} artifact identity",
    )
    relation_digest = require_fixed_width_nonzero_hex(
        report_identity.get("relation_digest_hex"),
        f"evidence {evidence_id} artifact identity.relation_digest_hex",
        48,
        "the native relation id",
    )
    if (
        report_identity.get("inner_magic") != "SMZ9"
        or report_identity.get("network_id") != identity["network_id"]
        or relation_digest != str(identity["relation_program_sha512"])[: 48 * 2]
    ):
        reject(f"evidence {evidence_id} artifact identity mismatch")

    relation_program = require_object(
        report_identity.get("relation_program"),
        f"evidence {evidence_id} artifact identity.relation_program",
    )
    require_exact_keys(
        relation_program,
        {"magic", "bytes", "sha512"},
        f"evidence {evidence_id} artifact identity.relation_program",
    )
    if (
        relation_program.get("magic") != RETAINED_RELATION_PROGRAM_MAGIC
        or relation_program.get("bytes") != RETAINED_RELATION_PROGRAM_BYTES
        or require_sha512(
            relation_program.get("sha512"),
            f"evidence {evidence_id} artifact identity.relation_program.sha512",
        )
        != identity["relation_program_sha512"]
    ):
        reject(f"evidence {evidence_id} artifact relation-program identity mismatch")
    if report_identity.get("semantic_relation") != RETAINED_SEMANTIC_RELATION:
        reject(f"evidence {evidence_id} artifact semantic relation mismatch")

    transport = require_object(
        report_identity.get("transport"),
        f"evidence {evidence_id} artifact identity.transport",
    )
    require_exact_keys(
        transport,
        {"native_leaf_magic", "rpc_envelope_magic"},
        f"evidence {evidence_id} artifact identity.transport",
    )
    try:
        expected_native_magic = bytes.fromhex(
            str(identity["native_leaf_magic_hex"])
        ).decode("ascii")
        expected_envelope_magic = bytes.fromhex(
            str(identity["envelope_magic_hex"])
        ).decode("ascii")
    except (UnicodeDecodeError, ValueError) as exc:
        raise SuccessorAuthorizationError(
            "source-owned transport magic is not canonical ASCII"
        ) from exc
    if transport != {
        "native_leaf_magic": expected_native_magic,
        "rpc_envelope_magic": expected_envelope_magic,
    }:
        reject(f"evidence {evidence_id} artifact transport identity mismatch")

    consensus_tuple = require_object(
        report_identity.get("consensus_tuple"),
        f"evidence {evidence_id} artifact identity.consensus_tuple",
    )
    require_exact_keys(
        consensus_tuple,
        {
            "circuit_version",
            "crypto_suite",
            "family_id",
            "action_id",
            "backend_id",
            "profile_id",
            "domain_set",
        },
        f"evidence {evidence_id} artifact identity.consensus_tuple",
    )
    if consensus_tuple != {
        "circuit_version": identity["circuit_version"],
        "crypto_suite": identity["crypto_suite"],
        "family_id": identity["family_id"],
        "action_id": identity["action_id"],
        "backend_id": identity["backend_wire_id"],
        "profile_id": identity["profile_wire_id"],
        "domain_set": identity["domain_set"],
    }:
        reject(f"evidence {evidence_id} artifact consensus tuple mismatch")

    profile_report = require_object(
        report_identity.get("profile"),
        f"evidence {evidence_id} artifact identity.profile",
    )
    require_exact_keys(
        profile_report,
        set(RETAINED_ARTIFACT_PROFILE),
        f"evidence {evidence_id} artifact identity.profile",
    )
    if profile_report != RETAINED_ARTIFACT_PROFILE:
        reject(f"evidence {evidence_id} artifact SmallWood profile mismatch")

    relation_program_payload = artifact_payloads["relation-program.bin"]
    if (
        len(relation_program_payload) != RETAINED_RELATION_PROGRAM_BYTES
        or not relation_program_payload.startswith(
            RETAINED_RELATION_PROGRAM_MAGIC.encode("ascii")
        )
        or sha512_bytes(relation_program_payload)
        != identity["relation_program_sha512"]
    ):
        reject(f"evidence {evidence_id} artifact relation-program bytes mismatch")
    if artifact_payloads["relation-digest.bin"].hex() != relation_digest:
        reject(f"evidence {evidence_id} artifact relation-digest bytes mismatch")
    if artifact_payloads["network-id.bin"] != int(identity["network_id"]).to_bytes(
        4, "little"
    ):
        reject(f"evidence {evidence_id} artifact network-id bytes mismatch")
    if not artifact_payloads["native-leaf.bin"].startswith(
        expected_native_magic.encode("ascii")
    ):
        reject(f"evidence {evidence_id} artifact native-leaf magic mismatch")
    if not artifact_payloads["rpc-envelope.bin"].startswith(
        expected_envelope_magic.encode("ascii")
    ):
        reject(f"evidence {evidence_id} artifact RPC-envelope magic mismatch")
    if not proof.startswith(b"SMZ9"):
        reject(f"evidence {evidence_id} is not a canonical SMZ9 proof")
    byte_report = require_object(
        report.get("bytes"), f"evidence {evidence_id} artifact bytes"
    )
    require_exact_keys(
        byte_report,
        {
            "measured_inner_proof",
            "projected_max_inner_proof",
            "relation_program",
            "native_leaf",
            "measured_rpc_envelope",
            "projected_max_rpc_envelope",
            "measured_scale_inline_args",
            "projected_max_scale_inline_args",
            "measured_pending_action",
            "projected_max_pending_action",
            "fixed_pending_action_overhead",
            "max_inline_route_args_bytes",
            "max_outer_envelope_bytes",
            "max_v8_pending_action_bytes",
            "fixed_action",
            "inline_ciphertexts",
        },
        f"evidence {evidence_id} artifact bytes",
    )
    measured_proof = require_positive_integer(
        byte_report.get("measured_inner_proof"),
        f"evidence {evidence_id} artifact bytes.measured_inner_proof",
    )
    measured_inline_args = require_positive_integer(
        byte_report.get("measured_scale_inline_args"),
        f"evidence {evidence_id} artifact bytes.measured_scale_inline_args",
    )
    measured_pending_action = require_positive_integer(
        byte_report.get("measured_pending_action"),
        f"evidence {evidence_id} artifact bytes.measured_pending_action",
    )
    if measured_proof != len(proof):
        reject(f"evidence {evidence_id} measured proof length mismatch")
    measured_envelope = len(artifact_payloads["rpc-envelope.bin"])
    expected_byte_report = {
        "measured_inner_proof": len(proof),
        "projected_max_inner_proof": 122_863,
        "relation_program": RETAINED_RELATION_PROGRAM_BYTES,
        "native_leaf": len(artifact_payloads["native-leaf.bin"]),
        "measured_rpc_envelope": measured_envelope,
        "projected_max_rpc_envelope": 128_293,
        "measured_scale_inline_args": len(artifact_payloads["scale-inline-args.bin"]),
        "projected_max_scale_inline_args": 128_297,
        "measured_pending_action": len(artifact_payloads["pending-action.bin"]),
        "projected_max_pending_action": 128_522,
        "fixed_pending_action_overhead": 225,
        "max_inline_route_args_bytes": identity["max_inline_route_args_bytes"],
        "max_outer_envelope_bytes": identity["max_outer_envelope_bytes"],
        "max_v8_pending_action_bytes": identity["max_v8_pending_action_bytes"],
        "fixed_action": 1_140,
        "inline_ciphertexts": len(artifact_payloads["ciphertexts.bin"]),
    }
    if byte_report != expected_byte_report:
        reject(f"evidence {evidence_id} artifact byte report mismatch")
    if (
        len(artifact_payloads["public-statement.bin"]) != 960
        or len(artifact_payloads["ciphertexts.bin"]) != 4_294
        or len(artifact_payloads["relation-binding.bin"]) != 56
        or len(artifact_payloads["transcript-preamble.bin"]) != 1_104
        or len(artifact_payloads["native-leaf.bin"]) != len(proof) + 5_398
        or measured_envelope != len(proof) + 5_430
        or len(artifact_payloads["scale-inline-args.bin"]) != len(proof) + 5_434
        or len(artifact_payloads["pending-action.bin"])
        != len(artifact_payloads["scale-inline-args.bin"]) + 225
        or artifact_payloads["pending-action.bin"].count(
            artifact_payloads["scale-inline-args.bin"]
        )
        != 1
    ):
        reject(f"evidence {evidence_id} artifact transport byte accounting mismatch")
    if measured_inline_args > identity["max_inline_route_args_bytes"]:
        reject(f"evidence {evidence_id} measured inline args exceed identity cap")
    if measured_envelope > identity["max_outer_envelope_bytes"]:
        reject(f"evidence {evidence_id} measured outer envelope exceeds identity cap")
    if measured_pending_action > identity["max_v8_pending_action_bytes"]:
        reject(f"evidence {evidence_id} measured PendingAction exceeds identity cap")
    hash_report = require_object(
        report.get("sha512"), f"evidence {evidence_id} artifact SHA-512 report"
    )
    hash_file_names = {
        "proof": "proof.bin",
        "public_statement": "public-statement.bin",
        "ciphertexts": "ciphertexts.bin",
        "relation_binding": "relation-binding.bin",
        "relation_program": "relation-program.bin",
        "transcript_preamble": "transcript-preamble.bin",
        "native_leaf": "native-leaf.bin",
        "rpc_envelope": "rpc-envelope.bin",
        "scale_inline_action": "scale-inline-args.bin",
        "pending_action": "pending-action.bin",
    }
    require_exact_keys(
        hash_report,
        set(hash_file_names),
        f"evidence {evidence_id} artifact SHA-512 report",
    )
    for report_name, file_name in hash_file_names.items():
        declared_hash = require_sha512(
            hash_report.get(report_name),
            f"evidence {evidence_id} artifact sha512.{report_name}",
        )
        if declared_hash != sha512_bytes(artifact_payloads[file_name]):
            reject(f"evidence {evidence_id} artifact SHA-512 mismatch for {report_name}")
    successor_evidence = require_object(
        report.get("successor_evidence"),
        f"evidence {evidence_id} successor evidence",
    )
    require_exact_keys(
        successor_evidence,
        {"proof", "relation_program"},
        f"evidence {evidence_id} successor evidence",
    )
    proof_evidence = require_object(
        successor_evidence.get("proof"),
        f"evidence {evidence_id} successor proof evidence",
    )
    proof_sha512 = sha512_bytes(proof)
    if generation_provenance.get("proof_sha512") != proof_sha512:
        reject(f"evidence {evidence_id} artifact generation proof digest mismatch")
    if proof_evidence != {
        "id": evidence_id,
        "kind": "proof",
        "path": "proof.bin",
        "bytes": len(proof),
        "sha512": proof_sha512,
    }:
        reject(f"evidence {evidence_id} successor proof label mismatch")
    relation_program_evidence = require_object(
        successor_evidence.get("relation_program"),
        f"evidence {evidence_id} successor relation-program evidence",
    )
    if relation_program_evidence != {
        "id": "relation_program",
        "kind": "program",
        "path": "relation-program.bin",
        "bytes": RETAINED_RELATION_PROGRAM_BYTES,
        "sha512": identity["relation_program_sha512"],
    }:
        reject(f"evidence {evidence_id} successor relation-program label mismatch")

    verification = require_object(
        report.get("verification"), f"evidence {evidence_id} artifact verification"
    )
    require_exact_keys(
        verification,
        {
            "source_factory_immediate",
            "readback_before_publish",
            "same_smz9_bytes_at_every_layer",
            "node_pending_action_lifecycle",
            "honest_map_audit",
            "transport_parser_stage_checks",
            "relation_mutations",
            "proof_and_input_mutations",
            "transport_mutations",
            "pending_action_mutations",
            "ciphertext_mutation",
        },
        f"evidence {evidence_id} artifact verification",
    )
    for field in (
        "source_factory_immediate",
        "readback_before_publish",
        "same_smz9_bytes_at_every_layer",
    ):
        require_true(
            verification.get(field),
            f"evidence {evidence_id} artifact verification.{field}",
        )
    node_pending_action_lifecycle = require_object(
        verification.get("node_pending_action_lifecycle"),
        f"evidence {evidence_id} artifact verification.node_pending_action_lifecycle",
    )
    require_exact_keys(
        node_pending_action_lifecycle,
        RETAINED_NODE_PENDING_ACTION_LIFECYCLE_FIELDS,
        f"evidence {evidence_id} artifact node PendingAction lifecycle",
    )
    for field in RETAINED_NODE_PENDING_ACTION_LIFECYCLE_FIELDS:
        require_true(
            node_pending_action_lifecycle.get(field),
            f"evidence {evidence_id} artifact node PendingAction lifecycle.{field}",
        )
    honest_map = require_object(
        verification.get("honest_map_audit"),
        f"evidence {evidence_id} artifact verification.honest_map_audit",
    )
    require_exact_keys(
        honest_map,
        RETAINED_HONEST_MAP_AUDIT_FIELDS
        | RETAINED_ACCEPTED_PROOF_REFINEMENT_FIELDS,
        f"evidence {evidence_id} artifact verification.honest_map_audit",
    )
    require_true(
        honest_map.get("exact_square_full_rank"),
        f"evidence {evidence_id} artifact honest map exact rank",
    )
    for field in RETAINED_HONEST_MAP_AUDIT_FIELDS - {"exact_square_full_rank"}:
        require_positive_integer(
            honest_map.get(field),
            f"evidence {evidence_id} artifact honest_map_audit.{field}",
        )
    if {
        field: honest_map.get(field) for field in RETAINED_HONEST_MAP_AUDIT_FIELDS
    } != RETAINED_HONEST_MAP_AUDIT:
        reject(f"evidence {evidence_id} artifact honest-map inventory mismatch")
    for field, expected in RETAINED_ACCEPTED_PROOF_REFINEMENT.items():
        if honest_map.get(field) != expected:
            reject(
                f"evidence {evidence_id} artifact accepted-proof refinement {field} mismatch"
            )
    if honest_map.get("proof_bytes") != len(proof):
        reject(
            f"evidence {evidence_id} artifact accepted-proof refinement proof length mismatch"
        )
    if honest_map.get("proof_sha512") != proof_sha512:
        reject(
            f"evidence {evidence_id} artifact accepted-proof refinement proof digest mismatch"
        )
    parser_stage_checks = verification.get("transport_parser_stage_checks")
    if not isinstance(parser_stage_checks, list) or len(parser_stage_checks) != len(
        RETAINED_TRANSPORT_PARSER_STAGES
    ):
        reject(f"evidence {evidence_id} artifact transport parser-stage inventory mismatch")
    for index, (stage_value, expected_stage) in enumerate(
        zip(parser_stage_checks, RETAINED_TRANSPORT_PARSER_STAGES)
    ):
        stage = require_object(
            stage_value,
            f"evidence {evidence_id} artifact transport parser-stage checks[{index}]",
        )
        require_exact_keys(
            stage,
            {"stage", "exact_bytes"},
            f"evidence {evidence_id} artifact transport parser-stage checks[{index}]",
        )
        if stage.get("stage") != expected_stage:
            reject(f"evidence {evidence_id} artifact transport parser-stage label mismatch")
        require_true(
            stage.get("exact_bytes"),
            f"evidence {evidence_id} artifact transport parser-stage checks[{index}].exact_bytes",
        )
    require_rejected_mutations(
        verification.get("relation_mutations"),
        RETAINED_RELATION_MUTATIONS,
        f"evidence {evidence_id} artifact relation mutations",
        includes_error=False,
    )
    require_rejected_mutations(
        verification.get("proof_and_input_mutations"),
        RETAINED_PROOF_MUTATIONS,
        f"evidence {evidence_id} artifact proof mutations",
        includes_error=True,
    )
    require_rejected_mutations(
        verification.get("transport_mutations"),
        RETAINED_TRANSPORT_MUTATIONS,
        f"evidence {evidence_id} artifact transport mutations",
        includes_error=False,
    )
    require_rejected_mutations(
        verification.get("pending_action_mutations"),
        RETAINED_PENDING_ACTION_MUTATIONS,
        f"evidence {evidence_id} artifact PendingAction mutations",
        includes_error=False,
    )
    ciphertext_mutation = require_object(
        verification.get("ciphertext_mutation"),
        f"evidence {evidence_id} artifact ciphertext mutation",
    )
    if ciphertext_mutation != {"name": "ciphertext_byte", "rejected": True}:
        reject(f"evidence {evidence_id} artifact ciphertext mutation mismatch")

    opening_surface = require_object(
        report.get("opening_surface"),
        f"evidence {evidence_id} artifact opening surface",
    )
    require_exact_keys(
        opening_surface,
        RETAINED_OPENING_SURFACE_FIELDS,
        f"evidence {evidence_id} artifact opening surface",
    )
    require_true(
        opening_surface.get("subset_eval_shape_matches_beta_packing_identity"),
        f"evidence {evidence_id} artifact opening-surface packing identity",
    )
    for field in RETAINED_OPENING_SURFACE_FIELDS - {
        "subset_eval_shape_matches_beta_packing_identity"
    }:
        require_nonnegative_integer(
            opening_surface.get(field),
            f"evidence {evidence_id} artifact opening_surface.{field}",
        )
    if opening_surface.get("total_inner_proof_bytes") != len(proof):
        reject(f"evidence {evidence_id} opening surface proof length mismatch")

    timings = require_object(
        report.get("timing_milliseconds"),
        f"evidence {evidence_id} artifact timings",
    )
    require_exact_keys(
        timings,
        {
            "projection_and_relation_mutations",
            "prove_and_internal_verify",
            "independent_source_factory_verify",
            "honest_map_audit",
        },
        f"evidence {evidence_id} artifact timings",
    )
    for field in timings:
        require_nonnegative_integer(
            timings[field], f"evidence {evidence_id} artifact timings.{field}"
        )
    return artifact_payloads


def run_artifact_verifier_command(
    command: list[str], root: Path
) -> tuple[int, str]:
    """Run the source verifier; tests may replace only this process boundary."""

    completed = subprocess.run(
        command,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30 * 60,
        check=False,
    )
    return completed.returncode, completed.stdout


def linux_proc_fd_available() -> bool:
    """Return whether Linux exposes inherited descriptors for exact execution."""

    return Path("/proc/self/fd").is_dir()


def linux_proc_descriptor_identity(
    descriptor: int,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Resolve one inherited descriptor through the Linux procfs execution view."""

    return _owned_file_identity(os.stat(f"/proc/self/fd/{descriptor}"))


def run_descriptor_bound_executable(
    command: list[str],
    root: Path,
    executable_path: Path,
    expected_bytes: int,
    expected_sha512: str,
    label: str,
) -> tuple[int, str]:
    """Execute exact verifier bytes from a sealed anonymous Linux descriptor."""

    if not command or command[0] != str(executable_path):
        reject(f"{label} command does not name the exact built verifier")
    if not sys.platform.startswith("linux"):
        reject(f"{label} execution requires Linux sealed memfd authority")
    if not linux_proc_fd_available():
        reject(f"{label} cannot execute without Linux /proc/self/fd")
    required_os_constants = ("MFD_ALLOW_SEALING",)
    required_fcntl_constants = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    )
    if not hasattr(os, "memfd_create") or any(
        not hasattr(os, name) for name in required_os_constants
    ):
        reject(f"{label} cannot create a sealable Linux memfd")
    if any(not hasattr(fcntl, name) for name in required_fcntl_constants):
        reject(f"{label} cannot enforce the required Linux memfd seals")
    try:
        expected = os.lstat(executable_path)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        reject(f"{label} must be a regular nonsymlink file")
    if expected.st_mode & 0o111 == 0:
        reject(f"{label} is not executable")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(executable_path, flags)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        opened_identity = _owned_file_identity(opened)
        if opened_identity != _owned_file_identity(expected):
            reject(f"{label} changed while being opened")
        if opened.st_uid != os.geteuid():
            reject(f"{label} must be owned by the release user")
        if stat.S_IMODE(opened.st_mode) & 0o022:
            reject(f"{label} must not be group- or world-writable")
        payload = _read_fd(descriptor, MAX_VERIFIER_BINARY_BYTES, label)
        if len(payload) != expected_bytes or sha512_bytes(payload) != expected_sha512:
            reject(f"{label} bytes differ from the private build identity")
        if (
            len(command) >= 2
            and command[1] == "verify"
            and (len(command) != 3 or not Path(command[2]).is_absolute())
        ):
            reject(f"{label} artifact verification path must be absolute")

        memfd_flags = os.MFD_ALLOW_SEALING | getattr(os, "MFD_CLOEXEC", 0)
        try:
            sealed_descriptor = os.memfd_create(
                "hegemon-release-verifier", memfd_flags
            )
        except OSError as exc:
            raise SuccessorAuthorizationError(
                f"cannot create sealed {label} descriptor: {exc}"
            ) from exc
        try:
            written = 0
            while written < len(payload):
                try:
                    count = os.write(sealed_descriptor, payload[written:])
                except InterruptedError:
                    continue
                if count <= 0:
                    reject(f"{label} sealed memfd write failed")
                written += count
            os.fchmod(sealed_descriptor, 0o500)
            required_seals = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            try:
                fcntl.fcntl(sealed_descriptor, fcntl.F_ADD_SEALS, required_seals)
                observed_seals = fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS)
            except OSError as exc:
                raise SuccessorAuthorizationError(
                    f"cannot seal {label} memfd: {exc}"
                ) from exc
            if observed_seals != required_seals:
                reject(f"{label} memfd does not carry the exact required seals")
            sealed_identity = _owned_file_identity(os.fstat(sealed_descriptor))
            sealed_stat = os.fstat(sealed_descriptor)
            if not stat.S_ISREG(sealed_stat.st_mode):
                reject(f"{label} sealed memfd is not a regular file")
            if sealed_stat.st_uid != os.geteuid():
                reject(f"{label} sealed memfd is not owned by the release user")
            if stat.S_IMODE(sealed_stat.st_mode) != 0o500:
                reject(f"{label} sealed memfd has an unsafe mode")
            os.lseek(sealed_descriptor, 0, os.SEEK_SET)
            sealed_payload = _read_fd(
                sealed_descriptor,
                MAX_VERIFIER_BINARY_BYTES,
                f"{label} sealed memfd",
            )
            if sealed_payload != payload or sha512_bytes(sealed_payload) != expected_sha512:
                reject(f"{label} sealed memfd differs from the opened verifier")
            execution_path = f"/proc/self/fd/{sealed_descriptor}"
            try:
                proc_identity = linux_proc_descriptor_identity(sealed_descriptor)
            except OSError as exc:
                raise SuccessorAuthorizationError(
                    f"cannot resolve sealed {label} descriptor through /proc: {exc}"
                ) from exc
            if proc_identity != sealed_identity:
                reject(f"{label} /proc descriptor does not name the sealed memfd")
            completed = subprocess.run(
                [execution_path, *command[1:]],
                executable=execution_path,
                pass_fds=(sealed_descriptor,),
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30 * 60,
                check=False,
            )
            if fcntl.fcntl(sealed_descriptor, fcntl.F_GET_SEALS) != required_seals:
                reject(f"{label} memfd seals changed during execution")
            if _owned_file_identity(os.fstat(sealed_descriptor)) != sealed_identity:
                reject(f"{label} sealed memfd identity changed during execution")
            os.lseek(sealed_descriptor, 0, os.SEEK_SET)
            sealed_payload_after = _read_fd(
                sealed_descriptor,
                MAX_VERIFIER_BINARY_BYTES,
                f"{label} sealed memfd",
            )
            if (
                sealed_payload_after != payload
                or sha512_bytes(sealed_payload_after) != expected_sha512
            ):
                reject(f"{label} sealed verifier bytes changed during execution")
        finally:
            os.close(sealed_descriptor)
        if _owned_file_identity(os.fstat(descriptor)) != opened_identity:
            reject(f"{label} opened inode changed during execution")
        os.lseek(descriptor, 0, os.SEEK_SET)
        opened_payload_after = _read_fd(descriptor, MAX_VERIFIER_BINARY_BYTES, label)
        if (
            opened_payload_after != payload
            or sha512_bytes(opened_payload_after) != expected_sha512
        ):
            reject(f"{label} opened bytes changed during execution")
        return completed.returncode, completed.stdout
    finally:
        os.close(descriptor)


def build_retained_artifact_verifier(
    root: Path,
    target_directory: Path,
    expected_source_inventory_sha512: str,
    expected_source_revision: str,
    *,
    command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> SourceReleaseVerifierBuild:
    """Build and bind both source-current release gates in one private target tree."""

    command = [
        "cargo",
        "build",
        "--locked",
        "--quiet",
        "-p",
        "transaction-circuit",
        "--profile",
        RETAINED_BUILD_PROFILE,
        "--example",
        RETAINED_ARTIFACT_EXAMPLE,
        "--example",
        SOURCE_SECURITY_REPORT_EXAMPLE,
        "--target-dir",
        str(target_directory),
    ]
    try:
        returncode, output = run_with_source_inventory_guard(
            command,
            root,
            command_runner,
            expected_source_inventory_sha512,
            expected_source_revision,
            "source artifact verifier build",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        reject(f"source artifact verifier failed to build: {exc}")
    if returncode != 0:
        tail = output[-2000:].replace("\n", " ").strip()
        reject(f"source artifact verifier failed to build: {tail}")
    verifier = (
        target_directory
        / RETAINED_BUILD_PROFILE
        / "examples"
        / RETAINED_ARTIFACT_EXAMPLE
    )
    binary_bytes, binary_sha512 = sha512_regular_executable(
        verifier,
        "source artifact verifier private output",
        MAX_VERIFIER_BINARY_BYTES,
    )
    security_verifier = (
        target_directory
        / RETAINED_BUILD_PROFILE
        / "examples"
        / SOURCE_SECURITY_REPORT_EXAMPLE
    )
    security_bytes, security_sha512 = sha512_regular_executable(
        security_verifier,
        "source deployed-security verifier private output",
        MAX_VERIFIER_BINARY_BYTES,
    )
    return SourceReleaseVerifierBuild(
        artifact_path=verifier,
        artifact_bytes=binary_bytes,
        artifact_sha512=binary_sha512,
        security_path=security_verifier,
        security_bytes=security_bytes,
        security_sha512=security_sha512,
    )


def verify_source_derived_security_report(
    root: Path,
    verifier_build: SourceReleaseVerifierBuild,
    expected_payload: bytes,
    expected_source_inventory_sha512: str,
    expected_source_revision: str,
    *,
    command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> None:
    """Run the fail-closed Rust deployed gate and byte-compare its exact report."""

    def require_exact_security_binary() -> None:
        observed_bytes, observed_sha512 = sha512_regular_executable(
            verifier_build.security_path,
            "source deployed-security verifier binary",
            MAX_VERIFIER_BINARY_BYTES,
        )
        if (
            observed_bytes != verifier_build.security_bytes
            or observed_sha512 != verifier_build.security_sha512
        ):
            reject("source deployed-security verifier binary changed after its private build")

    require_exact_security_binary()
    command = [str(verifier_build.security_path), "--require-deployed"]
    effective_command_runner = command_runner
    if command_runner is run_artifact_verifier_command:
        effective_command_runner = lambda argv, command_root: run_descriptor_bound_executable(
            argv,
            command_root,
            verifier_build.security_path,
            verifier_build.security_bytes,
            verifier_build.security_sha512,
            "source deployed-security verifier binary",
        )
    try:
        returncode, output = run_with_source_inventory_guard(
            command,
            root,
            effective_command_runner,
            expected_source_inventory_sha512,
            expected_source_revision,
            "source deployed-security verifier",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        reject(f"source deployed-security verifier failed to run: {exc}")
    require_exact_security_binary()
    if returncode != 0:
        tail = output[-2000:].replace("\n", " ").strip()
        reject(f"source deployed-security verifier rejected current source: {tail}")
    if output.encode("utf-8") != expected_payload:
        reject("source deployed-security verifier report bytes do not match evidence")


def verify_retained_artifact_with_source(
    root: Path,
    verifier_binary: Path,
    verifier_binary_bytes: int,
    verifier_binary_sha512: str,
    artifact_payloads: Mapping[str, bytes],
    evidence_id: str,
    expected_source_inventory_sha512: str,
    expected_source_revision: str,
    *,
    command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> None:
    """Verify an immutable private snapshot with the source-current Rust binary."""

    def require_exact_verifier_binary() -> None:
        observed_bytes, observed_sha512 = sha512_regular_executable(
            verifier_binary,
            f"evidence {evidence_id} source artifact verifier binary",
            MAX_VERIFIER_BINARY_BYTES,
        )
        if (
            observed_bytes != verifier_binary_bytes
            or observed_sha512 != verifier_binary_sha512
        ):
            reject(
                f"evidence {evidence_id} source artifact verifier binary changed "
                "after the private build"
            )

    with tempfile.TemporaryDirectory(prefix=f"hegemon-{evidence_id}-") as temporary:
        snapshot = Path(temporary) / evidence_id
        snapshot.mkdir(mode=0o700)
        for name in sorted(artifact_payloads):
            destination = snapshot / name
            with destination.open("xb") as output_file:
                output_file.write(artifact_payloads[name])
                output_file.flush()
                os.fsync(output_file.fileno())
            destination.chmod(0o400)
        command = [
            str(verifier_binary),
            "verify",
            str(snapshot),
        ]
        require_exact_verifier_binary()
        effective_command_runner = command_runner
        if command_runner is run_artifact_verifier_command:
            effective_command_runner = (
                lambda argv, command_root: run_descriptor_bound_executable(
                    argv,
                    command_root,
                    verifier_binary,
                    verifier_binary_bytes,
                    verifier_binary_sha512,
                    f"evidence {evidence_id} source artifact verifier binary",
                )
            )
        try:
            returncode, output = run_with_source_inventory_guard(
                command,
                root,
                effective_command_runner,
                expected_source_inventory_sha512,
                expected_source_revision,
                f"evidence {evidence_id} source artifact verifier",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            reject(f"evidence {evidence_id} source artifact verifier failed to run: {exc}")
        if returncode != 0:
            tail = output[-2000:].replace("\n", " ").strip()
            reject(
                f"evidence {evidence_id} source artifact verifier rejected the artifact: {tail}"
            )
        require_exact_verifier_binary()
        try:
            result = json.loads(
                output,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonstandard_constant,
            )
        except json.JSONDecodeError as exc:
            raise SuccessorAuthorizationError(
                f"evidence {evidence_id} source artifact verifier returned invalid JSON: {exc}"
            ) from exc
        result = require_object(
            result, f"evidence {evidence_id} source artifact verifier result"
        )
        require_exact_keys(
            result,
            {
                "artifact",
                "proof_bytes",
                "rpc_envelope_bytes",
                "scale_inline_args_bytes",
                "pending_action_bytes",
                "proof_sha512",
                "pending_action_sha512",
                "relation_id",
                "relation_program_sha512",
                "semantic_relation",
                "native_leaf_magic",
                "rpc_envelope_magic",
                "consensus_tuple",
                "generation_provenance",
                "verifier_provenance",
                "proof_randomness_binding",
                "source_factory_verified",
                "canonical_transport_verified",
                "canonical_pending_action_verified",
                "hash_manifest_verified",
                "honest_map_audit",
                "node_pending_action_lifecycle",
                "proof_and_input_mutations",
                "transport_mutations",
                "pending_action_mutations",
                "ciphertext_mutation_rejected",
            },
            f"evidence {evidence_id} source artifact verifier result",
        )
        report = load_evidence_manifest(
            artifact_payloads["artifact-report.json"],
            f"evidence {evidence_id} snapshotted artifact report",
        )
        report_identity = require_object(
            report.get("identity"), f"evidence {evidence_id} snapshotted identity"
        )
        report_verification = require_object(
            report.get("verification"),
            f"evidence {evidence_id} snapshotted verification",
        )
        verifier_provenance = require_object(
            result.get("verifier_provenance"),
            f"evidence {evidence_id} source verifier provenance",
        )
        require_exact_keys(
            verifier_provenance,
            {
                "schema",
                "binary_bytes",
                "binary_sha512",
                "target_os",
                "target_arch",
                "rustc_verbose_sha512",
                "source_inventory_root_sha512",
                "generator_binary_equality_required",
            },
            f"evidence {evidence_id} source verifier provenance",
        )
        report_source_inventory = require_object(
            report.get("proof_source_inventory"),
            f"evidence {evidence_id} snapshotted proof source inventory",
        )
        if (
            verifier_provenance.get("schema") != RETAINED_VERIFIER_PROVENANCE_SCHEMA
            or verifier_provenance.get("binary_bytes") != verifier_binary_bytes
            or verifier_provenance.get("binary_sha512") != verifier_binary_sha512
            or verifier_provenance.get("generator_binary_equality_required") is not False
            or verifier_provenance.get("source_inventory_root_sha512")
            != report_source_inventory.get("root_sha512")
        ):
            reject(f"evidence {evidence_id} source verifier self-attestation mismatch")
        require_string(
            verifier_provenance.get("target_os"),
            f"evidence {evidence_id} source verifier target OS",
        )
        require_string(
            verifier_provenance.get("target_arch"),
            f"evidence {evidence_id} source verifier target architecture",
        )
        require_nonzero_sha512(
            verifier_provenance.get("rustc_verbose_sha512"),
            f"evidence {evidence_id} source verifier rustc SHA-512",
        )
        expected_result = {
            "artifact": str(snapshot),
            "proof_bytes": len(artifact_payloads["proof.bin"]),
            "rpc_envelope_bytes": len(artifact_payloads["rpc-envelope.bin"]),
            "scale_inline_args_bytes": len(
                artifact_payloads["scale-inline-args.bin"]
            ),
            "pending_action_bytes": len(artifact_payloads["pending-action.bin"]),
            "proof_sha512": sha512_bytes(artifact_payloads["proof.bin"]),
            "pending_action_sha512": sha512_bytes(
                artifact_payloads["pending-action.bin"]
            ),
            "relation_id": artifact_payloads["relation-digest.bin"].hex(),
            "relation_program_sha512": sha512_bytes(
                artifact_payloads["relation-program.bin"]
            ),
            "semantic_relation": RETAINED_SEMANTIC_RELATION,
            "native_leaf_magic": require_object(
                report_identity.get("transport"),
                f"evidence {evidence_id} snapshotted transport",
            )["native_leaf_magic"],
            "rpc_envelope_magic": require_object(
                report_identity.get("transport"),
                f"evidence {evidence_id} snapshotted transport",
            )["rpc_envelope_magic"],
            "consensus_tuple": report_identity["consensus_tuple"],
            "generation_provenance": report["generation_provenance"],
            "verifier_provenance": verifier_provenance,
            "proof_randomness_binding": report["proof_randomness_binding"],
            "source_factory_verified": True,
            "canonical_transport_verified": True,
            "canonical_pending_action_verified": True,
            "hash_manifest_verified": True,
            "honest_map_audit": report_verification["honest_map_audit"],
            "node_pending_action_lifecycle": report_verification[
                "node_pending_action_lifecycle"
            ],
            "proof_and_input_mutations": report_verification[
                "proof_and_input_mutations"
            ],
            "transport_mutations": report_verification["transport_mutations"],
            "pending_action_mutations": report_verification[
                "pending_action_mutations"
            ],
            "ciphertext_mutation_rejected": True,
        }
        if result != expected_result:
            reject(f"evidence {evidence_id} source artifact verifier result mismatch")
        for name, expected_payload in artifact_payloads.items():
            if (snapshot / name).read_bytes() != expected_payload:
                reject(f"evidence {evidence_id} artifact snapshot changed during verification")


def require_relative_path(value: object, label: str) -> str:
    raw = require_string(value, label)
    if "\\" in raw or "\x00" in raw:
        reject(f"{label} must use a canonical repository-relative POSIX path")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        reject(f"{label} must stay inside the repository without dot components")
    canonical = relative.as_posix()
    if canonical != raw:
        reject(f"{label} must use a canonical repository-relative POSIX path")
    return canonical


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _owned_file_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        *_file_identity(value),
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )


def _read_fd(fd: int, maximum: int, label: str) -> bytes:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        reject(f"{label} is not a regular file")
    if before.st_size > maximum:
        reject(f"{label} exceeds {maximum} bytes")
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            reject(f"{label} changed or truncated while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        reject(f"{label} grew while being read")
    after = os.fstat(fd)
    if _file_identity(before) != _file_identity(after):
        reject(f"{label} changed while being read")
    return b"".join(chunks)


def sha512_regular_executable(
    path: Path, label: str, maximum: int
) -> tuple[int, str]:
    """Hash one exact executable inode without following a final symlink."""

    try:
        expected = os.lstat(path)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        reject(f"{label} must be a regular nonsymlink file")
    if expected.st_size <= 0 or expected.st_size > maximum:
        reject(f"{label} has an invalid byte length")
    if expected.st_mode & 0o111 == 0:
        reject(f"{label} is not executable")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if _file_identity(before) != _file_identity(expected):
            reject(f"{label} changed while being opened")
        digest = hashlib.sha512()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                reject(f"{label} changed or truncated while being hashed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            reject(f"{label} grew while being hashed")
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after):
            reject(f"{label} changed while being hashed")
    finally:
        os.close(fd)
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot recheck {label}: {exc}") from exc
    if _file_identity(after) != _file_identity(current):
        reject(f"{label} pathname changed while being hashed")
    return before.st_size, digest.hexdigest()


def _descriptor_relative_available() -> bool:
    return (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
    )


def read_regular_file_beneath(
    root: Path, relative_value: object, label: str, maximum: int
) -> tuple[str, bytes]:
    relative = require_relative_path(relative_value, label)
    root = root.resolve(strict=True)
    if not root.is_dir():
        reject(f"repository root is not a directory: {root}")
    parts = PurePosixPath(relative).parts

    if _descriptor_relative_available():
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
            file_flags |= os.O_CLOEXEC
        try:
            current_fd = os.open(root, directory_flags)
            for part in parts[:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            file_fd = os.open(parts[-1], file_flags, dir_fd=current_fd)
        except OSError as exc:
            if "current_fd" in locals():
                os.close(current_fd)
            raise SuccessorAuthorizationError(
                f"{label} is missing, nonregular, or traverses a symlink: {relative}: {exc}"
            ) from exc
        try:
            return relative, _read_fd(file_fd, maximum, label)
        finally:
            os.close(file_fd)
            os.close(current_fd)

    # Portable fallback: reject every symlink/reparse-like component, bind the
    # final object by file identity, then re-check the chain after opening.
    current = root
    try:
        for index, part in enumerate(parts):
            current = current / part
            observed = os.lstat(current)
            if stat.S_ISLNK(observed.st_mode):
                reject(f"{label} traverses a symlink: {relative}")
            if index < len(parts) - 1 and not stat.S_ISDIR(observed.st_mode):
                reject(f"{label} has a non-directory parent: {relative}")
        expected = os.lstat(current)
        if not stat.S_ISREG(expected.st_mode):
            reject(f"{label} is not a regular file: {relative}")
        file_fd = os.open(current, os.O_RDONLY)
    except OSError as exc:
        raise SuccessorAuthorizationError(f"cannot open {label} {relative}: {exc}") from exc
    try:
        if _file_identity(os.fstat(file_fd)) != _file_identity(expected):
            reject(f"{label} changed while being opened")
        payload = _read_fd(file_fd, maximum, label)
        check = root
        for part in parts:
            check = check / part
            if stat.S_ISLNK(os.lstat(check).st_mode):
                reject(f"{label} traverses a symlink: {relative}")
        return relative, payload
    finally:
        os.close(file_fd)


def require_release_workflow_binding(root: Path) -> None:
    """Bind the first release authorization command to the reviewed workflow bytes."""

    _, payload = read_regular_file_beneath(
        root,
        RELEASE_WORKFLOW_PATH,
        "release workflow",
        MAX_RELEASE_WORKFLOW_BYTES,
    )
    if sha512_bytes(payload) != RELEASE_WORKFLOW_SHA512:
        reject("release workflow SHA-512 does not match the source-owned authorization pin")


def resolve_checkout_source_revision(root: Path) -> str:
    """Return one stable commit only for a completely clean release checkout."""

    checkout = root.resolve(strict=True)

    def git_output(arguments: list[str], label: str) -> bytes:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=checkout,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            reject(f"cannot {label}: {exc}")
        if completed.returncode != 0:
            reject(
                f"cannot {label}: "
                + completed.stderr.decode("utf-8", errors="replace")[-1000:]
            )
        return completed.stdout

    def current_revision() -> str:
        payload = git_output(
            ["rev-parse", "--verify", "HEAD^{commit}"],
            "resolve release checkout source revision",
        )
        try:
            revision = payload.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise SuccessorAuthorizationError(
                "release checkout source revision is not ASCII"
            ) from exc
        if (
            len(revision) not in {40, 64}
            or revision != revision.lower()
            or any(character not in "0123456789abcdef" for character in revision)
        ):
            reject("release checkout source revision is not a canonical Git object id")
        return revision

    before = current_revision()
    dirty = git_output(
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "inspect release checkout cleanliness",
    )
    if dirty:
        reject("release checkout source revision requires a clean tracked and untracked tree")
    after = current_revision()
    if after != before:
        reject("release checkout source revision changed while being inspected")
    return before


def sha512_bytes(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def capability_identity_sha512(identity: dict[str, object]) -> str:
    """Commit the complete source capability tuple used by native admission."""

    return sha512_bytes(
        canonical_json_bytes(
            {field: identity[field] for field in CAPABILITY_IDENTITY_FIELDS}
        )
    )


def release_evidence_claim_sha512(
    evidence_id: str, result: Mapping[str, object]
) -> str:
    if evidence_id == PRODUCTION_CAPABILITY_MANIFEST_EVIDENCE_ID:
        claim = result.get("capability")
    elif evidence_id == PRODUCTION_VALUE_BALANCE_EVIDENCE_ID:
        claim = result.get("projection")
    elif evidence_id == PROOF_LIFETIME_ACCOUNTING_EVIDENCE_ID:
        claim = result.get("proof_lifetime_accounting")
    elif evidence_id == INDEPENDENT_REVIEW_EVIDENCE_ID:
        claim = result.get("review_attestation")
    elif evidence_id in FORMAL_SECURITY_RECEIPT_BINDINGS:
        claim = result.get("formal_receipt")
    else:
        claim = {"evidence_id": evidence_id}
    return sha512_bytes(canonical_json_bytes(claim))


def validate_lifecycle_capability(
    value: object, identity: Mapping[str, object], label: str
) -> dict[str, object]:
    capability = require_object(value, label)
    require_exact_keys(capability, set(CAPABILITY_IDENTITY_FIELDS), label)
    expected = {field: identity[field] for field in CAPABILITY_IDENTITY_FIELDS}
    if capability != expected:
        reject(f"{label} does not match the complete source capability")
    return capability


def validate_lifecycle_state_binding(
    value: object, identity: Mapping[str, object], label: str
) -> dict[str, object]:
    state = require_object(value, label)
    require_exact_keys(state, LIFECYCLE_STATE_BINDING_KEYS, label)
    parent_height = require_positive_integer(
        state.get("parent_height"), f"{label}.parent_height"
    )
    candidate_height = require_positive_integer(
        state.get("candidate_height"), f"{label}.candidate_height"
    )
    if candidate_height != parent_height + 1:
        reject(f"{label} candidate_height must equal parent_height + 1")
    if candidate_height != identity["activation_height"]:
        reject(f"{label} candidate_height must equal capability activation_height")
    if state.get("relation_digest_hex") != identity["relation_digest_hex"]:
        reject(f"{label} relation digest does not match the source capability")
    note_anchor = require_goldilocks_root(
        state.get("note_anchor"), f"{label}.note_anchor"
    )
    note_root_after = require_goldilocks_root(
        state.get("note_root_after"), f"{label}.note_root_after"
    )
    if note_anchor != identity["note_genesis_root"]:
        reject(f"{label} note anchor does not match capability note_genesis_root")
    if note_root_after == note_anchor:
        reject(f"{label} note_root_after must record the applied note transition")
    for field in (
        "stablecoin_current_root",
        "stablecoin_root_before",
        "stablecoin_root_after",
    ):
        root = require_goldilocks_root(state.get(field), f"{label}.{field}")
        if root != identity["stablecoin_genesis_root"]:
            reject(f"{label}.{field} does not match capability stablecoin genesis")
    if not (
        state["stablecoin_current_root"]
        == state["stablecoin_root_before"]
        == state["stablecoin_root_after"]
    ):
        reject(f"{label} stablecoin before/after roots do not preserve chain state")
    return state


def validate_identity(value: object, label: str) -> dict[str, object]:
    identity = require_object(value, label)
    require_exact_keys(identity, IDENTITY_KEYS, label)
    require_u32(identity["network_id"], f"{label}.network_id")
    for field in (
        "circuit_version",
        "crypto_suite",
        "family_id",
        "action_id",
        "coinbase_action_id",
        "backend_wire_id",
        "profile_wire_id",
        "domain_set",
        "statement_bytes",
        "envelope_version",
        "native_leaf_version",
        "inner_proof_wire_version",
        "consensus_binding_digest_bytes",
        "transaction_digest_bytes",
        "stablecoin_policy_hash_bytes",
        "stablecoin_oracle_commitment_bytes",
        "stablecoin_attestation_commitment_bytes",
        "transcript_digest_bytes",
        "proof_commitment_bytes",
        "security_epoch_max_proofs",
        "max_proofs_per_block",
        "max_proof_actions_per_block",
        "claimed_security_bits",
        "max_proof_bytes",
        "max_outer_envelope_bytes",
        "max_inline_route_args_bytes",
        "max_v8_pending_action_bytes",
    ):
        require_positive_integer(identity[field], f"{label}.{field}")
    require_nonnegative_integer(identity["activation_height"], f"{label}.activation_height")
    if identity["activation_height"] > (1 << 63) - 1:
        reject(f"{label}.activation_height exceeds the V8 relation scalar range")
    require_positive_integer(
        identity["deactivation_height_exclusive"],
        f"{label}.deactivation_height_exclusive",
    )
    expected_deactivation = identity["activation_height"] + RETAINED_SECURITY_EPOCH_BLOCKS
    if identity["deactivation_height_exclusive"] != expected_deactivation:
        reject(
            f"{label}.deactivation_height_exclusive must equal activation_height + "
            f"{RETAINED_SECURITY_EPOCH_BLOCKS}"
        )
    require_fixed_width_nonzero_hex(
        identity["activation_genesis_hash"],
        f"{label}.activation_genesis_hash",
        32,
        "activation genesis hash width",
    )
    require_goldilocks_root(
        identity["stablecoin_genesis_root"], f"{label}.stablecoin_genesis_root"
    )
    require_goldilocks_root(identity["note_genesis_root"], f"{label}.note_genesis_root")
    for field in (
        "statement_magic_hex",
        "envelope_magic_hex",
        "native_leaf_magic_hex",
        "inner_proof_wire_magic_hex",
    ):
        require_magic_hex(identity[field], f"{label}.{field}")
    digest_bytes = identity["consensus_binding_digest_bytes"]
    for field in DIGEST_WIDTH_IDENTITY_FIELDS:
        require_fixed_width_nonzero_hex(
            identity[field],
            f"{label}.{field}",
            digest_bytes,
            "consensus_binding_digest_bytes",
        )
    if identity["transcript_digest_bytes"] != 64:
        reject(f"{label}.transcript_digest_bytes must equal full SHA-512 output width 64")
    for field in SHA512_IDENTITY_PIN_FIELDS:
        require_nonzero_sha512(identity[field], f"{label}.{field}")
    if identity["relation_digest_hex"] != identity["relation_program_sha512"][:96]:
        reject(
            f"{label}.relation_digest_hex must equal the first 48 bytes of "
            "relation_program_sha512"
        )
    if (
        identity["source_derived_security_report_sha512"]
        == NON_AUTHORIZING_DIAGNOSTIC_SECURITY_REPORT_SHA512
    ):
        reject(
            f"{label}.source_derived_security_report_sha512 may not pin the "
            "non-authorizing current-source diagnostic report"
        )
    if identity["proof_mode"] != "inline_self_contained":
        reject(f"{label}.proof_mode must equal inline_self_contained")
    if identity["security_epoch_max_proofs"] < identity["max_proofs_per_block"]:
        reject(
            f"{label}.security_epoch_max_proofs must be at least max_proofs_per_block"
        )
    if identity["max_proofs_per_block"] != RETAINED_MAX_PROOFS_PER_BLOCK:
        reject(
            f"{label}.max_proofs_per_block must equal the shared consensus "
            f"proof-bearing-action cap {RETAINED_MAX_PROOFS_PER_BLOCK}"
        )
    if identity["max_proof_actions_per_block"] != identity["max_proofs_per_block"]:
        reject(
            f"{label}.max_proof_actions_per_block must equal max_proofs_per_block"
        )
    if (
        identity["security_epoch_max_proofs"]
        != RETAINED_SECURITY_EPOCH_MAX_PROOFS
    ):
        reject(
            f"{label}.security_epoch_max_proofs must equal "
            f"{RETAINED_MAX_PROOFS_PER_BLOCK} * {RETAINED_SECURITY_EPOCH_BLOCKS} = "
            f"{RETAINED_SECURITY_EPOCH_MAX_PROOFS}"
        )
    if identity["max_outer_envelope_bytes"] <= identity["max_proof_bytes"]:
        reject(f"{label}.max_outer_envelope_bytes must exceed max_proof_bytes")
    if (
        identity["max_inline_route_args_bytes"]
        != identity["max_outer_envelope_bytes"] + 4
    ):
        reject(
            f"{label}.max_inline_route_args_bytes must equal "
            "max_outer_envelope_bytes + 4"
        )
    if (
        identity["max_v8_pending_action_bytes"]
        != identity["max_inline_route_args_bytes"] + 225
    ):
        reject(
            f"{label}.max_v8_pending_action_bytes must equal "
            "max_inline_route_args_bytes + 225"
        )
    for field, expected in RETAINED_FIXED_IDENTITY_VALUES.items():
        if identity[field] != expected:
            reject(
                f"{label} identity does not match the frozen V8/SMZ9 profile: "
                f"{field} must equal {expected!r}"
            )
    return identity


def validate_registry_entry(key: str, profile: AuthorizedProfile) -> None:
    if profile.profile_id != key or not key:
        reject("source-owned registry key/profile mismatch")
    identity = validate_identity(dict(profile.identity), f"registry[{key}].identity")
    if profile.max_proof_bytes != identity["max_proof_bytes"]:
        reject("source-owned registry max_proof_bytes does not match its exact identity")
    bundle_path = require_relative_path(
        profile.evidence_bundle_path, f"registry[{key}].evidence_bundle_path"
    )
    if bundle_path in AUTHORITY_SOURCE_PATHS:
        reject("source-owned registry may not use an authority source as its evidence bundle")
    require_sha512(
        profile.evidence_bundle_sha512, f"registry[{key}].evidence_bundle_sha512"
    )
    if (
        isinstance(profile.max_evidence_file_bytes, bool)
        or profile.max_evidence_file_bytes <= 0
        or profile.max_evidence_file_bytes > MAX_EVIDENCE_FILE_BYTES
    ):
        reject("source-owned registry max_evidence_file_bytes is outside the fixed cap")
    if profile.required_evidence != tuple(REQUIRED_EVIDENCE_KINDS.items()):
        reject("source-owned registry may not weaken or reorder required evidence")


REGISTRY_RECORD_KEYS = {
    "profile_id",
    "identity",
    "evidence_bundle_path",
    "evidence_bundle_sha512",
    "max_proof_bytes",
}


def authorized_profiles_from_records(records: object) -> dict[str, AuthorizedProfile]:
    """Convert the deliberately data-only source registry into checked records."""

    if not isinstance(records, dict):
        reject("source-owned authorized registry must be a mapping")
    for key in records:
        if not isinstance(key, str) or not key:
            reject("source-owned authorized registry keys must be nonempty strings")

    profiles: dict[str, AuthorizedProfile] = {}
    for key in sorted(records):
        record = require_object(records[key], f"source registry[{key}]")
        require_exact_keys(record, REGISTRY_RECORD_KEYS, f"source registry[{key}]")
        profile_id = require_string(
            record["profile_id"], f"source registry[{key}].profile_id"
        )
        if profile_id != key:
            reject("source-owned registry key/profile mismatch")
        identity = validate_identity(
            record["identity"], f"source registry[{key}].identity"
        )
        profile = AuthorizedProfile(
            profile_id=profile_id,
            identity=dict(identity),
            evidence_bundle_path=require_relative_path(
                record["evidence_bundle_path"],
                f"source registry[{key}].evidence_bundle_path",
            ),
            evidence_bundle_sha512=require_sha512(
                record["evidence_bundle_sha512"],
                f"source registry[{key}].evidence_bundle_sha512",
            ),
            max_proof_bytes=require_positive_integer(
                record["max_proof_bytes"],
                f"source registry[{key}].max_proof_bytes",
            ),
        )
        validate_registry_entry(key, profile)
        profiles[key] = profile
    return profiles


def load_source_owned_registry(
    checker_source: Path = Path(__file__),
) -> dict[str, AuthorizedProfile]:
    """Load the sibling source registry without relying on PYTHONPATH.

    Release invokes this checker with Python isolated mode. Resolving the
    registry from the checker's own committed path keeps both authority files
    in the same checkout and rejects symlink substitution.
    """

    checker = checker_source.resolve(strict=True)
    repository_root = checker.parents[1]
    _, registry_payload = read_regular_file_beneath(
        repository_root,
        SOURCE_REGISTRY_RELATIVE_PATH,
        "source-owned authorized registry",
        MAX_SELECTION_JSON_BYTES,
    )
    try:
        registry_source = registry_payload.decode("utf-8")
        registry_module = ast.parse(
            registry_source,
            filename=str(repository_root / SOURCE_REGISTRY_RELATIVE_PATH),
            mode="exec",
        )
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise SuccessorAuthorizationError(
            f"cannot parse source-owned authorized registry: {exc}"
        ) from exc

    def parse_registry_literal(node: ast.AST, label: str) -> object:
        if isinstance(node, ast.Constant):
            if node.value is None or isinstance(node.value, (str, bool, int)):
                return node.value
            reject(f"{label} contains a non-JSON scalar")
        if isinstance(node, ast.List):
            return [
                parse_registry_literal(element, f"{label}[{index}]")
                for index, element in enumerate(node.elts)
            ]
        if isinstance(node, ast.Dict):
            result: dict[str, object] = {}
            for index, (key_node, value_node) in enumerate(
                zip(node.keys, node.values)
            ):
                if key_node is None:
                    reject(f"{label} may not use dictionary unpacking")
                key = parse_registry_literal(key_node, f"{label} key {index}")
                if not isinstance(key, str) or not key:
                    reject(f"{label} keys must be nonempty strings")
                if key in result:
                    reject(f"{label} contains duplicate key {key!r}")
                result[key] = parse_registry_literal(
                    value_node, f"{label}[{key!r}]"
                )
            return result
        reject(
            f"{label} must use data-only dict/list/string/integer/bool/null literals"
        )

    assignment: ast.Assign | None = None
    for index, statement in enumerate(registry_module.body):
        if (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
            or statement.targets[0].id != "AUTHORIZED_PROFILE_RECORDS"
        ):
            reject(
                "source-owned authorized registry may contain only a module "
                "docstring and one data-only AUTHORIZED_PROFILE_RECORDS assignment"
            )
        if assignment is not None:
            reject("source-owned authorized registry repeats AUTHORIZED_PROFILE_RECORDS")
        assignment = statement
    if assignment is None:
        reject("source-owned authorized registry has no AUTHORIZED_PROFILE_RECORDS")
    return authorized_profiles_from_records(
        parse_registry_literal(assignment.value, "AUTHORIZED_PROFILE_RECORDS")
    )


# Empty by design in this revision. JSON cannot populate this registry. A
# reviewed source edit is required before authorization can succeed.
AUTHORIZED_PROFILES: dict[str, AuthorizedProfile] = load_source_owned_registry()


def authority_source_reference_markers() -> tuple[bytes, ...]:
    """Return path and digest encodings forbidden inside bundled manifests."""

    repository_root = Path(__file__).resolve(strict=True).parents[1]
    markers: list[bytes] = []
    for relative in sorted(AUTHORITY_SOURCE_PATHS):
        payload = (repository_root / relative).read_bytes()
        digest = hashlib.sha512(payload).digest()
        markers.extend(
            (
                relative.encode("utf-8"),
                digest.hex().encode("ascii"),
                digest.hex().upper().encode("ascii"),
                digest,
            )
        )
    return tuple(markers)


AUTHORITY_SOURCE_REFERENCE_MARKERS = authority_source_reference_markers()


def require_source_bound_hermetic_release_authority(
    profile_id: str,
    root: Path,
) -> None:
    """Stop production before tools run unless a complete hermetic root is reviewed."""

    if not sys.platform.startswith("linux"):
        reject("production release authorization requires Linux hermetic authority")
    authority = SOURCE_BOUND_HERMETIC_RELEASE_ROOTS.get(profile_id)
    if authority is None:
        reject(
            "source-owned hermetic release root authority is absent for the profile"
        )
    authority = require_object(authority, "source-owned hermetic release authority")
    require_exact_keys(
        authority,
        HERMETIC_RELEASE_AUTHORITY_KEYS,
        "source-owned hermetic release authority",
    )
    if authority.get("schema") != HERMETIC_RELEASE_AUTHORITY_SCHEMA:
        reject("source-owned hermetic release authority schema mismatch")
    if authority.get("profile_id") != profile_id:
        reject("source-owned hermetic release authority profile mismatch")
    release_root_raw = require_string(
        authority.get("release_root"),
        "source-owned hermetic release authority.release_root",
    )
    release_root = Path(release_root_raw)
    if (
        not release_root.is_absolute()
        or str(release_root) != release_root_raw
        or any(part in {"", ".", ".."} for part in release_root.parts[1:])
    ):
        reject("source-owned hermetic release root must be one canonical absolute path")
    checkout_relative = require_relative_path(
        authority.get("checkout_relative_path"),
        "source-owned hermetic release authority.checkout_relative_path",
    )
    if root.resolve(strict=True) != (release_root / checkout_relative).resolve(
        strict=True
    ):
        reject("release checkout is outside the source-owned hermetic release root")
    for field in (
        "git_metadata_relative_path",
        "dependency_cache_relative_path",
        "release_manifest_relative_path",
        "mount_attestation_relative_path",
    ):
        require_relative_path(
            authority.get(field), f"source-owned hermetic release authority.{field}"
        )
    require_positive_integer(
        authority.get("release_manifest_bytes"),
        "source-owned hermetic release authority.release_manifest_bytes",
    )
    require_sha512(
        authority.get("release_manifest_sha512"),
        "source-owned hermetic release authority.release_manifest_sha512",
    )
    require_positive_integer(
        authority.get("mount_attestation_bytes"),
        "source-owned hermetic release authority.mount_attestation_bytes",
    )
    require_sha512(
        authority.get("mount_attestation_sha512"),
        "source-owned hermetic release authority.mount_attestation_sha512",
    )
    fixed_environment = require_object(
        authority.get("fixed_environment"),
        "source-owned hermetic release authority.fixed_environment",
    )
    if fixed_environment != HERMETIC_RELEASE_FIXED_ENVIRONMENT:
        reject("source-owned hermetic release environment is not the exact fixed map")

    def require_file_inventory(value: object, label: str) -> set[str]:
        if not isinstance(value, list) or not value:
            reject(f"{label} must be a nonempty sorted file inventory")
        roles: set[str] = set()
        previous_role: str | None = None
        paths: set[str] = set()
        for index, raw_entry in enumerate(value):
            entry = require_object(raw_entry, f"{label}[{index}]")
            require_exact_keys(entry, HERMETIC_RELEASE_FILE_KEYS, f"{label}[{index}]")
            role = require_string(entry.get("role"), f"{label}[{index}].role")
            if previous_role is not None and role <= previous_role:
                reject(f"{label} roles must be strictly sorted and unique")
            previous_role = role
            roles.add(role)
            path = require_relative_path(entry.get("path"), f"{label}[{index}].path")
            if path in paths:
                reject(f"{label} paths must be unique")
            paths.add(path)
            require_positive_integer(entry.get("bytes"), f"{label}[{index}].bytes")
            require_sha512(entry.get("sha512"), f"{label}[{index}].sha512")
            if entry.get("owner_uid") != 0:
                reject(f"{label}[{index}] must be root-owned")
            mode = entry.get("mode")
            if (
                isinstance(mode, bool)
                or not isinstance(mode, int)
                or mode < 0
                or mode > 0o777
                or mode & 0o022
            ):
                reject(f"{label}[{index}] mode must not be group- or world-writable")
        return roles

    bootstrap_roles = require_file_inventory(
        authority.get("bootstrap_files"),
        "source-owned hermetic release authority.bootstrap_files",
    )
    if not HERMETIC_RELEASE_REQUIRED_BOOTSTRAP_ROLES.issubset(bootstrap_roles):
        reject("source-owned hermetic release authority omits bootstrap identities")
    command_roles = require_file_inventory(
        authority.get("command_files"),
        "source-owned hermetic release authority.command_files",
    )
    if not HERMETIC_RELEASE_REQUIRED_COMMAND_ROLES.issubset(command_roles):
        reject("source-owned hermetic release authority omits toolchain commands")

    # The schema is frozen now, but no trusted launcher/mount attestation and no
    # descriptor-bound command dispatcher are provisioned in this revision.
    # Never fall through to PATH, git, cargo, or an evidence executable.
    reject("hermetic release runtime is not provisioned in this revision")


def validate_evidence_bundle(
    document: object,
    root: Path,
    profile: AuthorizedProfile,
    *,
    artifact_command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> None:
    bundle = require_object(document, "evidence bundle")
    require_exact_keys(
        bundle,
        {
            "schema",
            "profile_id",
            "identity",
            "source_revision",
            "source_inventory_sha512",
            "evidence_files",
        },
        "evidence bundle",
    )
    if bundle["schema"] != EVIDENCE_BUNDLE_SCHEMA:
        reject("evidence bundle schema mismatch")
    if bundle["profile_id"] != profile.profile_id:
        reject("evidence bundle profile_id mismatch")
    if artifact_command_runner is run_artifact_verifier_command:
        require_source_bound_hermetic_release_authority(profile.profile_id, root)
    identity = validate_identity(bundle["identity"], "evidence bundle.identity")
    if identity != dict(profile.identity):
        reject("evidence bundle identity does not match the source-owned registry")
    source_revision = require_string(
        bundle.get("source_revision"), "evidence bundle.source_revision"
    )
    if source_revision != resolve_checkout_source_revision(root):
        reject("evidence bundle source revision does not match the release checkout")
    source_inventory_sha512 = require_nonzero_sha512(
        bundle.get("source_inventory_sha512"),
        "evidence bundle.source_inventory_sha512",
    )
    initial_source_inventory = recompute_retained_proof_source_inventory(root)
    if initial_source_inventory.get("root_sha512") != source_inventory_sha512:
        reject("evidence bundle source inventory does not match the release checkout")
    entries = bundle["evidence_files"]
    if not isinstance(entries, list):
        reject("evidence bundle.evidence_files must be an array")

    expected = dict(profile.required_evidence)
    observed: dict[str, dict[str, object]] = {}
    previous_id: str | None = None
    for index, value in enumerate(entries):
        entry = require_object(value, f"evidence_files[{index}]")
        entry_id = entry.get("id")
        expected_entry_keys = {"id", "kind", "path", "bytes", "sha512"}
        if entry_id in RETAINED_PROOF_IDS:
            expected_entry_keys |= {
                "artifact_report_bytes",
                "artifact_report_sha512",
            }
        require_exact_keys(
            entry,
            expected_entry_keys,
            f"evidence_files[{index}]",
        )
        evidence_id = require_string(entry["id"], f"evidence_files[{index}].id")
        if previous_id is not None and evidence_id <= previous_id:
            reject("evidence files must be strictly sorted by unique id")
        previous_id = evidence_id
        if evidence_id in observed:
            reject(f"duplicate evidence id {evidence_id}")
        observed[evidence_id] = entry

    if set(observed) != set(expected):
        reject(
            "evidence id set mismatch; "
            f"missing={sorted(set(expected) - set(observed))} "
            f"extra={sorted(set(observed) - set(expected))}"
        )

    for evidence_id, entry in observed.items():
        declared_path = require_relative_path(
            entry["path"], f"evidence {evidence_id}.path"
        )
        fixed_non_source_path = FIXED_NON_SOURCE_EVIDENCE_PATHS_BY_ID.get(evidence_id)
        if fixed_non_source_path is not None and declared_path != fixed_non_source_path:
            reject(
                f"evidence {evidence_id} path must equal the source-owned canonical "
                f"path {fixed_non_source_path}"
            )
        if declared_path in AUTHORITY_SOURCE_PATHS:
            reject(f"evidence {evidence_id} may not include a release authority source")
        if declared_path == profile.evidence_bundle_path:
            reject(f"evidence {evidence_id} may not include the evidence bundle itself")

    source_evidence_ids = {
        evidence_id for evidence_id, kind in expected.items() if kind == "source"
    }
    if set(SOURCE_EVIDENCE_PATHS_BY_ID) != source_evidence_ids:
        reject("source-owned evidence path inventory does not cover exact source ids")
    expected_source_files: list[dict[str, str]] = []
    for evidence_id in sorted(source_evidence_ids):
        expected_path = SOURCE_EVIDENCE_PATHS_BY_ID[evidence_id]
        declared_path = require_relative_path(
            observed[evidence_id]["path"], f"evidence {evidence_id}.path"
        )
        if declared_path != expected_path:
            reject(
                f"evidence {evidence_id} source path must equal the source-owned "
                f"canonical path {expected_path}"
            )
        _, source_payload = read_regular_file_beneath(
            root,
            expected_path,
            f"source-owned evidence {evidence_id}",
            profile.max_evidence_file_bytes,
        )
        source_sha512 = sha512_bytes(source_payload)
        if require_sha512(
            observed[evidence_id]["sha512"], f"evidence {evidence_id}.sha512"
        ) != source_sha512:
            reject(
                f"evidence {evidence_id} digest does not match its source-owned "
                "canonical path"
            )
        expected_source_files.append(
            {"path": expected_path, "sha512": source_sha512}
        )
    expected_source_files.sort(key=lambda source: source["path"])

    paths: set[str] = set()
    digests: set[str] = set()
    evidence_payloads: dict[str, bytes] = {}
    evidence_paths: dict[str, str] = {}
    evidence_digests: dict[str, str] = {}
    proof_digests: list[str] = []
    generation_provenances: list[dict[str, object]] = []
    proof_randomness_bindings: list[dict[str, object]] = []
    retained_artifacts: list[tuple[str, dict[str, bytes]]] = []
    for evidence_id in sorted(expected):
        entry = observed[evidence_id]
        if entry["kind"] != expected[evidence_id]:
            reject(f"evidence {evidence_id} kind mismatch")
        declared_bytes = require_positive_integer(
            entry["bytes"], f"evidence {evidence_id}.bytes"
        )
        declared_sha512 = require_sha512(
            entry["sha512"], f"evidence {evidence_id}.sha512"
        )
        declared_path = require_relative_path(
            entry["path"], f"evidence {evidence_id}.path"
        )
        if declared_path in AUTHORITY_SOURCE_PATHS:
            reject(
                f"evidence {evidence_id} may not include a release authority source"
            )
        if declared_path == profile.evidence_bundle_path:
            reject(f"evidence {evidence_id} may not include the evidence bundle itself")
        path, payload = read_regular_file_beneath(
            root,
            declared_path,
            f"evidence {evidence_id}.path",
            profile.max_evidence_file_bytes,
        )
        if path in paths:
            reject(f"evidence path is reused: {path}")
        paths.add(path)
        if declared_sha512 in digests:
            reject(f"evidence SHA-512 is reused: {declared_sha512}")
        digests.add(declared_sha512)
        if len(payload) != declared_bytes:
            reject(
                f"evidence {evidence_id} byte length mismatch: "
                f"declared={declared_bytes} actual={len(payload)}"
            )
        actual_sha512 = sha512_bytes(payload)
        if actual_sha512 != declared_sha512:
            reject(f"evidence {evidence_id} SHA-512 mismatch")
        if expected[evidence_id] == "manifest":
            bundle_references = (
                profile.evidence_bundle_path.encode("utf-8"),
                profile.evidence_bundle_sha512.encode("ascii"),
                profile.evidence_bundle_sha512.upper().encode("ascii"),
                bytes.fromhex(profile.evidence_bundle_sha512),
            )
            if any(
                reference in payload
                for reference in bundle_references
                + AUTHORITY_SOURCE_REFERENCE_MARKERS
            ):
                reject(
                    f"evidence manifest {evidence_id} may not reference its evidence "
                    "bundle or release authority sources"
                )
        identity_pin_field = PINNED_EVIDENCE_DIGEST_FIELDS.get(evidence_id)
        if (
            identity_pin_field is not None
            and actual_sha512 != identity[identity_pin_field]
        ):
            reject(
                f"evidence {evidence_id} SHA-512 does not match exact identity pin "
                f"{identity_pin_field}"
            )
        if evidence_id == EXECUTABLE_ZK_REFINEMENT_EVIDENCE_ID:
            validate_executable_zk_refinement_report(payload, identity)
        elif (
            expected[evidence_id]
            in {"certificate", "report", "receipt", "manifest", "attestation"}
            and evidence_id
            not in {
                "relation_manifest",
                "profile_manifest",
                "source_derived_composed_security_report",
            }
        ):
            validate_release_evidence_document(
                evidence_id,
                expected[evidence_id],
                payload,
                profile,
                identity,
                expected_source_files,
                source_revision,
                source_inventory_sha512,
                require_sha512(
                    observed["retained_proof_primary"]["sha512"],
                    "evidence retained_proof_primary.sha512",
                ),
                require_positive_integer(
                    observed["retained_proof_primary"]["bytes"],
                    "evidence retained_proof_primary.bytes",
                ),
                require_sha512(
                    observed["retained_proof_independent"]["sha512"],
                    "evidence retained_proof_independent.sha512",
                ),
                root,
                artifact_command_runner,
            )
        if evidence_id == "source_derived_composed_security_report":
            validate_source_security_report_document(payload, identity)
            if artifact_command_runner is run_artifact_verifier_command:
                validate_source_security_primitive_evidence_bindings(
                    payload,
                    root=root,
                    expected_source_inventory_sha512=source_inventory_sha512,
                    independent_review_payload=evidence_payloads[
                        INDEPENDENT_REVIEW_EVIDENCE_ID
                    ],
                    global_qrom_lifetime_receipt_payload=evidence_payloads[
                        GLOBAL_QROM_LIFETIME_EVIDENCE_ID
                    ],
                )
        if evidence_id in RETAINED_PROOF_IDS:
            if len(payload) > profile.max_proof_bytes:
                reject(f"evidence {evidence_id} exceeds the source-owned proof cap")
            proof_digests.append(actual_sha512)
            declared_report_bytes = require_positive_integer(
                entry["artifact_report_bytes"],
                f"evidence {evidence_id}.artifact_report_bytes",
            )
            declared_report_sha512 = require_sha512(
                entry["artifact_report_sha512"],
                f"evidence {evidence_id}.artifact_report_sha512",
            )
            retained_artifacts.append(
                (
                    evidence_id,
                    validate_retained_smz9_artifact_report(
                        root,
                        evidence_id,
                        path,
                        payload,
                        identity,
                        declared_report_bytes,
                        declared_report_sha512,
                        source_revision,
                    ),
                )
            )
            artifact_report = load_evidence_manifest(
                retained_artifacts[-1][1]["artifact-report.json"],
                f"evidence {evidence_id} validated artifact report",
            )
            generation_provenances.append(
                require_object(
                    artifact_report.get("generation_provenance"),
                    f"evidence {evidence_id} validated generation provenance",
                )
            )
            proof_randomness_bindings.append(
                require_object(
                    artifact_report.get("proof_randomness_binding"),
                    f"evidence {evidence_id} validated proof randomness binding",
                )
            )
        evidence_payloads[evidence_id] = payload
        evidence_paths[evidence_id] = path
        evidence_digests[evidence_id] = actual_sha512
    if len(set(proof_digests)) != len(RETAINED_PROOF_IDS):
        reject("retained proof artifacts must be two distinct exact byte strings")
    if len(generation_provenances) != len(RETAINED_PROOF_IDS):
        reject("retained proof artifacts must carry two generation provenance records")
    if len(proof_randomness_bindings) != len(RETAINED_PROOF_IDS):
        reject("retained proofs must carry two verifier-derived randomness bindings")
    if len({binding["wire_salt_hex"] for binding in proof_randomness_bindings}) != 2:
        reject("retained proofs must have two distinct verifier-derived wire salts")
    if (
        len(
            {
                binding["decs_transcript_root_hex"]
                for binding in proof_randomness_bindings
            }
        )
        != 2
    ):
        reject("retained proofs must have two distinct verifier-derived transcript roots")
    validate_relation_profile_manifest_binding(
        profile, identity, evidence_payloads, evidence_paths, evidence_digests
    )
    with tempfile.TemporaryDirectory(prefix="hegemon-v8-verifier-") as temporary:
        verifier_build = build_retained_artifact_verifier(
            root,
            Path(temporary) / "target",
            source_inventory_sha512,
            source_revision,
            command_runner=artifact_command_runner,
        )
        verify_source_derived_security_report(
            root,
            verifier_build,
            evidence_payloads["source_derived_composed_security_report"],
            source_inventory_sha512,
            source_revision,
            command_runner=artifact_command_runner,
        )
        for evidence_id, artifact_payloads in retained_artifacts:
            verify_retained_artifact_with_source(
                root,
                verifier_build.artifact_path,
                verifier_build.artifact_bytes,
                verifier_build.artifact_sha512,
                artifact_payloads,
                evidence_id,
                source_inventory_sha512,
                source_revision,
                command_runner=artifact_command_runner,
            )
    final_source_inventory = recompute_retained_proof_source_inventory(root)
    if final_source_inventory.get("root_sha512") != source_inventory_sha512:
        reject("release checkout source inventory changed during authorization")


def check_selection_document(
    document: object,
    root: Path,
    *,
    require_authorized: bool,
    registry: Mapping[str, AuthorizedProfile] = AUTHORIZED_PROFILES,
    artifact_command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> str | None:
    selection = require_object(document, "successor selection")
    require_exact_keys(
        selection,
        {
            "schema",
            "selection",
            "profile_id",
            "identity",
            "evidence_bundle_path",
            "claim_boundary",
        },
        "successor selection",
    )
    if selection["schema"] != SELECTION_SCHEMA:
        reject("successor selection schema mismatch")
    claim_boundary = require_string(selection["claim_boundary"], "claim_boundary")
    if not claim_boundary.strip():
        reject("claim_boundary must contain non-whitespace text")

    posture = selection["selection"]
    if posture == "unselected":
        for field in ("profile_id", "identity", "evidence_bundle_path"):
            if selection[field] is not None:
                reject(f"unselected successor must keep {field} null")
        if require_authorized:
            reject("no transaction-proof successor is source-authorized")
        return None
    if posture != "selected":
        reject("selection must equal unselected or selected")

    profile_id = require_string(selection["profile_id"], "profile_id")
    profile = registry.get(profile_id)
    if profile is None:
        reject(f"profile {profile_id!r} is absent from the source-owned authorized registry")
    validate_registry_entry(profile_id, profile)
    identity = validate_identity(selection["identity"], "successor selection.identity")
    if identity != dict(profile.identity):
        reject("successor selection identity does not match the source-owned registry")
    bundle_path = require_relative_path(
        selection["evidence_bundle_path"], "evidence_bundle_path"
    )
    if bundle_path != profile.evidence_bundle_path:
        reject("evidence bundle path does not match the source-owned registry")
    _, bundle_payload = read_regular_file_beneath(
        root,
        bundle_path,
        "evidence bundle",
        MAX_EVIDENCE_BUNDLE_JSON_BYTES,
    )
    actual_bundle_sha512 = sha512_bytes(bundle_payload)
    if actual_bundle_sha512 != profile.evidence_bundle_sha512:
        reject("evidence bundle SHA-512 does not match the source-owned registry")
    bundle_document = load_canonical_json_bytes(
        bundle_payload, "evidence bundle", MAX_EVIDENCE_BUNDLE_JSON_BYTES
    )
    validate_evidence_bundle(
        bundle_document,
        root,
        profile,
        artifact_command_runner=artifact_command_runner,
    )
    if not require_authorized:
        return profile_id
    return profile_id


def check_selection_file(
    path: Path,
    root: Path,
    *,
    require_authorized: bool,
    registry: Mapping[str, AuthorizedProfile] = AUTHORIZED_PROFILES,
    artifact_command_runner: ArtifactCommandRunner = run_artifact_verifier_command,
) -> str | None:
    lexical_root = Path(os.path.abspath(root))
    candidate = path if path.is_absolute() else lexical_root / path
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(lexical_root).as_posix()
    except ValueError as exc:
        raise SuccessorAuthorizationError(
            f"selection path must stay inside repository root: {path}"
        ) from exc
    root = lexical_root.resolve(strict=True)
    _, payload = read_regular_file_beneath(
        root, relative, "successor selection", MAX_SELECTION_JSON_BYTES
    )
    document = load_canonical_json_bytes(
        payload, "successor selection", MAX_SELECTION_JSON_BYTES
    )
    return check_selection_document(
        document,
        root,
        require_authorized=require_authorized,
        registry=registry,
        artifact_command_runner=artifact_command_runner,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "selection",
        nargs="?",
        type=Path,
        default=DEFAULT_SELECTION_PATH,
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--require-authorized", action="store_true")
    mode.add_argument("--diagnostic-only", action="store_true")
    parser.add_argument(
        "--verify-retained-artifacts",
        action="store_true",
        help="required in authorization mode; run the source Rust verifier on both artifacts",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    selection_path = args.selection if args.selection.is_absolute() else root / args.selection
    require_authorized = not args.diagnostic_only
    try:
        if require_authorized:
            if not args.verify_retained_artifacts:
                reject("authorization mode requires --verify-retained-artifacts")
            require_release_workflow_binding(root)
        profile_id = check_selection_file(
            selection_path,
            root,
            require_authorized=require_authorized,
        )
    except (OSError, SuccessorAuthorizationError) as exc:
        raise SystemExit(f"Transaction-proof successor release unauthorized: {exc}") from exc
    if profile_id is None:
        print("Transaction-proof successor diagnostic passed: selection=unselected authority=none")
    else:
        print(f"Transaction-proof successor release authorized: profile={profile_id}")


if __name__ == "__main__":
    main()
