#!/usr/bin/env python3
"""Exact, fail-closed composition ledger for odd-field Hegemon candidates.

This module deliberately separates four things that are easy to conflate:

* primary-theorem statements, including their hidden ``O(...)`` constants;
* exact local policy arithmetic used only as a screen;
* source facts about the current Hegemon, Plonky3, and ProveKit candidates; and
* a production composition, which is ``None`` until every required term is
  instantiated and source-bound.

All admission comparisons use :class:`fractions.Fraction`.  Decimal security
bits are never used for a decision.  Missing probabilities are represented by
``None`` and never by zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LEDGER_PATH = HERE / "ledger.json"

SCHEMA = "hegemon.strict-odd-field-composition.v1"
STATUS = "fail_closed_no_selected_architecture"

STRICT_TARGET_BITS = 128
STRICT_TARGET = Fraction(1, 1 << STRICT_TARGET_BITS)
QROM_QUERY_BUDGET = 1 << 64
STRICT_WIRE_HASH_ROLE_TYPE_COUNT = 14
SECURITY_BEARING_TYPED_ROLE_COUNT = 15
CMS_RO_BITS = 512

# Direct SmallWood QROM-ZK sensitivity.  These constants describe only the
# GHCM21 adaptive-reprogramming game; they do not turn the current SmallWood
# transform into CMS/BCS, prove a whole-view simulator, or instantiate SHA-512
# as a quantum random oracle.
SMALLWOOD_DECS_DOMAIN_SIZE = 1 << 20
SMALLWOOD_OPENED_LEAF_COUNT = 23
SMALLWOOD_FIAT_SHAMIR_PROGRAM_POINTS = 8
SMALLWOOD_LEAF_REPROGRAM_POINT_CAP = 2 * SMALLWOOD_DECS_DOMAIN_SIZE
SMALLWOOD_GHCM_REPROGRAM_POINT_CAP = (
    SMALLWOOD_LEAF_REPROGRAM_POINT_CAP + SMALLWOOD_FIAT_SHAMIR_PROGRAM_POINTS
)
SMALLWOOD_CURRENT_LEAF_TAPE_BITS = 512
SMALLWOOD_WIDENED_LEAF_TAPE_BITS = 576
SMALLWOOD_CURRENT_GLOBAL_SALT_BITS = 256
SMALLWOOD_REQUIRED_GLOBAL_SALT_BITS = 512
SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN = 1 << 64
SMALLWOOD_PROVISIONAL_OPENED_TAPE_COUNTS = (23, 48, 55)


def widened_opened_tape_delta_bytes(opened_tape_count: int) -> int:
    """Wire sensitivity for widening each opened tape from 512 to 576 bits."""

    if opened_tape_count < 0:
        raise ValueError("opened tape count must be nonnegative")
    return (
        opened_tape_count
        * (SMALLWOOD_WIDENED_LEAF_TAPE_BITS - SMALLWOOD_CURRENT_LEAF_TAPE_BITS)
        // 8
    )


SMALLWOOD_WIDENED_OPENED_TAPE_DELTA_BYTES = widened_opened_tape_delta_bytes(
    SMALLWOOD_OPENED_LEAF_COUNT
)
SMALLWOOD_GLOBAL_SALT_DELTA_BYTES = (
    SMALLWOOD_REQUIRED_GLOBAL_SALT_BITS - SMALLWOOD_CURRENT_GLOBAL_SALT_BITS
) // 8

R1CS_M_CONSTRAINTS = 20_457_227
R1CS_N_NONCONSTANT = 19_311_555
R1CS_L_PUBLIC = 10_152
R1CS_PRIVATE_TRANSPORT = 77_376
R1CS_DERIVED_AUXILIARY = 19_224_027
R1CS_WITNESS_USED = R1CS_PRIVATE_TRANSPORT + R1CS_DERIVED_AUXILIARY
R1CS_MATRIX_NONZEROS = 94_551_238
R1CS_Z_WITH_CONSTANT = 19_311_556
SPLIT_R1CS_M_CONSTRAINTS = 23_727_052
SPLIT_R1CS_N_NONCONSTANT = 23_613_572
SPLIT_R1CS_DERIVED_AUXILIARY = 23_526_044
SPLIT_R1CS_WITNESS_USED = 23_603_420
SPLIT_R1CS_MATRIX_NONZEROS = 112_255_042
SPLIT_R1CS_Z_WITH_CONSTANT = 23_613_573
CFW_HALF_LENGTH = 1 << 25
CFW_TOTAL_CARRIER = 1 << 26
CFW_HALF_LOG2 = 25
CFW_TOTAL_CARRIER_LOG2 = 26
CFW_LOG_ELL_PLUS_ONE = CFW_HALF_LOG2 + 1
CFW_INNER_MASK_ENCODED_ORACLES = 3 * CFW_LOG_ELL_PLUS_ONE
CFW_OUTER_MASK_ENCODED_ORACLES = CFW_LOG_ELL_PLUS_ONE
CFW_WITNESS_ENCODED_ORACLES = 1
CFW_TOTAL_ENCODED_ORACLES = (
    CFW_INNER_MASK_ENCODED_ORACLES
    + CFW_OUTER_MASK_ENCODED_ORACLES
    + CFW_WITNESS_ENCODED_ORACLES
)
CFW_HVZK_STATISTICAL_UNION_COEFFICIENT = 4 * CFW_HALF_LOG2 + 5
CFW_RBR_MIDDLE_COORDINATE_TERMS = CFW_LOG_ELL_PLUS_ONE
CFW_RBR_TOTAL_COORDINATE_TERMS = 1 + CFW_RBR_MIDDLE_COORDINATE_TERMS + 1 + 1
CFW_MIN_INNER_MESSAGE_FIELD_ELEMENTS = 4
CFW_MIN_OUTER_MESSAGE_FIELD_ELEMENTS = 8
CFW_PROVER_FIELD_ELEMENT_FLOOR = (
    CFW_HALF_LENGTH
    + CFW_INNER_MASK_ENCODED_ORACLES * CFW_MIN_INNER_MESSAGE_FIELD_ELEMENTS
    + CFW_OUTER_MASK_ENCODED_ORACLES * CFW_MIN_OUTER_MESSAGE_FIELD_ELEMENTS
    + CFW_LOG_ELL_PLUS_ONE * (CFW_MIN_OUTER_MESSAGE_FIELD_ELEMENTS + 1)
    + 4
)
E320_CANONICAL_COEFFICIENT_BYTES = 5 * 8
E320_CANONICAL_COEFFICIENT_BITS = 8 * E320_CANONICAL_COEFFICIENT_BYTES
BCS_PROOF_LENGTH_BITS_FLOOR = (
    CFW_PROVER_FIELD_ELEMENT_FLOOR * E320_CANONICAL_COEFFICIENT_BITS
)

GOLDILOCKS_MODULUS = (1 << 64) - (1 << 32) + 1
KOALABEAR_MODULUS = (1 << 31) - (1 << 24) + 1
BABYBEAR_MODULUS = (1 << 31) - (1 << 27) + 1

PLONKY3_REVISION = "5df89eeadae18d6935bb874f8a92808dcc200c9d"
PLONKY3_ROOT = Path(
    "/Users/pldd/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/5df89ee"
)
PROVEKIT_MAIN_REVISION = "4b61b5d68e633a044eb41de4a6934d52ffdcbedc"
PROVEKIT_V1_BRANCH_REVISION = "9b2a6f37c67691eab4b0cec6c35e35c520e93285"
PROVEKIT_V1_TAG_OBJECT = "add654221a069ac1412caa747777e781e6901474"
PROVEKIT_V1_TAG_COMMIT = "253113f4be6bc256551a43fa56084e84af2db013"
PROVEKIT_WHIR_REVISION = "0aeaa7f337c743d9ddfcb9d909628d6491e3355c"
SPONGEFISH_REVISION = "fcc277f8a857fdeeadd7cca92ab08de63b1ff1a1"


# These source-only artifacts were independently checked before this ledger was
# generated.  They are deliberately pinned here so a later source edit makes
# this package fail closed rather than silently changing its meaning.
LOCAL_SOURCE_PINS: Mapping[str, str] = {
    ".agent/hardening/strict-qrom-profile-selection/profile_manifest.json":
        "9fce9c878b4814318c5fee0a03be61366fb09c2416240d07f6a0ed51e07cd500b35c9fa4822578b6ad379792e79c7bd62197701e00543a2f58c492187ed616dd",
    ".agent/hardening/strict-qrom-profile-selection/theorem_premise_map.json":
        "43aa3a028b14316184604f06da4d6c7ec4d9eb65a5bc9603e4b078b3f4a0a5c8450b42d96334fb7b6c0018fd04863dda908088f2e896fdf774efefd01c151fd5",
    ".agent/hardening/strict-qrom-profile-selection/strict_qrom_profile.py":
        "a7b26a1ecff3767016d45ebe00cf9ccb85bdd188406b073afc7a2a6c453b427d9babafaf6ea8a6c3e8aefc7781de20c524097c367e6dcba87ae9b2d6ce37c183",
    ".agent/hardening/hvzk-whir-strict-wire-profile/profile.json":
        "186629728ffe1af2671fd34d9447c2bbe3719a13501caafe673a99cc63f1c544b1c1fe8bc16b329dece6e37c965ec2abdacf89fe993bf46f8df3c2262ae87951",
    ".agent/hardening/hvzk-whir-strict-wire-profile/source_evidence.json":
        "d31620c4f5d13f844afc489aeac249fe05cb20ede10da78bcf1fb3bbf3f9886388aeeb5fbe1a2871d93821108ba357c07729c2967bbc946ccf0f3cbe73f308ea",
    ".agent/hardening/hvzk-whir-strict-wire-profile/hvzk_whir_profile.py":
        "6be03c4db96dad8214787be2f1a3a7f2f587b0304028f8a7e8fce4a908c3fa87d9be9c16ec1850c7c6183af1b7f09172a6a2e305fde2c5bd646eba5104932e04",
    ".agent/hardening/hvzk-whir-strict-wire-profile/CFW26_SECTION11_SPEC_AUDIT.md":
        "d80e57702a1d07d25579faabfe0b1606632d053688a60092ea5a0690d00d3aa29de7950e769968a10d9384831aec9ab2d2145c9fe2fb62dfbd89c465bd87810a",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/certificate.json":
        "f6b2cdc6944a55c013d5d89644579ac8e10cb20cac7e74e5887b8230c735e3b8d4adea09a130fe35e8eb0327ba99ec8ac27e119b764c3995a15d2b16375e4bfd",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json":
        "dae278e46a5d2ed2c58fae4443db8b73967f2b1190336520081a6f3791c04fad63d182cc61c0e1fb75f66bdb70e9ff40d4b1b975d9295fcf3a93bf189c76607e",
    ".agent/hardening/hvzk-whir-odd-field-r1cs/compiler.py":
        "62bd836c41fac8691e2ff97414c33d3bb955ae2b5cb833721e811e3e52b43c1793676a98178007fc3727bad825545cd8075d06b44c467d4d54b6a3cdf70226b5",
    ".agent/hardening/smallwood-v6-qrom-composition/CONCRETE_HASH_QROM_AUDIT.md":
        "7abb31345d078869747ac73101cd61fae7767186e4ecf0759cf33f3aded3c2a2086aa3a14aa3857c837665956724c64581ea123a94057eed9d5d7cefbf9b5170",
    ".agent/hardening/smallwood-v6-qrom-composition/escape_hatch.py":
        "a4ecaf4cff94eb154da527d37f440eb77a7f74b8dc09a4715dcaff94b0ededb3a0a4a1a3ccb6f3e712ab5b2e2f90b8fd0a8291eb2b57b2c91228f24ad750828d",
    ".agent/hardening/smallwood-v6-qrom-composition/profile.json":
        "1655ea03ef65761f95de24e16a55e8b436bc0922182c716738d0ddaf2879eb8064c14be0344c59dc811250f2ad2cde124ad48a12cf37f4b42b27aadcff1af90a",
    ".agent/hardening/standard-hash-successor/PARITY_CONTRACT.md":
        "16525a546c433e9bb4bd92909a379192bf1bc189ec5164c9b7815686afbff1c15bf34201c7b29acc48646c1081698fc777579bc8bd57f1b2d1ea8234402f7d4e",
    ".agent/hardening/hvzk-whir-r1cs-ior/certificate.json":
        "3ce57f71ea09b564ecc9ca0ad3f54d6b2e341aba057ef737bfa58ebb74793cc6535f089fa3212f9776d39333a36ce2caa9fa6cf717ecd04990117687f8fc011f",
    ".agent/hardening/hvzk-whir-r1cs-ior/source-manifest.json":
        "410db0d60fe6bd5091def488af821f10291e170b2bee295783cf76b024e9c6f15affe779b71396b82ef38aeea08be64dbf7d1c6d02d8f0c70c2f3b8ebcdb8c46",
    ".agent/hardening/hvzk-whir-r1cs-ior/check_cfw26_r1cs_ior.py":
        "54f73f57edf78f2f6d08524402ecc8caa4b183460540d8e09732d1cb961cc1c76c638907440790c6fdab8d11c05045224eb5b78ad942ce15d087b39043fc18a5",
}

PLONKY3_SOURCE_PINS: Mapping[str, str] = {
    "field/src/extension/mod.rs":
        "3eeeed69262e9edb6f90cb9d537f8acac24a1699644397025d9b5ca69f1e7baf55a535b36a736aaf89d853df864327b6f768d83212e0eee8c149b290ad970ac0",
    "field/src/extension/binomial_extension.rs":
        "4e09114e9813f15ff373d4265b73b9ec76827ac6c305cea9e9c1c58caa7e903db5ee648897ec7d6f72c83aec898c50d81d4e2d02bc75761b449f561b8b650d77",
    "goldilocks/src/extension.rs":
        "73c837919bfd74aa0fe1241088209daf5d1efd980140265897bb7044450e5f9c35c7502be986b723d74e41e7a7e367b76291214132547f96a5e6e8ce05c7b55a",
    "goldilocks/src/goldilocks.rs":
        "81dc364dda3c37dffd8f083c15b8827e0075121266030f93dd4e72f73268f90c613e0b6457841d79f79c17a31529b69eb32d0f85472c6743fa682a7d8eafc00b",
    "koala-bear/src/koala_bear.rs":
        "623910f93d2a2e94d235df1182a9bfaf9858bb9c06e892d460d5d7871ea774f8e723f2470f963ef3ee999a8b6ff45f09820fc488d2026fcd06f3de6b11292a73",
    "baby-bear/src/baby_bear.rs":
        "6e7a2648c903e0352bd97678ac1748c8b10c9acf878dbb0a06c1f4349294fa1bb9af2b216566ac0b6cf290914ae2681d644c2a97523480288c3b1390185aefd1",
    "whir/src/pcs/zk/adapter.rs":
        "cbffc7b9330e857ed76562d9ea32be3d50b5a004102844f5325c456b7076276c9dba18e4ceac1c4275075a2ab2ca468bc363124f1c635dfbbbf943f7c2fd0e40",
    "whir/src/pcs/zk/config.rs":
        "b63c0b6b796d9c44e1a68e28e9935d72cc1710babc3e09febb1f59d1655e5807136294fc7b07ea7ef5f29ccf596aaa0cc31a82a3299b6782db2cffdd02e74832",
}

# Remote bytes were fetched from raw.githubusercontent.com at the immutable
# commit paths below and SHA-512 hashed.  The checker validates this retained
# pin set but intentionally does not perform network access.
REMOTE_SOURCE_PINS: Sequence[Mapping[str, str]] = (
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "README.md",
        "sha512": "5cef3af3aac5c5004d82f436d25254d1375e540a3ff212eda298c40dcaf7ef3425f3624cfd3cf0af7a5e16af03879b58ba0f80926ed26df34dfd99597eda39d9",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "docs/src/content/docs/concepts/security-model.mdx",
        "sha512": "b3ebe5deb7cd8407d00f1d56d0e0a7792ad3637dad673c337b9424fdff7ea390680b4641606594978de33c77e89c9221cfcaadc0d57679d88eac07a3fe6ac74b",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/common/src/hash_config.rs",
        "sha512": "0a4383d89eb677cfad0147bf3538933c57395b7f6e747906f83180db0ac6801d6d191bc0e5dc76c72f458ecbfc89a7a12d48268f5ec06130653a42b60e08a312",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/common/src/whir_r1cs.rs",
        "sha512": "1ee1f2d289bf1ad32ba634cc5fe6154512b502ff72ee2d3059960db9a8cfc908688f5eeb08bf2d38874458acc44b3610d9037702dc115aa7526d98777dfd01e6",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/prover/src/whir_r1cs.rs",
        "sha512": "8d0aff4701bb5c7d3091575faec6ee94dbdc5a326dcf03f169e868021722a5e5bb6b5dbc52b60569e27cc5aa8fc34ea75489b31e182f9aef2da46fba604b725e",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/verifier/src/whir_r1cs.rs",
        "sha512": "b823c809935b9d444b9852e714553a632e24e6a9d963255966e49dd18a9040e3643904357d815b211a9a5f3a51ef5ef19b9ec4a14fc223f5db1d935d0226b9ce",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/backend/bn254/src/transcript_sponge.rs",
        "sha512": "374de5f60647d8835876d45a92f13503c6728b4d9c94fc2f4a5395023e3e437ff6e42d33336948ca073eb98d5a95e3c70ad92070b398d83f0683e8e4e0e4f2cd",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "provekit/backend/goldilocks/src/transcript_sponge.rs",
        "sha512": "ed3fa126295dc3e3b766803a5fedf16d71caeaf5f4721bd8cc5b2f645cf24b8fd915e6e3cf532f0394bce5fef0b3f6ad77f4d08752b015cfc9dfc45c08cdfea8",
    },
    {
        "repository": "https://github.com/worldfnd/ProveKit",
        "revision": PROVEKIT_MAIN_REVISION,
        "path": "Cargo.lock",
        "sha512": "855d8ae5d0c93d99e9ac1644d1b2a75669e8f757733e20970589988dcb1415bb46453c111d3862e015260e4f15de00b133b86e22c020df9507971205ab1e1685",
    },
    {
        "repository": "https://github.com/WizardOfMenlo/whir",
        "revision": PROVEKIT_WHIR_REVISION,
        "path": "src/hash/mod.rs",
        "sha512": "c8eccd48cdad599814143e695b2a6d198a1c68631be8aed86f885c73df1f091f61f9da88a20f0993ca8373382f0a045c674c484f4e92b28edc126e031e9c9934",
    },
    {
        "repository": "https://github.com/WizardOfMenlo/whir",
        "revision": PROVEKIT_WHIR_REVISION,
        "path": "src/hash/digest_engine.rs",
        "sha512": "85f0e5e7ea6f51f89cf12d36b291ddbbc9e83b83b7665562f092f4b2801847d9914e2ea7a447aae02ececd8fa7a3cf3e4bf21a31126520282a79f3d5a5185955",
    },
    {
        "repository": "https://github.com/WizardOfMenlo/whir",
        "revision": PROVEKIT_WHIR_REVISION,
        "path": "src/hash/blake3_engine.rs",
        "sha512": "17b619f8a60323af26d07b60dcf25fcac5adf9b4d2801d44293d3ae4d5ad10bc6f4eb3b7c1bacf0f1b0ca51f6277df4464b0e191d2d29c94018aee7d5c477902",
    },
    {
        "repository": "https://github.com/WizardOfMenlo/whir",
        "revision": PROVEKIT_WHIR_REVISION,
        "path": "src/parameters.rs",
        "sha512": "a50e87c1a3908a9ba5f704afc9192ee343f817b74bb5cce4a398aa29cb8ac6a4e5c7719a9e467c0ea3a8168844ce44d3c2944e45b5a7a8457f5057a78140cfce",
    },
    {
        "repository": "https://github.com/WizardOfMenlo/whir",
        "revision": PROVEKIT_WHIR_REVISION,
        "path": "src/protocols/merkle_tree.rs",
        "sha512": "6a3d511d3794103d0d4738083430ee3a9dc33c115e5e885d705b527c77d527badff535249965a032d8647770eb5ac7e17bd7dcfadd08b035af3f062e02e590f2",
    },
)


REQUIRED_TERM_IDS: tuple[str, ...] = (
    "exact_transaction_relation_refinement",
    "odd_field_r1cs_compiler_refinement",
    "host_only_manifest_and_consensus_boundary",
    "r1cs_to_cic_ior",
    "ior_honest_completeness",
    "ior_output_relation_typing",
    "pcs_binding",
    "pcs_proximity",
    "pcs_list_decoding",
    "pcs_zero_evader",
    "iop_soundness",
    "rbr_soundness",
    "rbr_knowledge",
    "cms_knowledge_notion_compatibility",
    "complete_hvzk_iop",
    "complete_zk_noninteractive",
    "bcs_salted_commitment_hiding",
    "bcs_cms_fiat_shamir_qrom",
    "cms_augmented_query_expansion",
    "transcript_ideal_to_concrete_qrom",
    "mmcs_collision_and_second_preimage",
    "mmcs_selective_opening_hiding",
    "quantum_collision_union",
    "quantum_preimage_and_prf_union",
    "challenge_sampling_bias_and_abort",
    "grinding_failure",
    "prover_retry_reset_and_restart",
    "rng_entropy_failure_and_reuse",
    "semantic_hash_role_union",
    "physical_hash_call_union",
    "multi_proof_union",
    "authorization_mode_and_activity_mask_union",
    "action_and_block_union",
    "adversarial_history_and_epoch_union",
    "consensus_lifetime_union",
    "canonical_parser_refinement",
    "native_verifier_refinement",
    "formal_refinement",
    "wallet_rpc_relay_mempool_block_sync_reorg_refinement",
    "release_source_and_artifact_closure",
)


def canonical_json(value: Any) -> str:
    """Return the only admitted ledger encoding."""

    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def factored(value: Fraction) -> dict[str, str]:
    if not isinstance(value, Fraction):
        raise TypeError("exact values must be Fractions")
    return {"denominator": str(value.denominator), "numerator": str(value.numerator)}


def from_factored(value: Mapping[str, str]) -> Fraction:
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def strict_gt_128(value: Fraction) -> bool:
    """Return true only for advantage strictly below 2^-128."""

    if not isinstance(value, Fraction):
        raise TypeError("security comparisons require exact Fractions")
    return value < STRICT_TARGET


def integer_security_bits(value: Fraction) -> int:
    """Largest integer b for which value <= 2^-b.

    This display helper does not perform admission.  In particular an exact
    value of 2^-128 displays 128 but fails :func:`strict_gt_128`.
    """

    if value <= 0:
        raise ValueError("advantage must be positive")
    if value > 1:
        return -1
    bits = 0
    while value <= Fraction(1, 1 << bits):
        bits += 1
    return bits - 1


def exact_value_record(value: Fraction) -> dict[str, Any]:
    return {
        "exact_fraction": factored(value),
        "integer_security_bits_display": integer_security_bits(value),
        "strictly_below_2^-128": strict_gt_128(value),
    }


def compose_required(values: Mapping[str, Fraction | None]) -> Fraction | None:
    """Union all required terms, returning None when even one is missing."""

    if set(values) != set(REQUIRED_TERM_IDS):
        raise ValueError("required composition term set mismatch")
    if any(value is None for value in values.values()):
        return None
    total = Fraction(0, 1)
    for value in values.values():
        if not isinstance(value, Fraction) or value < 0:
            raise TypeError("present terms must be nonnegative exact Fractions")
        total += value
    return total


def local_hash_width_terms(output_bits: int) -> dict[str, Any]:
    """Return exact *policy screens*, not concrete-hash theorem bounds.

    The unit-coefficient shapes q^3/2^n and q^2/2^n mirror the asymptotic
    quantum collision and preimage exponents.  Primary results do not make
    unit constants an exact reduction for SHA-2, Keccak, BLAKE3, or SHAKE.
    Consequently these values can disqualify a width but cannot authorize a
    concrete primitive.
    """

    if output_bits < 1:
        raise ValueError("invalid hash-width screen")
    collision = Fraction(QROM_QUERY_BUDGET**3, 1 << output_bits)
    optimistic_preimage = Fraction(QROM_QUERY_BUDGET**2, 1 << output_bits)
    amplitude_preimage = Fraction((2 * QROM_QUERY_BUDGET + 1) ** 2, 1 << output_bits)
    return {
        "amplitude_preimage_screen": exact_value_record(amplitude_preimage),
        "collision_unit_policy": exact_value_record(collision),
        "optimistic_preimage_unit_policy": exact_value_record(optimistic_preimage),
        "physical_call_cap": None,
        "physical_call_union": None,
        "role_type_union": None,
        "theorem_exact_constant": None,
        "theorem_shape_only": "collision O(q^3/2^n); preimage O(q^2/2^n)",
        "unit_constants_are_local_policy": True,
    }


def hash_profile_record(
    profile_id: str,
    primitive: str,
    output_bits: int,
    *,
    provekit_selectable: bool,
    conventional: bool = True,
) -> dict[str, Any]:
    terms = local_hash_width_terms(output_bits)
    collision = from_factored(terms["collision_unit_policy"]["exact_fraction"])
    preimage = from_factored(terms["optimistic_preimage_unit_policy"]["exact_fraction"])
    return {
        "concrete_qrom_bridge": None,
        "conventional": conventional,
        "output_bits": output_bits,
        "primitive": primitive,
        "profile_id": profile_id,
        "provekit_selectable_at_pinned_main": provekit_selectable,
        "source_width_screen": terms,
        "strict_collision_screen": strict_gt_128(collision),
        "strict_preimage_screen": strict_gt_128(preimage),
        "strict_width_screen": strict_gt_128(collision + preimage),
        "width_can_authorize_concrete_hash": False,
    }


def cms_lifted_unit_field_term(field_order: int) -> Fraction:
    """Local CMS-policy lift of one 1/|F| source event.

    The coefficient 12 is the repository's conservative corollary from CMS
    Section 8.5.1 and Lemma 4.9.  CMS Theorem 8.6 itself is big-O and does not
    state this as an exact theorem constant.
    """

    if field_order < 2:
        raise ValueError("invalid field order")
    return Fraction(12 * QROM_QUERY_BUDGET**2, field_order)


def known_sha512_policy_terms() -> dict[str, Fraction]:
    """Exact non-null local-policy atoms used for field sensitivity.

    Transcript and MMCS call unions are deliberately excluded: the current
    source-only profile records fourteen *role types*, not a physical-call or
    oracle count.  Treating that registry size as a call cap would undercount
    the real protocol and turn an unknown term into a fabricated constant.
    """

    return {
        "cms_database_path": Fraction(48 * QROM_QUERY_BUDGET**3, 1 << CMS_RO_BITS),
    }


def max_strict_field_coefficient(field_order: int) -> int:
    """Largest integer C passing the local subset C*12*q^2/|F| + hash atoms."""

    hash_total = sum(known_sha512_policy_terms().values(), Fraction(0, 1))
    remaining = STRICT_TARGET - hash_total
    if remaining <= 0:
        return -1
    threshold = remaining * field_order / (12 * QROM_QUERY_BUDGET**2)
    # Strict inequality C < threshold.
    return (threshold.numerator - 1) // threshold.denominator


def field_record(
    field_id: str,
    base_name: str,
    modulus: int,
    degree: int,
    *,
    extension_kind: str,
    two_adic_implemented: bool,
    candidate_scope: str,
    two_adicity: int | None = None,
) -> dict[str, Any]:
    order = modulus**degree
    lifted = cms_lifted_unit_field_term(order)
    hash_terms = known_sha512_policy_terms()
    half_carrier_subset = CFW_HALF_LENGTH * lifted + sum(
        hash_terms.values(), Fraction(0, 1)
    )
    total_carrier_subset = CFW_TOTAL_CARRIER * lifted + sum(
        hash_terms.values(), Fraction(0, 1)
    )
    return {
        "base_field": base_name,
        "base_modulus_decimal": str(modulus),
        "candidate_scope": candidate_scope,
        "extension_degree": degree,
        "extension_kind": extension_kind,
        "field_id": field_id,
        "field_order_decimal": str(order),
        "field_order_floor_log2": order.bit_length() - 1,
        "local_cms_lifted_unit_1_over_field": exact_value_record(lifted),
        "local_cfw_half_length_sensitivity": exact_value_record(half_carrier_subset),
        "local_cfw_total_carrier_sensitivity": exact_value_record(total_carrier_subset),
        "local_known_sha512_policy_subset": exact_value_record(total_carrier_subset),
        "local_sensitivity_coefficient": CFW_TOTAL_CARRIER,
        "local_sensitivity_is_primary_theorem_coefficient": False,
        "max_integer_source_field_coefficient_before_strict_target": max_strict_field_coefficient(
            order
        ),
        "overall_composed_advantage": None,
        "overall_strict_gt_128": False,
        "rng_failure_advantage": None,
        "standard_uniform_distribution_implemented": True,
        "two_adicity": two_adicity,
        "two_adic_implemented": two_adic_implemented,
    }


def bcs_direct_term(proof_length_bits: int, lambda_bits: int) -> Fraction:
    """BCS Lemmas 3.4/7.5 term for lambda divisible by four.

    The theorem's ``p(x)`` is total IOP proof length in bits.  It is not a
    commitment count, oracle count, or number of field elements.
    """

    if proof_length_bits < 1 or lambda_bits < 8 or lambda_bits % 4:
        raise ValueError("BCS exact rational form needs positive proof bits and lambda divisible by four")
    exponent = lambda_bits // 4 - 2
    if exponent < 0:
        return Fraction(proof_length_bits * (1 << -exponent), 1)
    return Fraction(proof_length_bits, 1 << exponent)


def minimum_bcs_lambda_multiple_of_four(proof_length_bits: int) -> int:
    """First theorem-compatible multiple-of-four lambda passing the strict target."""

    if proof_length_bits < 1:
        raise ValueError("proof_length_bits must be positive")
    lambda_bits = 8
    while not strict_gt_128(bcs_direct_term(proof_length_bits, lambda_bits)):
        lambda_bits += 4
    return lambda_bits


def byte_align(bits: int) -> int:
    if bits < 0:
        raise ValueError("negative width")
    return ((bits + 7) // 8) * 8


def ideal_secret_prefix_term(key_bits: int, users: int = 1) -> Fraction:
    """Exact ideal-QRO screen 2*U*q/sqrt(2^k), for even k.

    The cited primary lemmas are single-key.  Multiplication by ``users`` is
    the local triangle-inequality hybrid used by the retained audit; it is not
    a published multi-user theorem and never instantiates a deployed hash.
    """

    if key_bits < 2 or key_bits % 2 or users < 1:
        raise ValueError("secret-prefix screen needs an even key width and positive users")
    return Fraction(2 * users * QROM_QUERY_BUDGET, 1 << (key_bits // 2))


def ideal_qro_collision_term(output_bits: int) -> Fraction:
    """Conservative exact use of alpha < 648 as alpha <= 648."""

    if output_bits < 1:
        raise ValueError("invalid ideal-QRO output width")
    return Fraction(648 * (QROM_QUERY_BUDGET + 1) ** 3, 1 << output_bits)


def ghcm21_prop2_reprogramming_term(
    reprogram_points: int,
    quantum_queries: int,
    conditional_min_entropy_bits: int,
    *,
    proof_instances: int = 1,
) -> Fraction:
    """Exact GHCM21 Proposition 2 bound for the retained power-of-two screen.

    Proposition 2 gives ``(3R/2)*sqrt(q*pmax)``.  This helper deliberately
    accepts only a power-of-two query count and an entropy width for which the
    square root is rational, so the ledger never rounds a security decision.
    ``proof_instances`` is the explicit sequential-hybrid multiplier; the
    selected interpretation requires ``quantum_queries`` to be the *global*
    history query cap rather than a fresh cap for every proof.
    """

    if reprogram_points < 1 or proof_instances < 1:
        raise ValueError("GHCM screen needs positive program and proof counts")
    if quantum_queries < 1 or quantum_queries & (quantum_queries - 1):
        raise ValueError("GHCM exact helper requires a power-of-two query cap")
    query_exponent = quantum_queries.bit_length() - 1
    if conditional_min_entropy_bits <= query_exponent:
        raise ValueError("GHCM Proposition 2 requires q*pmax < 1")
    root_exponent_numerator = conditional_min_entropy_bits - query_exponent
    if root_exponent_numerator % 2:
        raise ValueError("GHCM exact helper requires a rational square root")
    root_exponent = root_exponent_numerator // 2
    return Fraction(
        3 * reprogram_points * proof_instances,
        2 * (1 << root_exponent),
    )


def smallwood_direct_ghcm21_ledger() -> dict[str, Any]:
    """Conditional direct-QROM-ZK screen for SmallWood's custom transform.

    The numeric entries become relevant only after a source/refinement proof
    maps the entire SmallWood simulator to at most ``2*N+8`` GHCM programming
    instructions and proves fresh conditional entropy at every instruction.
    They establish reprogramming indistinguishability only, never soundness.
    """

    homogeneous_512_single = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
        QROM_QUERY_BUDGET,
        SMALLWOOD_CURRENT_LEAF_TAPE_BITS,
    )
    homogeneous_512_history = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
        QROM_QUERY_BUDGET,
        SMALLWOOD_CURRENT_LEAF_TAPE_BITS,
        proof_instances=SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
    )
    homogeneous_576_single = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
        QROM_QUERY_BUDGET,
        SMALLWOOD_WIDENED_LEAF_TAPE_BITS,
    )
    homogeneous_576_history = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
        QROM_QUERY_BUDGET,
        SMALLWOOD_WIDENED_LEAF_TAPE_BITS,
        proof_instances=SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
    )
    heterogeneous_leaf_history = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_LEAF_REPROGRAM_POINT_CAP,
        QROM_QUERY_BUDGET,
        SMALLWOOD_WIDENED_LEAF_TAPE_BITS,
        proof_instances=SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
    )
    heterogeneous_chain_history = ghcm21_prop2_reprogramming_term(
        SMALLWOOD_FIAT_SHAMIR_PROGRAM_POINTS,
        QROM_QUERY_BUDGET,
        SMALLWOOD_CURRENT_LEAF_TAPE_BITS,
        proof_instances=SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
    )
    heterogeneous_history = heterogeneous_leaf_history + heterogeneous_chain_history
    current_first_program_single = ghcm21_prop2_reprogramming_term(
        1,
        QROM_QUERY_BUDGET,
        SMALLWOOD_CURRENT_GLOBAL_SALT_BITS,
    )
    current_first_program_history = ghcm21_prop2_reprogramming_term(
        1,
        QROM_QUERY_BUDGET,
        SMALLWOOD_CURRENT_GLOBAL_SALT_BITS,
        proof_instances=SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
    )
    return {
        "applicability": {
            "adaptive_programming_timing_refinement": None,
            "canonical_injective_tagged_oracle_encoding": None,
            "current_global_salt_bits": SMALLWOOD_CURRENT_GLOBAL_SALT_BITS,
            "current_global_salt_has_required_entropy": False,
            "full_view_simulator_implemented": False,
            "future_program_points_retain_entropy_after_side_information": None,
            "later_chain_program_conditional_entropy_bits_required": 512,
            "later_chain_program_entropy_source_proved": None,
            "later_chain_program_entropy_requirement": (
                "each later chain program needs a fresh conditionally uniform 512-bit "
                "prior digest or an independent salt"
            ),
            "leaf_tapes_conditionally_independent_uniform": None,
            "one_global_salt_is_revealed_after_first_use": True,
            "one_global_salt_proves_later_chain_program_entropy": False,
            "output_chain_conditional_min_entropy_bits": None,
            "required_global_salt_bits": SMALLWOOD_REQUIRED_GLOBAL_SALT_BITS,
            "rng_failure_and_reuse_advantage": None,
            "whole_protocol_hybrid_reprogram_bound_proved": False,
        },
        "bound": {
            "conditional_formula": "(3*R/2)*sqrt(q_H*pmax)",
            "conditional_min_entropy_model": "pmax=2^-h",
            "current_256_bit_salt_first_program_single_proof": exact_value_record(
                current_first_program_single
            ),
            "current_256_bit_salt_first_program_u2^64_history": exact_value_record(
                current_first_program_history
            ),
            "global_quantum_query_cap": QROM_QUERY_BUDGET,
            "history_proof_instances": SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
            "history_query_interpretation": (
                "q_H is one global cap across the history; a per-proof q_H cap would require "
                "a different, larger total-query calculation"
            ),
            "heterogeneous_576_leaf_512_chain_formula": (
                "3/2^172 + 3/2^158 = 3*(1+2^-14)/2^158"
            ),
            "heterogeneous_576_leaf_512_chain_approximate_security_bits_display": (
                "156.4149494468487"
            ),
            "heterogeneous_576_leaf_512_chain_u2^64_history": exact_value_record(
                heterogeneous_history
            ),
            "heterogeneous_576_leaf_term_u2^64_history": exact_value_record(
                heterogeneous_leaf_history
            ),
            "heterogeneous_512_chain_term_u2^64_history": exact_value_record(
                heterogeneous_chain_history
            ),
            "homogeneous_512_bit_all_programs_single_proof_sensitivity_only": (
                exact_value_record(homogeneous_512_single)
            ),
            "homogeneous_512_bit_all_programs_u2^64_history_sensitivity_only": (
                exact_value_record(homogeneous_512_history)
            ),
            "homogeneous_576_bit_all_programs_single_proof_sensitivity_only": (
                exact_value_record(homogeneous_576_single)
            ),
            "homogeneous_576_bit_all_programs_u2^64_history_sensitivity_only": (
                exact_value_record(homogeneous_576_history)
            ),
            "homogeneous_576_bit_approximate_security_bits_sensitivity_only": (
                "170.4150319958445"
            ),
            "homogeneous_sensitivity_has_protocol_authority": False,
            "leaf_reprogram_point_cap": SMALLWOOD_LEAF_REPROGRAM_POINT_CAP,
            "chain_reprogram_point_cap": SMALLWOOD_FIAT_SHAMIR_PROGRAM_POINTS,
            "reprogram_point_cap": SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
            "reprogram_point_cap_formula": "2*N+8",
        },
        "cms_boundary": {
            "cms19_theorem_8_6_part3_qrom_statistical_zk": True,
            "cms19_theorem_8_6_soundness_is_for_bcs_construction": True,
            "custom_smallwood_transform_is_literal_bcs": False,
            "custom_smallwood_vector_leaf_bcs_refinement": None,
            "direct_ghcm_establishes_soundness_or_knowledge": False,
            "provisional_beta1_iop_query_count": 55,
            "provisional_beta2_iop_query_count": 48,
            "q_log_ell_augmented_query_term": None,
            "rbr_soundness_and_knowledge_for_custom_transform": None,
            "soundness_inherited_without_new_bcs_or_cms_refinement": False,
            "theorem_big_o_constants": None,
        },
        "concrete_hash_boundary": {
            "Adv_QRO-inst(SHA-512)": None,
            "Adv_QRO-inst(SHAKE256-512)": None,
            "ideal_tagged_product_qro_only": True,
        },
        "decs_domain_size": SMALLWOOD_DECS_DOMAIN_SIZE,
        "fiat_shamir_program_points": SMALLWOOD_FIAT_SHAMIR_PROGRAM_POINTS,
        "opened_leaf_count": SMALLWOOD_OPENED_LEAF_COUNT,
        "proof_size_sensitivity": {
            "global_salt_256_to_512_delta_bytes": SMALLWOOD_GLOBAL_SALT_DELTA_BYTES,
            "global_salt_delta_establishes_later_chain_entropy": False,
            "opened_tape_query_count_sensitivities": {
                str(query_count): {
                    "opened_tape_count_q_D": query_count,
                    "opened_tapes_512_to_576_delta_bytes": (
                        widened_opened_tape_delta_bytes(query_count)
                    ),
                    "plus_32_byte_global_salt_delta_bytes": (
                        widened_opened_tape_delta_bytes(query_count)
                        + SMALLWOOD_GLOBAL_SALT_DELTA_BYTES
                    ),
                }
                for query_count in SMALLWOOD_PROVISIONAL_OPENED_TAPE_COUNTS
            },
            "query_counts_are_profile_sensitivities_not_a_selected_production_profile": True,
            "prover_private_rng_delta_bytes_for_all_N_tapes": (
                SMALLWOOD_DECS_DOMAIN_SIZE
                * (SMALLWOOD_WIDENED_LEAF_TAPE_BITS - SMALLWOOD_CURRENT_LEAF_TAPE_BITS)
                // 8
            ),
            "wire_profile_and_parser_change_required": True,
        },
        "route_status": "conditional_numeric_viability_but_not_an_applicable_complete_zk_or_soundness_theorem",
        "strict_complete_zk_authority": False,
    }


def semantic_hash_roles() -> list[dict[str, Any]]:
    """All fifteen security-bearing typed roles from the retained audit.

    ``enforced_conditional_min_entropy_bits`` is intentionally null for every
    secret or unknown-source role: transport width is not an entropy proof.
    Public roles have no key and therefore also use null, rather than a fake
    zero.  The current mixed relation uses unkeyed BLAKE2b for secret-derived
    application frames; keyed BLAKE2b is only a rejected repair screen.
    """

    single_384 = ideal_secret_prefix_term(384)
    multi_448_two_inputs_epoch = ideal_secret_prefix_term(448, 2 * (1 << 32))
    specs: tuple[tuple[Any, ...], ...] = (
        (
            "semantic.note_commitment",
            "collision-binding+commitment-hiding",
            "RFC7693-BLAKE2b-448-unkeyed",
            448,
            384,
            384,
            "single-384-bit-prefix-screen",
            single_384,
        ),
        (
            "semantic.nullifier",
            "collision-binding+qPRF+key-derivation",
            "RFC7693-BLAKE2b-448-unkeyed",
            448,
            448,
            384,
            "448-bit-derived-prefix-U=2*2^32-screen",
            multi_448_two_inputs_epoch,
        ),
        (
            "semantic.merkle_node",
            "collision-binding",
            "FIPS202-SHAKE256-448",
            448,
            None,
            None,
            None,
            None,
        ),
        (
            "semantic.spend_key_xof",
            "qPRF+KDF+RO-XOF",
            "RFC7693-BLAKE2b-448-unkeyed-two-tagged-calls",
            896,
            384,
            384,
            "single-384-bit-prefix-screen",
            single_384,
        ),
        (
            "semantic.authorization_policy",
            "collision-binding+commitment-hiding",
            "RFC7693-BLAKE2b-448-unkeyed",
            448,
            448,
            None,
            "missing-independent-uniform-entropy",
            None,
        ),
        (
            "semantic.authorization_accumulator",
            "collision-binding+commitment-hiding+qPRF+KDF",
            "RFC7693-BLAKE2b-448-unkeyed-tagged-lane",
            448,
            448,
            None,
            "missing-independent-uniform-entropy",
            None,
        ),
        (
            "semantic.authorization_value_lock",
            "collision-binding+commitment-hiding+qPRF+KDF",
            "RFC7693-BLAKE2b-448-unkeyed-tagged-lane",
            448,
            448,
            None,
            "missing-independent-uniform-entropy",
            None,
        ),
        (
            "semantic.intent",
            "collision-binding",
            "FIPS202-SHAKE256-448",
            448,
            None,
            None,
            None,
            None,
        ),
        (
            "semantic.balance_tag",
            "collision-binding",
            "FIPS202-SHAKE256-448",
            448,
            None,
            None,
            None,
            None,
        ),
        (
            "semantic.ciphertext_hash",
            "collision-binding",
            "FIPS202-SHAKE256-448",
            448,
            None,
            None,
            None,
            None,
        ),
        (
            "statement.stablecoin_policy_hash",
            "robust-collision-binding",
            "RFC7693-BLAKE2b-384-live-host-constructor",
            384,
            None,
            None,
            None,
            None,
        ),
        (
            "statement.stablecoin_oracle_commitment",
            "collision-binding-or-hiding-if-source-secret",
            None,
            384,
            None,
            None,
            "source-grammar-and-secrecy-classification-missing",
            None,
        ),
        (
            "statement.stablecoin_attestation_commitment",
            "collision-binding-or-hiding-if-source-secret",
            None,
            384,
            None,
            None,
            "source-grammar-and-secrecy-classification-missing",
            None,
        ),
        (
            "proof.merkle_leaf",
            "collision-binding+commitment-hiding",
            "SHA-512-or-SHAKE256-512-candidate; pinned-ProveKit-is-256-bit",
            512,
            512,
            None,
            "direct-BCS-carrier-term-charged-separately",
            None,
        ),
        (
            "proof.opened_leaf_random_tape",
            "commitment-hiding+adaptive-selective-opening",
            "SHA-512-or-SHAKE256-512-candidate; pinned-ProveKit-witness-hiding-off",
            512,
            512,
            None,
            "complete-ZK-and-selective-opening-proof-missing",
            None,
        ),
    )
    roles = []
    for (
        role_id,
        required_property,
        primitive,
        output_bits,
        key_or_prefix_width_bits,
        source_secret_width_bits,
        screen_basis,
        screen,
    ) in specs:
        roles.append(
            {
                "deployed_hash_qrom_bridge": None,
                "enforced_conditional_min_entropy_bits": None,
                "ideal_secret_prefix_screen": (
                    exact_value_record(screen) if screen is not None else None
                ),
                "ideal_secret_prefix_screen_basis": screen_basis,
                "key_or_prefix_width_bits": key_or_prefix_width_bits,
                "output_or_transport_bits": output_bits,
                "primitive_or_status": primitive,
                "required_property": required_property,
                "role_id": role_id,
                "source_secret_width_bits": source_secret_width_bits,
            }
        )
    if len(roles) != SECURITY_BEARING_TYPED_ROLE_COUNT:
        raise AssertionError("semantic role inventory drift")
    return roles


def hash_assumption_lanes() -> dict[str, Any]:
    """Separate theorem-only concrete evidence from a hash-as-QRO assumption."""

    collision448 = ideal_qro_collision_term(448)
    collision512 = ideal_qro_collision_term(512)
    preimage448 = Fraction((2 * QROM_QUERY_BUDGET + 1) ** 2, 1 << 448)
    preimage512 = Fraction((2 * QROM_QUERY_BUDGET + 1) ** 2, 1 << 512)
    reprogram_multiplier = (2 * QROM_QUERY_BUDGET + 2) ** 2
    assumptions = {
        "Adv_QRO-inst(BLAKE2b-384)": None,
        "Adv_QRO-inst(BLAKE2b-448)": None,
        "Adv_QRO-inst(SHA-512)": None,
        "Adv_QRO-inst(SHAKE256-448)": None,
        "Adv_QRO-inst(SHAKE256-512)": None,
    }
    return {
        "A_theorem_only_concrete_deployed_hash": {
            "concrete_instantiation_advantage": None,
            "finite_exact_composed_bound": None,
            "strict_gt_128": False,
            "verdict": "unbounded_fail_closed_no_applicable_exact_deployed_hash_qrom_bridge",
        },
        "B_conventional_hash_as_qro_assumption": {
            "assumption_advantages": assumptions,
            "assumptions_are_never_zeroed": True,
            "conditional_full_advantage": None,
            "ideal_oracle_terms": {
                "collision_448_alpha648_global_q_screen": exact_value_record(collision448),
                "collision_512_alpha648_global_q_screen": exact_value_record(collision512),
                "preimage_448_amplitude_screen": exact_value_record(preimage448),
                "preimage_512_amplitude_screen": exact_value_record(preimage512),
                "measure_reprogram_n1_multiplier": str(reprogram_multiplier),
                "measure_reprogram_round_count": None,
                "measure_reprogram_challenge_denominator": None,
                "measure_reprogram_advantage": None,
                "semantic_physical_call_union": None,
                "transcript_mmcs_physical_call_union": None,
            },
            "known_term_no_go": True,
            "known_term_no_go_reasons": [
                "384-bit single-key ideal secret-prefix term is exactly 2^-127",
                "448-bit two-input epoch hybrid term is exactly 2^-126",
                "lambda512 direct BCS term is p/2^126 with p>=10,737,660,800 bits, leaving under 93 bits",
            ],
            "strict_gt_128": False,
            "zero_instantiation_advantage_counterfactual_passes": False,
        },
    }


def e320_ligerito_comparison_screen() -> dict[str, Any]:
    """Retain the exact E320 comparison-only one-level Ligerito projection.

    This is intentionally recomputed with the actual Goldilocks^5 order.  The
    wire formula belongs to the old non-ZK Ligerito source screen; it is not an
    HVZK-WHIR serializer, proof, bound, or candidate parameter selection.
    """

    p = 5
    r = 2048
    m = 4096
    q = 130
    field_order = GOLDILOCKS_MODULUS**5
    proximity = Fraction(m - r - 1, 2 * m) ** q
    algebraic = Fraction(p * (m + 2), field_order)
    source = proximity + algebraic
    total = (
        12 * QROM_QUERY_BUDGET**2 * source
        + Fraction(48 * QROM_QUERY_BUDGET**3, 1 << 512)
        + Fraction(2 * m**2, 1 << 512)
    )
    wire = {
        "authentication": 41344,
        "claimed_value": 40,
        "commitment_root": 64,
        "header": 128,
        "opened_rows": 66560,
        "statement_id": 64,
        "sumcheck": 400,
        "terminal": 81920,
    }
    wire["total"] = sum(wire.values())
    return {
        "actual_field_order_used": True,
        "conditional_total": exact_value_record(total),
        "field": "Goldilocks^5",
        "field_bytes": 40,
        "geometry": {"codeword_rows": m, "fold_variables": p, "message_rows": r, "q": q},
        "not_hvzk_whir_wire": True,
        "not_proof_bytes": True,
        "not_security_certificate": True,
        "not_zero_knowledge": True,
        "wire_projection_bytes": wire,
    }


def primary_sources() -> list[dict[str, Any]]:
    return [
        {
            "anchor": "Theorem 1 and Proposition 2",
            "exact_constants_in_primary_theorem": True,
            "id": "ghcm21-adaptive-reprogramming",
            "pdf_sha512": "4c4dea78491790b10ee049c70fd7bef6abc36015d5011243164b0a7c4aaa8134fa88e1fc1ecb6bb7de7566a5324e7d0ec8de44f9303ab4482fe525c037699f8b",
            "role": "information-theoretic adaptive QRO reprogramming with side information",
            "url": "https://eprint.iacr.org/2020/1361.pdf",
        },
        {
            "anchor": "Theorems 2, 4, 6, 8, and 10; Figure 8",
            "exact_constants_in_primary_theorem": True,
            "id": "smallwood25",
            "pdf_sha512": "cd035a0739d3c7f2f82fd4a089e3e1bb748cd16c5fa30addc16f2197e49f972be2ed97f760b3eafee480bd978030e9b339a93341a0661daca11738fdc128a8e2",
            "role": "classical-ROM whole-protocol simulator structure and eight Fiat-Shamir programs",
            "url": "https://eprint.iacr.org/2025/1085.pdf",
        },
        {
            "anchor": "Theorem 8.6; Section 8.5.1; Lemma 4.9",
            "exact_constants_in_primary_theorem": False,
            "id": "cms19",
            "role": "modified BCS adaptive-QROM lifting; theorem uses big-O",
            "url": "https://eprint.iacr.org/2019/834.pdf",
        },
        {
            "anchor": "Lemmas 3.4 and 7.5",
            "exact_constants_in_primary_theorem": True,
            "id": "bcs16",
            "role": "direct salted-Merkle statistical-ZK term p*2^(-lambda/4+2)",
            "url": "https://eprint.iacr.org/2016/116.pdf",
        },
        {
            "anchor": "Definition 3.7; Theorem 10.2; Construction 11.4",
            "exact_constants_in_primary_theorem": False,
            "id": "cfw26",
            "pdf_sha512": "be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd",
            "role": "HVZK-WHIR and printed odd-field R1CS reduction",
            "url": "https://eprint.iacr.org/2026/391.pdf",
        },
        {
            "anchor": "Section 2.8; Definition 2.7; Appendix C",
            "exact_constants_in_primary_theorem": False,
            "id": "bcfw25",
            "pdf_sha512": "0b5fceaa077ee4ff3dc3cbe1ef9d68ec67761a2778c4c7a6caf7bde8dd5b1c3eef42c9c9373303bba997726e836620b508fd470b926475c86c6736fa272d58d9",
            "role": "relaxed RBR-knowledge direction and QROM conjecture boundary",
            "url": "https://eprint.iacr.org/2025/753.pdf",
        },
        {
            "anchor": "Theorem 1.1; Theorem 1.3; Corollary 1.6; Remark 1.7",
            "exact_constants_in_primary_theorem": False,
            "id": "block23",
            "role": "special soundness to RBR soundness, not knowledge",
            "url": "https://eprint.iacr.org/2023/1256.pdf",
        },
        {
            "anchor": "Lemma 2.1",
            "exact_constants_in_primary_theorem": True,
            "id": "xy18-secret-prefix",
            "role": "single-key ideal-QRO secret-prefix bound 2*q*2^(-ell/2)",
            "url": "https://eprint.iacr.org/2018/838.pdf",
        },
        {
            "anchor": "Appendix B, Lemmas 3 and 6",
            "exact_constants_in_primary_theorem": True,
            "id": "gmp21-qro",
            "role": "single-key secret-prefix qPRF and alpha<648 ideal-QRO collision bounds",
            "url": "https://eprint.iacr.org/2021/708.pdf",
        },
        {
            "anchor": "Corollaries 13 and 15",
            "exact_constants_in_primary_theorem": True,
            "id": "dfm20",
            "role": "measure-and-reprogram coefficient; requires round and challenge parameters",
            "url": "https://eprint.iacr.org/2020/282.pdf",
        },
        {
            "anchor": "quant-ph/9705002",
            "exact_constants_in_primary_theorem": False,
            "id": "bht97",
            "role": "O(N^(1/3)) quantum collision-finding algorithm",
            "url": "https://arxiv.org/abs/quant-ph/9705002",
        },
        {
            "anchor": "quant-ph/9605043",
            "exact_constants_in_primary_theorem": False,
            "id": "grover96",
            "role": "O(sqrt(N)) unstructured quantum search",
            "url": "https://arxiv.org/abs/quant-ph/9605043",
        },
        {
            "anchor": "FIPS PUB 180-4",
            "exact_constants_in_primary_theorem": False,
            "id": "fips180-4",
            "role": "SHA-256 and SHA-512 construction specification, not a QRO reduction",
            "url": "https://doi.org/10.6028/NIST.FIPS.180-4",
        },
        {
            "anchor": "FIPS PUB 202",
            "exact_constants_in_primary_theorem": False,
            "id": "fips202",
            "role": "SHA3/SHAKE construction specification, not a QRO reduction",
            "url": "https://doi.org/10.6028/NIST.FIPS.202",
        },
        {
            "anchor": "BLAKE3 specification, hash mode and 256-bit default output",
            "exact_constants_in_primary_theorem": False,
            "id": "blake3-spec",
            "role": "BLAKE3 construction specification, not a QRO reduction",
            "url": "https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex",
        },
    ]


def required_terms() -> list[dict[str, Any]]:
    classifications = {
        "exact_transaction_relation_refinement": "relation",
        "odd_field_r1cs_compiler_refinement": "relation",
        "host_only_manifest_and_consensus_boundary": "relation",
        "r1cs_to_cic_ior": "ior",
        "ior_honest_completeness": "ior",
        "ior_output_relation_typing": "ior",
        "pcs_binding": "pcs",
        "pcs_proximity": "pcs",
        "pcs_list_decoding": "pcs",
        "pcs_zero_evader": "pcs",
        "iop_soundness": "iop",
        "rbr_soundness": "iop",
        "rbr_knowledge": "iop",
        "cms_knowledge_notion_compatibility": "fiat-shamir",
        "complete_hvzk_iop": "zero-knowledge",
        "complete_zk_noninteractive": "zero-knowledge",
        "bcs_salted_commitment_hiding": "zero-knowledge",
        "bcs_cms_fiat_shamir_qrom": "fiat-shamir",
        "cms_augmented_query_expansion": "fiat-shamir",
        "transcript_ideal_to_concrete_qrom": "hash",
        "mmcs_collision_and_second_preimage": "hash",
        "mmcs_selective_opening_hiding": "hash",
        "quantum_collision_union": "hash",
        "quantum_preimage_and_prf_union": "hash",
        "challenge_sampling_bias_and_abort": "sampling",
        "grinding_failure": "grinding",
        "prover_retry_reset_and_restart": "grinding",
        "rng_entropy_failure_and_reuse": "rng",
        "semantic_hash_role_union": "union",
        "physical_hash_call_union": "union",
        "multi_proof_union": "union",
        "authorization_mode_and_activity_mask_union": "union",
        "action_and_block_union": "union",
        "adversarial_history_and_epoch_union": "union",
        "consensus_lifetime_union": "union",
        "canonical_parser_refinement": "refinement",
        "native_verifier_refinement": "refinement",
        "formal_refinement": "refinement",
        "wallet_rpc_relay_mempool_block_sync_reorg_refinement": "refinement",
        "release_source_and_artifact_closure": "refinement",
    }
    return [
        {
            "authority": "missing",
            "category": classifications[term_id],
            "id": term_id,
            "value": None,
        }
        for term_id in REQUIRED_TERM_IDS
    ]


def build_ledger() -> dict[str, Any]:
    hash_profiles = [
        hash_profile_record("sha256", "FIPS 180-4 SHA-256", 256, provekit_selectable=True),
        hash_profile_record("keccak256", "Keccak-256", 256, provekit_selectable=True),
        hash_profile_record("blake3-256", "BLAKE3 default 32-byte output", 256, provekit_selectable=True),
        hash_profile_record("sha512", "FIPS 180-4 SHA-512", 512, provekit_selectable=False),
        hash_profile_record(
            "shake256-512", "FIPS 202 SHAKE256 with 64-byte output", 512, provekit_selectable=False
        ),
    ]

    fields = [
        field_record(
            "goldilocks-e128-binomial",
            "Goldilocks",
            GOLDILOCKS_MODULUS,
            2,
            extension_kind="BinomialExtensionField<F,2>",
            two_adic_implemented=True,
            candidate_scope="locally implemented Plonky3 binomial option",
            two_adicity=33,
        ),
        field_record(
            "goldilocks-e320-binomial",
            "Goldilocks",
            GOLDILOCKS_MODULUS,
            5,
            extension_kind="BinomialExtensionField<F,5>",
            two_adic_implemented=True,
            candidate_scope="locally implemented Plonky3 binomial option",
            two_adicity=32,
        ),
        field_record(
            "koalabear-degree8-binomial",
            "KoalaBear",
            KOALABEAR_MODULUS,
            8,
            extension_kind="BinomialExtensionField<F,8>",
            two_adic_implemented=True,
            candidate_scope="locally implemented comparison option",
        ),
        field_record(
            "babybear-degree8-binomial",
            "BabyBear",
            BABYBEAR_MODULUS,
            8,
            extension_kind="BinomialExtensionField<F,8>",
            two_adic_implemented=True,
            candidate_scope="locally implemented comparison option",
        ),
    ]

    sha512_atoms = known_sha512_policy_terms()
    bcs_lambda512_floor = bcs_direct_term(BCS_PROOF_LENGTH_BITS_FLOOR, 512)
    bcs_lambda648_floor = bcs_direct_term(BCS_PROOF_LENGTH_BITS_FLOOR, 648)
    bcs_lambda656_floor = bcs_direct_term(BCS_PROOF_LENGTH_BITS_FLOOR, 656)
    missing_values = {term_id: None for term_id in REQUIRED_TERM_IDS}
    overall = compose_required(missing_values)
    assert overall is None

    return {
        "architecture": {
            "cfw26_hvzk_whir": {
                "printed_hvzk_theorem_claim_present": True,
                "usable_complete_hvzk_theorem": False,
                "exact_hegemon_relation_profile": "blake2b448-mixed-source-only",
                "exact_security_epsilon": None,
                "plonky3_hiding_whir_pcs_present": True,
                "plonky3_r1cs_ior_present": False,
                "production_candidate": False,
                "r1cs_bridge_authority": False,
                "r1cs_bridge_blocker": (
                    "candidate embedding is source checked, but its authoritative CFW26 theorem/refinement "
                    "binding and the R1CS-to-HVZK-WHIR composition are absent"
                ),
                "selected": False,
                "whir_polynomial_num_variables": None,
            },
            "hegemon_odd_field_r1cs": {
                "activity_masks": 16,
                "authorization_modes": 5,
                "cfw26_candidate_embedding": {
                    "authoritative_theorem_binding": False,
                    "column_flattening": "v[0..ell) then w[0..ell)",
                    "ell_half_length": CFW_HALF_LENGTH,
                    "ell_log2": CFW_HALF_LOG2,
                    "equal_public_witness_halves": True,
                    "total_carrier_elements": CFW_TOTAL_CARRIER,
                    "total_carrier_log2": CFW_TOTAL_CARRIER_LOG2,
                    "whir_polynomial_num_variables": None,
                },
                "complete_transaction_relation": False,
                "compiled_host_only_predicates": 0,
                "host_only_predicates": 4,
                "proof_artifact": None,
                "source_geometry": {
                    "derived_auxiliary_variables": R1CS_DERIVED_AUXILIARY,
                    "l_public_variables": R1CS_L_PUBLIC,
                    "m_constraints": R1CS_M_CONSTRAINTS,
                    "matrix_nonzeros_total": R1CS_MATRIX_NONZEROS,
                    "n_nonconstant_variables": R1CS_N_NONCONSTANT,
                    "private_transport_variables": R1CS_PRIVATE_TRANSPORT,
                    "witness_used": R1CS_WITNESS_USED,
                    "z_vector_length_including_constant_one": R1CS_Z_WITH_CONSTANT,
                },
                "split_sha3_512_control_geometry": {
                    "cfw_ell_half_length": CFW_HALF_LENGTH,
                    "cfw_total_carrier": CFW_TOTAL_CARRIER,
                    "derived_auxiliary_variables": SPLIT_R1CS_DERIVED_AUXILIARY,
                    "l_public_variables": R1CS_L_PUBLIC,
                    "m_constraints": SPLIT_R1CS_M_CONSTRAINTS,
                    "matrix_nonzeros_total": SPLIT_R1CS_MATRIX_NONZEROS,
                    "n_nonconstant_variables": SPLIT_R1CS_N_NONCONSTANT,
                    "private_transport_variables": R1CS_PRIVATE_TRANSPORT,
                    "witness_used": SPLIT_R1CS_WITNESS_USED,
                    "z_vector_length_including_constant_one": SPLIT_R1CS_Z_WITH_CONSTANT,
                },
                "source_only_macro_program": True,
            },
            "provekit_main": {
                "hash_choices": ["skyscraper", "sha256", "keccak", "blake3", "poseidon2"],
                "main_revision": PROVEKIT_MAIN_REVISION,
                "merkle_digest_bytes": 32,
                "no_poseidon_candidate_choices": ["sha256", "keccak", "blake3"],
                "pq128_numeric_parameter_is_qrom_composition": False,
                "plonky3_whir_config_security_level_semantics": "classical_only",
                "plonky3_whir_pow_and_query_derivation_is_qrom_composition": False,
                "production_candidate": False,
                "r1cs_spartan_whir_stack_present": True,
                "selected": False,
                "sha512_or_shake256_512_option_present": False,
                "source_comment": "sumcheck ZK on; witness ZK off; non-hiding witness WHIR openings leak witness values",
                "transcript_hash_choices_are_256_bit": True,
                "witness_complete_zk": False,
                "whir_revision": PROVEKIT_WHIR_REVISION,
            },
            "selected_architecture": None,
            "winner": None,
        },
        "bcs_direct_zk": {
            "exact_total_iop_proof_length_bits_p_of_x": None,
            "minimum_cfw_prover_field_elements": CFW_PROVER_FIELD_ELEMENT_FLOOR,
            "minimum_cfw_prover_field_elements_formula": (
                "ell + 78*ell_in + 26*ell_out + 26*(ell_out+1) + 4, "
                "with rate-1 injective floors ell_in=4 and ell_out=8"
            ),
            "e320_canonical_coefficient_bits": E320_CANONICAL_COEFFICIENT_BITS,
            "e320_minimum_injective_encoding_bits": (
                GOLDILOCKS_MODULUS**5
            ).bit_length(),
            "actual_main_codeword_length": None,
            "actual_inner_codeword_length": None,
            "actual_outer_codeword_length": None,
            "actual_encoding_randomness_lengths": None,
            "proof_length_bits_floor": BCS_PROOF_LENGTH_BITS_FLOOR,
            "proof_length_bits_floor_basis": (
                "BCS p(x) is total IOP proof length in bits; Theorem11.3 communication has at least "
                "33,555,190 E320 field elements under rate-1 injective encoding floors, each canonically "
                "represented by five 64-bit coefficients; actual codeword and randomness lengths can only add"
            ),
            "lambda512_term_lower_bound_from_p_floor": exact_value_record(bcs_lambda512_floor),
            "lambda512_strict_certificate_possible": False,
            "lambda648_term_at_p_floor_only": exact_value_record(bcs_lambda648_floor),
            "lambda656_term_at_p_floor_only": exact_value_record(bcs_lambda656_floor),
            "lambda656_is_current_sha512_or_shake256_512_profile": False,
            "minimum_byte_aligned_lambda_lower_bound_from_p_floor": byte_align(
                minimum_bcs_lambda_multiple_of_four(BCS_PROOF_LENGTH_BITS_FLOOR)
            ),
            "minimum_multiple_of_four_lambda_lower_bound_from_p_floor": minimum_bcs_lambda_multiple_of_four(
                BCS_PROOF_LENGTH_BITS_FLOOR
            ),
            "required_lambda_for_exact_p": None,
            "source_expression": "p*2^(-lambda/4+2)",
            "verdict": (
                "direct BCS theorem at lambda=512 has at most about 92 bits from the E320 communication floor; "
                "lambda648 still fails and lambda656 first passes this floor only, while exact p and required lambda stay null"
            ),
        },
        "capabilities": {
            "complete_zk": False,
            "composed_strict_gt_128": False,
            "concrete_conventional_hash_qrom": False,
            "exact_full_relation": False,
            "exact_verifier_consensus_binding": False,
            "measured_qualifying_proof": False,
            "production_authorized": False,
            "retained_source_closure": False,
        },
        "cfw26_section11_theorem_geometry": {
            "encoded_oracles": {
                "inner_mask": CFW_INNER_MASK_ENCODED_ORACLES,
                "outer_mask": CFW_OUTER_MASK_ENCODED_ORACLES,
                "total": CFW_TOTAL_ENCODED_ORACLES,
                "witness": CFW_WITNESS_ENCODED_ORACLES,
            },
            "hvzk_statistical_error": {
                "coefficient": CFW_HVZK_STATISTICAL_UNION_COEFFICIENT,
                "formula": "(4*log2(ell)+5)*zeta = 105*zeta",
                "zeta": None,
                "value": None,
            },
            "log2_ell": CFW_HALF_LOG2,
            "log2_ell_plus_one": CFW_LOG_ELL_PLUS_ONE,
            "one_polynomial_pcs_is_full_relation": False,
            "printed_output_relation_defects": {
                "endpoint_state": {
                    "counterexample": "s(X)=X^2-X has s(0)=s(1)=0 but (0,1,0,...)*coeff(s)=-1",
                    "honest_completeness_inherited": False,
                    "printed_state": "st2=(0,1,0^(L_in-2))",
                    "required_typed_repair": "st2=pow(1)=(1,1,...,1)",
                },
                "main_linear_form": {
                    "printed_state_typechecks": False,
                    "required_typed_repair": "row_M(M,alpha)[b]=Mhat(alpha,b,1), with alpha in state",
                },
            },
            "rbr_middle_sumcheck_coordinate_terms": CFW_RBR_MIDDLE_COORDINATE_TERMS,
            "rbr_total_coordinate_terms": CFW_RBR_TOTAL_COORDINATE_TERMS,
            "rbr_coordinate_union_advantage": None,
            "rbr_initial_numerator_issue": {
                "paper_expression": "(L_out+1)/|F|",
                "safe_numerator_without_new_premise": "d+1=27",
                "required_missing_premise": "L_out>=d",
                "theorem_instantiated": False,
            },
            "theorem_authority": False,
        },
        "claim_boundary": (
            "Exact source and arithmetic audit only.  No architecture, field, hash, query count, "
            "proof size, QROM composition, complete-ZK NIZK, verifier refinement, or production route is selected."
        ),
        "composition": {
            "all_required_terms_present": False,
            "composed_security_bits": None,
            "missing_term_count": len(REQUIRED_TERM_IDS),
            "overall_advantage": None,
            "required_terms": required_terms(),
            "strict_gt_128": False,
        },
        "e320_decision": {
            "direct_bcs_lambda512_certificate_passes": False,
            "field_and_local_total_carrier_sha512_policy_subset_passes_strict_gt_128": True,
            "field_choice_selected": False,
            "full_composition": None,
            "full_composition_reason": (
                "actual algebraic coefficient, WHIR polynomial variable count, IOP/RBR/HVZK/FS, "
                "hash-call, grinding, RNG, union, and refinement terms are missing; the direct BCS "
                "lambda=512 term and semantic secret-prefix screens already fail strict >128"
            ),
            "local_max_integer_field_error_coefficient": max_strict_field_coefficient(
                GOLDILOCKS_MODULUS**5
            ),
            "verdict": (
                "E320 retains local arithmetic headroom even when the unit 1/|F| sensitivity is multiplied "
                "by the full 2^26 CFW carrier, but the coefficient is not theorem-authorized and the "
                "SHA-512/SHAKE256-512 direct BCS lane has under 93 bits at the communication floor"
            ),
        },
        "field_options": fields,
        "generated_at_utc": "2026-08-22",
        "hash_assumption_lanes": hash_assumption_lanes(),
        "hash_width_profiles": hash_profiles,
        "local_policy": {
            "cms_corollary_formula": "12*t^2*epsilon + 48*t^3/2^lambda + 2*a/2^lambda",
            "cms_augmented_query_budget_selected": None,
            "cms_exact_base_game_arity": None,
            "cms_local_policy_t": QROM_QUERY_BUDGET,
            "cms_theorem_8_6_exact_constants": None,
            "cms_unit_field_sensitivity": "12*t^2/|F|",
            "cfw_half_length": CFW_HALF_LENGTH,
            "cfw_section11_encoded_oracle_count": CFW_TOTAL_ENCODED_ORACLES,
            "cfw_total_carrier": CFW_TOTAL_CARRIER,
            "hash_physical_call_cap": None,
            "hash_role_type_count_is_not_a_call_count": True,
            "hash_width_collision_screen": "q^3/2^n",
            "hash_width_preimage_screen": "q^2/2^n",
            "oracle_count": None,
            "query_budget": QROM_QUERY_BUDGET,
            "security_bearing_typed_role_count": SECURITY_BEARING_TYPED_ROLE_COUNT,
            "sha512_policy_atoms": {
                key: exact_value_record(value) for key, value in sorted(sha512_atoms.items())
            },
            "strict_wire_hash_role_type_count": STRICT_WIRE_HASH_ROLE_TYPE_COUNT,
            "strict_comparison": "overall_advantage < 2^-128; equality rejects",
            "strict_target_denominator_power": STRICT_TARGET_BITS,
            "transcript_call_cap": None,
            "verbatim_primary_theorem": False,
            "whir_polynomial_num_variables": None,
        },
        "non_authoritative_comparison": {
            "e320_one_level_ligerito": e320_ligerito_comparison_screen()
        },
        "primary_sources": primary_sources(),
        "production_profile": None,
        "proof_bytes": None,
        "schema": SCHEMA,
        "semantic_hash_ledger": {
            "all_15_roles_instantiated": False,
            "all_15_roles_present": True,
            "current_mixed_relation_physical_hash_invocations": 83,
            "current_mixed_relation_physical_hash_invocations_are_security_role_count": False,
            "deployed_hash_bridges_complete": False,
            "epoch_secret_prefix_screens": {
                "single_384_bit_prefix": exact_value_record(ideal_secret_prefix_term(384)),
                "two_input_epoch_448_bit_prefix": exact_value_record(
                    ideal_secret_prefix_term(448, 2 * (1 << 32))
                ),
                "all_15_roles_epoch_448_bit_prefix": exact_value_record(
                    ideal_secret_prefix_term(448, 15 * (1 << 32))
                ),
            },
            "roles": semantic_hash_roles(),
            "strict_gt_128": False,
        },
        "smallwood_direct_ghcm21_qrom_zk": smallwood_direct_ghcm21_ledger(),
        "union_and_runtime_ledger": {
            "action_and_block_union_advantage": None,
            "activity_mask_count": 16,
            "adversarial_history_union_advantage": None,
            "authorization_mode_count": 5,
            "authorization_mode_mask_type_cross_product": 80,
            "canonical_parser_refinement_advantage": None,
            "consensus_history_cap_enforced": False,
            "consensus_lifetime_epoch_count": None,
            "consensus_lifetime_union_advantage": None,
            "formal_refinement_advantage": None,
            "max_actions_per_block": None,
            "max_proofs_per_block_source_policy": 10_000,
            "multi_proof_union_advantage": None,
            "native_verifier_refinement_advantage": None,
            "security_epoch_max_proofs_source_policy": 1 << 32,
            "wallet_rpc_relay_mempool_block_sync_reorg_advantage": None,
        },
        "wire_sampling_grinding_rng_ledger": {
            "challenge_sampling_bias_and_abort": None,
            "grinding_difficulty_bits": None,
            "grinding_failure": None,
            "max_mmcs_leaves_source_wire_cap": 1 << 20,
            "max_rejection_draws_source_wire_cap": 16,
            "physical_hash_call_cap": None,
            "prover_retry_reset_restart": None,
            "rng_entropy_failure_and_reuse": None,
            "source_wire_caps_are_selected_security_profile": False,
        },
        "whir_parameterization": {
            "capacity_bound": {
                "authoritative": False,
                "status": "conjectural_size_screen_only",
            },
            "johnson_bound_local_implementation": {
                "authoritative": False,
                "arithmetic": "f64",
                "omitted_terms": "additive_and_subdominant_terms",
                "retained_term": "BCSS25-Theorem-1.5-dominant-term-only",
            },
            "johnson_bound_full_exact_rational_instantiation": None,
            "selected_profile": None,
            "unique_decoding_exact_rational_instantiation": None,
            "verdict": (
                "no WHIR parameter profile is authorized until UniqueDecoding and a full exact-rational "
                "Johnson theorem instantiation are compared with every theorem term retained"
            ),
        },
        "source_binding": {
            "local_hegemon_sha512": dict(LOCAL_SOURCE_PINS),
            "local_plonky3_revision": PLONKY3_REVISION,
            "local_plonky3_sha512": dict(PLONKY3_SOURCE_PINS),
            "provekit_main_revision": PROVEKIT_MAIN_REVISION,
            "provekit_v1_branch_revision_observed": PROVEKIT_V1_BRANCH_REVISION,
            "provekit_v1_tag_commit": PROVEKIT_V1_TAG_COMMIT,
            "provekit_v1_tag_object": PROVEKIT_V1_TAG_OBJECT,
            "provekit_whir_revision": PROVEKIT_WHIR_REVISION,
            "remote_bytes_rechecked_by_checker": False,
            "remote_primary_source_pins": list(REMOTE_SOURCE_PINS),
            "retained_source_closure": False,
            "spongefish_revision": SPONGEFISH_REVISION,
        },
        "status": STATUS,
    }


def validate_source_pins(ledger: Mapping[str, Any]) -> None:
    binding = ledger["source_binding"]
    if binding["local_hegemon_sha512"] != dict(LOCAL_SOURCE_PINS):
        raise AssertionError("local Hegemon source pin manifest drift")
    for relative, expected in LOCAL_SOURCE_PINS.items():
        path = REPO / relative
        if not path.is_file():
            raise AssertionError(f"missing pinned Hegemon source: {relative}")
        if sha512_file(path) != expected:
            raise AssertionError(f"pinned Hegemon source drift: {relative}")

    certificate = json.loads(
        (REPO / ".agent/hardening/hvzk-whir-odd-field-r1cs/certificate.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = json.loads(
        (REPO / ".agent/hardening/hvzk-whir-odd-field-r1cs/relation_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    geometry = certificate["profile_geometry"]["blake2b448-mixed"]
    expected_geometry = {
        "auxiliary_variables_total": R1CS_WITNESS_USED,
        "derived_auxiliary_variables": R1CS_DERIVED_AUXILIARY,
        "l_public_variables": R1CS_L_PUBLIC,
        "m_constraints": R1CS_M_CONSTRAINTS,
        "matrix_nonzeros_total": R1CS_MATRIX_NONZEROS,
        "n_nonconstant_variables": R1CS_N_NONCONSTANT,
        "private_transport_variables": R1CS_PRIVATE_TRANSPORT,
        "z_vector_length_including_constant_one": R1CS_Z_WITH_CONSTANT,
    }
    if geometry != expected_geometry:
        raise AssertionError("pinned mixed R1CS geometry drift")
    split_geometry = certificate["profile_geometry"]["sha3-512-split-control"]
    expected_split_geometry = {
        "auxiliary_variables_total": SPLIT_R1CS_WITNESS_USED,
        "derived_auxiliary_variables": SPLIT_R1CS_DERIVED_AUXILIARY,
        "l_public_variables": R1CS_L_PUBLIC,
        "m_constraints": SPLIT_R1CS_M_CONSTRAINTS,
        "matrix_nonzeros_total": SPLIT_R1CS_MATRIX_NONZEROS,
        "n_nonconstant_variables": SPLIT_R1CS_N_NONCONSTANT,
        "private_transport_variables": R1CS_PRIVATE_TRANSPORT,
        "z_vector_length_including_constant_one": SPLIT_R1CS_Z_WITH_CONSTANT,
    }
    if split_geometry != expected_split_geometry:
        raise AssertionError("pinned split R1CS control geometry drift")
    profile = manifest["hash_profiles"]["blake2b448-mixed"]
    if profile["geometry"] != expected_geometry:
        raise AssertionError("manifest/certificate mixed geometry mismatch")
    embedding = profile["cfw26_section11_candidate_embedding"]
    if (
        embedding["ell"] != CFW_HALF_LENGTH
        or embedding["n0"] != CFW_HALF_LENGTH
        or embedding["embedded_geometry"]["columns_including_v_constant"]
        != CFW_TOTAL_CARRIER
        or embedding["authoritative_cfw26_theorem_binding"] is not False
    ):
        raise AssertionError("CFW26 equal-half candidate embedding drift")
    if len(profile["calls"]) != 83:
        raise AssertionError("mixed semantic hash invocation schedule drift")
    split_profile = manifest["hash_profiles"]["sha3-512-split-control"]
    if split_profile["geometry"] != expected_split_geometry:
        raise AssertionError("manifest/certificate split geometry mismatch")
    split_embedding = split_profile["cfw26_section11_candidate_embedding"]
    if (
        split_embedding["ell"] != CFW_HALF_LENGTH
        or split_embedding["embedded_geometry"]["columns_including_v_constant"]
        != CFW_TOTAL_CARRIER
        or split_embedding["authoritative_cfw26_theorem_binding"] is not False
    ):
        raise AssertionError("split CFW26 candidate embedding drift")
    if len(manifest["host_only_boundary"]["groups"]) != 4:
        raise AssertionError("host-only production boundary drift")
    if any(manifest["authority"].values()):
        raise AssertionError("source-only relation authority unexpectedly promoted")
    cfw_certificate = json.loads(
        (REPO / ".agent/hardening/hvzk-whir-r1cs-ior/certificate.json").read_text(
            encoding="utf-8"
        )
    )
    projection = cfw_certificate["reported_hegemon_section11_projection"]
    if (
        projection["ell"] != CFW_HALF_LENGTH
        or projection["carrier_matrix_side"] != CFW_TOTAL_CARRIER
        or projection["section11_sumcheck_variables"] != CFW_LOG_ELL_PLUS_ONE
        or projection["section11_hvzk_oracle_hybrid_count"]
        != CFW_HVZK_STATISTICAL_UNION_COEFFICIENT
    ):
        raise AssertionError("pinned CFW26 Section11 projection drift")
    if cfw_certificate["decision"]["theorem_authority"] is not False:
        raise AssertionError("diagnostic CFW26 IOR cannot acquire theorem authority")

    qrom_profile = json.loads(
        (REPO / ".agent/hardening/smallwood-v6-qrom-composition/profile.json").read_text(
            encoding="utf-8"
        )
    )
    budgets = qrom_profile["budgets"]
    if (
        budgets["max_proofs_per_block"] != 10_000
        or budgets["security_epoch_max_proofs"] != 1 << 32
        or budgets["history_cap_consensus_enforced"] is not False
    ):
        raise AssertionError("retained multi-proof/history policy source drift")
    wire_profile = json.loads(
        (REPO / ".agent/hardening/hvzk-whir-strict-wire-profile/profile.json").read_text(
            encoding="utf-8"
        )
    )
    if (
        wire_profile["limits"]["max_mmcs_leaves"] != 1 << 20
        or wire_profile["limits"]["max_rejection_draws"] != 16
        or wire_profile["production_authorized"] is not False
    ):
        raise AssertionError("retained wire/sampling source cap drift")

    if binding["local_plonky3_sha512"] != dict(PLONKY3_SOURCE_PINS):
        raise AssertionError("Plonky3 pin manifest drift")
    if not PLONKY3_ROOT.is_dir():
        raise AssertionError("pinned local Plonky3 snapshot is absent")
    for relative, expected in PLONKY3_SOURCE_PINS.items():
        path = PLONKY3_ROOT / relative
        if not path.is_file() or sha512_file(path) != expected:
            raise AssertionError(f"pinned Plonky3 source drift: {relative}")
    gold_extension = (PLONKY3_ROOT / "goldilocks/src/extension.rs").read_text(
        encoding="utf-8"
    )
    for required in (
        "impl BinomiallyExtendable<2> for Goldilocks",
        "impl HasTwoAdicBinomialExtension<2> for Goldilocks",
        "impl BinomiallyExtendable<5> for Goldilocks",
        "impl HasTwoAdicBinomialExtension<5> for Goldilocks",
        "const EXT_TWO_ADICITY: usize = 33",
        "const EXT_TWO_ADICITY: usize = 32",
    ):
        if required not in gold_extension:
            raise AssertionError(f"pinned Goldilocks extension fact absent: {required}")
    generic_extension = (PLONKY3_ROOT / "field/src/extension/mod.rs").read_text(
        encoding="utf-8"
    )
    if "rand::distr::StandardUniform" not in generic_extension:
        raise AssertionError("generic extension StandardUniform implementation drift")
    binomial_extension = (
        PLONKY3_ROOT / "field/src/extension/binomial_extension.rs"
    ).read_text(encoding="utf-8")
    if "const NUM_BYTES: usize = F::NUM_BYTES * D" not in binomial_extension:
        raise AssertionError("binomial extension raw serialization width drift")
    head = subprocess.run(
        ["git", "-C", str(PLONKY3_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != PLONKY3_REVISION:
        raise AssertionError("local Plonky3 revision drift")

    if binding["remote_primary_source_pins"] != list(REMOTE_SOURCE_PINS):
        raise AssertionError("remote source pin manifest drift")
    if binding["remote_bytes_rechecked_by_checker"] is not False:
        raise AssertionError("offline checker must not claim remote revalidation")
    for item in REMOTE_SOURCE_PINS:
        if len(item["revision"]) != 40 or len(item["sha512"]) != 128:
            raise AssertionError("malformed immutable remote source pin")


def validate_ledger(ledger: Mapping[str, Any]) -> None:
    if ledger.get("schema") != SCHEMA or ledger.get("status") != STATUS:
        raise AssertionError("ledger identity drift")
    if ledger != build_ledger():
        raise AssertionError("canonical ledger content drift")

    composition = ledger["composition"]
    terms = composition["required_terms"]
    if [term["id"] for term in terms] != list(REQUIRED_TERM_IDS):
        raise AssertionError("required composition term order drift")
    if any(term["value"] is not None for term in terms):
        raise AssertionError("missing terms must remain null, never zero")
    if composition["overall_advantage"] is not None:
        raise AssertionError("incomplete overall advantage must remain null")
    if composition["strict_gt_128"] is not False:
        raise AssertionError("incomplete composition cannot pass")

    profiles = {item["profile_id"]: item for item in ledger["hash_width_profiles"]}
    for profile_id in ("sha256", "keccak256", "blake3-256"):
        if profiles[profile_id]["strict_width_screen"] is not False:
            raise AssertionError(f"256-bit collision width must fail: {profile_id}")
        width = profiles[profile_id]["source_width_screen"]
        if width["optimistic_preimage_unit_policy"]["strictly_below_2^-128"] is not False:
            raise AssertionError("256-bit preimage equality must fail strict policy")
        if width["physical_call_union"] is not None:
            raise AssertionError("unknown physical call unions must remain null")
    for profile_id in ("sha512", "shake256-512"):
        if profiles[profile_id]["strict_width_screen"] is not True:
            raise AssertionError(f"512-bit local width screen drift: {profile_id}")
        if profiles[profile_id]["concrete_qrom_bridge"] is not None:
            raise AssertionError("width screen must not become a concrete QROM bridge")

    fields = {item["field_id"]: item for item in ledger["field_options"]}
    if fields["goldilocks-e320-binomial"]["local_cfw_total_carrier_sensitivity"][
        "strictly_below_2^-128"
    ] is not True:
        raise AssertionError("E320 local total-carrier field subset should retain headroom")
    for field_id in (
        "goldilocks-e128-binomial",
        "koalabear-degree8-binomial",
        "babybear-degree8-binomial",
    ):
        if fields[field_id]["local_cms_lifted_unit_1_over_field"][
            "strictly_below_2^-128"
        ] is not False:
            raise AssertionError(f"small field local CMS unit screen must fail: {field_id}")
    if ledger["e320_decision"]["full_composition"] is not None:
        raise AssertionError("E320 full composition must remain null")
    bcs = ledger["bcs_direct_zk"]
    if bcs["minimum_cfw_prover_field_elements"] != 33_555_190:
        raise AssertionError("CFW Theorem11.3 communication floor drift")
    if bcs["proof_length_bits_floor"] != 10_737_660_800:
        raise AssertionError("E320 serialized proof-bit floor drift")
    if bcs["e320_minimum_injective_encoding_bits"] != 320:
        raise AssertionError("E320 injective encoding width drift")
    if from_factored(
        bcs["lambda512_term_lower_bound_from_p_floor"]["exact_fraction"]
    ) != Fraction(BCS_PROOF_LENGTH_BITS_FLOOR, 1 << 126):
        raise AssertionError("direct BCS lambda512 communication floor drift")
    if bcs["lambda512_strict_certificate_possible"]:
        raise AssertionError("direct BCS lambda512 term cannot certify strict >128")
    if bcs["minimum_multiple_of_four_lambda_lower_bound_from_p_floor"] != 656:
        raise AssertionError("minimum strict BCS lambda floor must be 656")
    if bcs["minimum_byte_aligned_lambda_lower_bound_from_p_floor"] != 656:
        raise AssertionError("minimum byte-aligned BCS lambda floor must be 656")
    if bcs["lambda648_term_at_p_floor_only"]["strictly_below_2^-128"] is not False:
        raise AssertionError("lambda648 must fail at the proof-length floor")
    if bcs["lambda656_term_at_p_floor_only"]["strictly_below_2^-128"] is not True:
        raise AssertionError("lambda656 should pass the floor-only BCS term")
    if (
        bcs["exact_total_iop_proof_length_bits_p_of_x"] is not None
        or bcs["required_lambda_for_exact_p"] is not None
    ):
        raise AssertionError("exact BCS p and its required lambda must remain null")
    for key in (
        "actual_main_codeword_length",
        "actual_inner_codeword_length",
        "actual_outer_codeword_length",
        "actual_encoding_randomness_lengths",
    ):
        if bcs[key] is not None:
            raise AssertionError(f"unselected code parameter must remain null: {key}")

    relation = ledger["architecture"]["hegemon_odd_field_r1cs"]
    if relation["source_geometry"]["witness_used"] != R1CS_WITNESS_USED:
        raise AssertionError("R1CS witness geometry drift")
    embedding = relation["cfw26_candidate_embedding"]
    if (
        embedding["ell_half_length"] != CFW_HALF_LENGTH
        or embedding["total_carrier_elements"] != CFW_TOTAL_CARRIER
        or embedding["whir_polynomial_num_variables"] is not None
    ):
        raise AssertionError("CFW/WHIR dimensional distinction drift")

    semantic = ledger["semantic_hash_ledger"]
    if len(semantic["roles"]) != SECURITY_BEARING_TYPED_ROLE_COUNT:
        raise AssertionError("fifteen-role semantic ledger drift")
    role_ids = [role["role_id"] for role in semantic["roles"]]
    if len(set(role_ids)) != SECURITY_BEARING_TYPED_ROLE_COUNT:
        raise AssertionError("semantic role IDs must be unique")
    screens = semantic["epoch_secret_prefix_screens"]
    if from_factored(screens["single_384_bit_prefix"]["exact_fraction"]) != Fraction(
        1, 1 << 127
    ):
        raise AssertionError("384-bit secret-prefix screen drift")
    if from_factored(
        screens["two_input_epoch_448_bit_prefix"]["exact_fraction"]
    ) != Fraction(1, 1 << 126):
        raise AssertionError("448-bit multi-user secret-prefix screen drift")
    if any(role["deployed_hash_qrom_bridge"] is not None for role in semantic["roles"]):
        raise AssertionError("missing concrete hash bridges must remain null")

    lanes = ledger["hash_assumption_lanes"]
    if lanes["A_theorem_only_concrete_deployed_hash"]["finite_exact_composed_bound"] is not None:
        raise AssertionError("theorem-only concrete lane must remain unbounded")
    assumed = lanes["B_conventional_hash_as_qro_assumption"]
    if any(value is not None for value in assumed["assumption_advantages"].values()):
        raise AssertionError("hash-as-QRO instantiation advantages must remain explicit nulls")
    if assumed["zero_instantiation_advantage_counterfactual_passes"] is not False:
        raise AssertionError("known conditional terms independently disqualify the candidate")

    ghcm = ledger["smallwood_direct_ghcm21_qrom_zk"]
    ghcm_bound = ghcm["bound"]
    if ghcm_bound["reprogram_point_cap"] != 2 * (1 << 20) + 8:
        raise AssertionError("SmallWood GHCM reprogram cap drift")
    expected_homogeneous_512_single = Fraction(
        3 * SMALLWOOD_GHCM_REPROGRAM_POINT_CAP,
        2 * (1 << 224),
    )
    expected_homogeneous_512_history = (
        expected_homogeneous_512_single * SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN
    )
    expected_homogeneous_576_history = Fraction(
        3
        * SMALLWOOD_GHCM_REPROGRAM_POINT_CAP
        * SMALLWOOD_CONSENSUS_PROOF_HISTORY_SCREEN,
        2 * (1 << 256),
    )
    expected_heterogeneous_leaf_history = Fraction(3, 1 << 172)
    expected_heterogeneous_chain_history = Fraction(3, 1 << 158)
    expected_heterogeneous_history = (
        expected_heterogeneous_leaf_history + expected_heterogeneous_chain_history
    )
    if from_factored(
        ghcm_bound[
            "homogeneous_512_bit_all_programs_single_proof_sensitivity_only"
        ]["exact_fraction"]
    ) != expected_homogeneous_512_single:
        raise AssertionError("SmallWood GHCM 512-bit single-proof bound drift")
    if from_factored(
        ghcm_bound[
            "homogeneous_512_bit_all_programs_u2^64_history_sensitivity_only"
        ]["exact_fraction"]
    ) != expected_homogeneous_512_history:
        raise AssertionError("SmallWood GHCM 512-bit history bound drift")
    if ghcm_bound[
        "homogeneous_512_bit_all_programs_u2^64_history_sensitivity_only"
    ]["integer_security_bits_display"] != 138:
        raise AssertionError("SmallWood GHCM corrected 512-bit history display must be 138")
    if from_factored(
        ghcm_bound[
            "homogeneous_576_bit_all_programs_u2^64_history_sensitivity_only"
        ]["exact_fraction"]
    ) != expected_homogeneous_576_history:
        raise AssertionError("SmallWood GHCM 576-bit history bound drift")
    if ghcm_bound[
        "homogeneous_576_bit_all_programs_u2^64_history_sensitivity_only"
    ]["integer_security_bits_display"] != 170:
        raise AssertionError("homogeneous 576-bit sensitivity display must be 170")
    if ghcm_bound["homogeneous_sensitivity_has_protocol_authority"] is not False:
        raise AssertionError("homogeneous sensitivity cannot gain protocol authority")
    if from_factored(
        ghcm_bound["heterogeneous_576_leaf_term_u2^64_history"]["exact_fraction"]
    ) != expected_heterogeneous_leaf_history:
        raise AssertionError("heterogeneous 576-bit leaf term drift")
    if from_factored(
        ghcm_bound["heterogeneous_512_chain_term_u2^64_history"]["exact_fraction"]
    ) != expected_heterogeneous_chain_history:
        raise AssertionError("heterogeneous 512-bit chain term drift")
    heterogeneous_record = ghcm_bound[
        "heterogeneous_576_leaf_512_chain_u2^64_history"
    ]
    if from_factored(heterogeneous_record["exact_fraction"]) != expected_heterogeneous_history:
        raise AssertionError("heterogeneous GHCM sum drift")
    if heterogeneous_record["integer_security_bits_display"] != 156:
        raise AssertionError("heterogeneous GHCM history display must be 156")
    if (
        ghcm_bound[
            "heterogeneous_576_leaf_512_chain_approximate_security_bits_display"
        ]
        != "156.4149494468487"
    ):
        raise AssertionError("heterogeneous GHCM decimal display drift")
    if ghcm_bound["current_256_bit_salt_first_program_single_proof"][
        "strictly_below_2^-128"
    ] is not False:
        raise AssertionError("current 32-byte salt cannot support the first GHCM program")
    if ghcm["applicability"]["whole_protocol_hybrid_reprogram_bound_proved"] is not False:
        raise AssertionError("unproved whole-protocol GHCM hybrid cannot gain authority")
    if ghcm["applicability"]["one_global_salt_is_revealed_after_first_use"] is not True:
        raise AssertionError("global salt disclosure timing must remain explicit")
    if ghcm["applicability"]["one_global_salt_proves_later_chain_program_entropy"] is not False:
        raise AssertionError("one disclosed salt cannot prove later chain entropy")
    if ghcm["applicability"]["later_chain_program_entropy_source_proved"] is not None:
        raise AssertionError("missing later-chain entropy proof must remain null")
    if ghcm["cms_boundary"]["soundness_inherited_without_new_bcs_or_cms_refinement"] is not False:
        raise AssertionError("GHCM ZK reprogramming cannot silently establish CMS soundness")
    if any(
        value is not None for value in ghcm["concrete_hash_boundary"].values()
        if value is not True
    ):
        raise AssertionError("concrete hash QRO instantiation terms must remain null")
    sensitivity = ghcm["proof_size_sensitivity"]
    if sensitivity["global_salt_256_to_512_delta_bytes"] != 32:
        raise AssertionError("64-byte global salt repair must add exactly 32 bytes")
    expected_deltas = {23: (184, 216), 48: (384, 416), 55: (440, 472)}
    for query_count, (tape_delta, combined_delta) in expected_deltas.items():
        row = sensitivity["opened_tape_query_count_sensitivities"][str(query_count)]
        if row["opened_tapes_512_to_576_delta_bytes"] != tape_delta:
            raise AssertionError(f"q_D={query_count} widened-tape delta drift")
        if row["plus_32_byte_global_salt_delta_bytes"] != combined_delta:
            raise AssertionError(f"q_D={query_count} tape-plus-salt delta drift")
    if sensitivity["global_salt_delta_establishes_later_chain_entropy"] is not False:
        raise AssertionError("salt wire delta cannot silently prove later chain entropy")

    policy = ledger["local_policy"]
    for key in (
        "cms_augmented_query_budget_selected",
        "hash_physical_call_cap",
        "oracle_count",
        "transcript_call_cap",
        "whir_polynomial_num_variables",
    ):
        if policy[key] is not None:
            raise AssertionError(f"unknown profile quantity must remain null: {key}")

    section11 = ledger["cfw26_section11_theorem_geometry"]
    if section11["encoded_oracles"] != {
        "inner_mask": 78,
        "outer_mask": 26,
        "total": 105,
        "witness": 1,
    }:
        raise AssertionError("Section11 encoded-oracle count drift")
    if section11["hvzk_statistical_error"]["coefficient"] != 105:
        raise AssertionError("Section11 HVZK union coefficient drift")
    if section11["hvzk_statistical_error"]["value"] is not None:
        raise AssertionError("missing zeta must keep the HVZK term null")
    if section11["rbr_middle_sumcheck_coordinate_terms"] != 26:
        raise AssertionError("Section11 repeated RBR coordinate count drift")
    if section11["rbr_total_coordinate_terms"] != 29:
        raise AssertionError("Section11 full RBR coordinate count drift")
    if section11["one_polynomial_pcs_is_full_relation"] is not False:
        raise AssertionError("one-polynomial PCS screen cannot stand for the full relation")
    defects = section11["printed_output_relation_defects"]
    if defects["endpoint_state"]["honest_completeness_inherited"] is not False:
        raise AssertionError("printed endpoint state cannot inherit honest completeness")
    if defects["main_linear_form"]["printed_state_typechecks"] is not False:
        raise AssertionError("printed matrix state cannot silently typecheck")

    whir = ledger["whir_parameterization"]
    if whir["selected_profile"] is not None:
        raise AssertionError("approximate or conjectural WHIR profile cannot be selected")
    if whir["capacity_bound"]["authoritative"] is not False:
        raise AssertionError("CapacityBound must remain conjectural")
    if whir["johnson_bound_local_implementation"]["authoritative"] is not False:
        raise AssertionError("f64 dominant-term Johnson screen cannot authorize security")

    unions = ledger["union_and_runtime_ledger"]
    for key, value in unions.items():
        if key.endswith("_advantage") and value is not None:
            raise AssertionError(f"uninstantiated runtime union must remain null: {key}")
    if unions["consensus_history_cap_enforced"] is not False:
        raise AssertionError("source policy history cap is not consensus authority")
    runtime = ledger["wire_sampling_grinding_rng_ledger"]
    for key in (
        "challenge_sampling_bias_and_abort",
        "grinding_difficulty_bits",
        "grinding_failure",
        "physical_hash_call_cap",
        "prover_retry_reset_restart",
        "rng_entropy_failure_and_reuse",
    ):
        if runtime[key] is not None:
            raise AssertionError(f"uninstantiated runtime security value must remain null: {key}")

    architecture = ledger["architecture"]
    if architecture["selected_architecture"] is not None or architecture["winner"] is not None:
        raise AssertionError("architecture tournament winner must remain null")
    if architecture["provekit_main"]["witness_complete_zk"] is not False:
        raise AssertionError("pinned ProveKit main explicitly has witness ZK off")
    if architecture["cfw26_hvzk_whir"]["r1cs_bridge_authority"] is not False:
        raise AssertionError("ambiguous CFW26 Section 11 bridge cannot carry authority")
    if architecture["cfw26_hvzk_whir"]["usable_complete_hvzk_theorem"] is not False:
        raise AssertionError("printed Section11 defects prevent inherited complete HVZK authority")
    if any(ledger["capabilities"].values()):
        raise AssertionError("all production capabilities must remain false")
    validate_source_pins(ledger)


def run_check() -> None:
    raw = LEDGER_PATH.read_text(encoding="utf-8")
    ledger = json.loads(raw)
    if raw != canonical_json(ledger):
        raise AssertionError("ledger.json is not canonical JSON")
    validate_ledger(ledger)


def write_ledger() -> None:
    LEDGER_PATH.write_text(canonical_json(build_ledger()), encoding="utf-8")


def report() -> None:
    ledger = build_ledger()
    print("architecture_winner=null")
    print("provekit_complete_zk=false")
    print("provekit_256_bit_hashes_strict_width=false")
    print("cfw_half_length=33554432")
    print("cfw_total_carrier=67108864")
    print("whir_polynomial_num_variables=null")
    print("e320_local_total_carrier_field_subset_strict_gt_128=true")
    print("semantic_384_single_key_screen_bits=127_fail")
    print("semantic_448_two_input_epoch_screen_bits=126_fail")
    print("cfw_prover_field_element_floor=33555190")
    print("bcs_total_iop_proof_bits_floor_e320=10737660800")
    print("lambda512_direct_bcs_security_bits_upper_bound=92_fail")
    print("lambda648_floor_term_strict_gt_128=false")
    print("lambda656_floor_term_strict_gt_128=true")
    print("exact_total_iop_proof_length_bits=null")
    print("lambda512_direct_bcs_strict_gt_128=false")
    print("theorem_only_concrete_hash_advantage=null")
    print("hash_as_qro_instantiation_advantages=null")
    print("smallwood_ghcm_reprogram_cap=2097160")
    print("smallwood_ghcm_heterogeneous_history_security_bits_display=156")
    print("smallwood_ghcm_homogeneous_576_sensitivity_bits_display=170")
    print("smallwood_ghcm_homogeneous_sensitivity_authority=false")
    print("smallwood_current_256_salt_first_program_strict_gt_128=false")
    print("smallwood_later_chain_entropy_source=null")
    print("smallwood_cms_soundness_inherited=false")
    print("overall_composed_advantage=null")
    print("production_authorized=false")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if not (args.check or args.report or args.write):
        parser.error("choose --check, --report, and/or --write")
    if args.write:
        write_ledger()
        print("STRICT_ODD_FIELD_COMPOSITION_LEDGER_WRITTEN")
    if args.check:
        run_check()
        print("STRICT_ODD_FIELD_COMPOSITION_CHECK_PASS")
    if args.report:
        report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
