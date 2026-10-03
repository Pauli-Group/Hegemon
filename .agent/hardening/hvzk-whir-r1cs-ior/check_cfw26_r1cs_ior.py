#!/usr/bin/env python3
"""Fail-closed checker for the retained CFW26 Section 11 diagnostic."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import io
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SOURCE_PATH = HERE / "cfw26_r1cs_ior.py"
TEST_PATH = HERE / "test_cfw26_r1cs_ior.py"
CERTIFICATE_PATH = HERE / "certificate.json"
MANIFEST_PATH = HERE / "source-manifest.json"
MUTATION_PATH = HERE / "mutation-ledger.json"

EXPECTED_SCHEMA = "hegemon.cfw26-section11-r1cs-ior.certificate.v1"
EXPECTED_MANIFEST_SCHEMA = "hegemon.cfw26-section11-r1cs-ior.sources.v1"
EXPECTED_MUTATION_SCHEMA = "hegemon.cfw26-section11-r1cs-ior.mutations.v1"
EXPECTED_UNIT_TESTS = 27
EXPECTED_MUTATIONS = 56
EXPECTED_PDF_SHA256 = "6a2092b7bc50e5ea68ec8e679c4b830f2fe260c961dc08ee7582b7e652a46f7c"
EXPECTED_PDF_SHA512 = (
    "be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87"
    "c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd"
)
EXPECTED_BINDING = (
    "f83dbba3f17e8f174d8b04057f2823e921d5ef9e195ce3c4b718be98dec5a8f7"
    "cb27b1c7d3f9d712a45c18a21ddd20d67cb66cdfacb2a42c92762dde27575d01"
)
EXPECTED_INSTANCE_DIGEST = (
    "35ae2228a125a8ae112b00362f037455b269e7f67b4e225792df0fa1c7e90ad1"
    "84a66d1405b1eab264fa83ba21dcf04da698edf58310643c65324f5b3678b659"
)
EXPECTED_PROFILE_DIGEST = (
    "a656fdaa13fd9754f10c31727bf7108553a9cc65ba181fcf24c911d85a8b7251"
    "d658fd0236b574865bbe0428b32a58f221cdb98f918c9af154968493b668c5a7"
)
EXPECTED_BRANCH_WIRES = {
    "construction_literal_coefficient_1": {
        "factor": 1,
        "joint_mu": "1e1995fe60591aa1",
        "transcript_bytes": 6837,
        "transcript_sha512": (
            "eddd6b491e0e3e193a63c01b60d403ca3dfa1fd21b8c0e6c3041970f248826b8"
            "1e1db893d4052f346219a5d8e8afd47fa6a2e4ff2433cdc3891492ed79002b50"
        ),
    },
    "proof_sketch_coefficient_2": {
        "factor": 2,
        "joint_mu": "9eb066d48f7f753b",
        "transcript_bytes": 6829,
        "transcript_sha512": (
            "fd5dfd4cade58eae46845b1664ae746a87c90d54795e47d1d8ccdff4befde6dc"
            "eca9feba06203fd724c6adf01538dda7b49b313f7b6c86c58d40bcbeec1a5805"
        ),
    },
}
EXPECTED_DIMENSIONS = {
    "boolean_index_width": 3,
    "direct_prover_field_elements": 31,
    "ell": 4,
    "hvzk_encoding_hybrid_count": 13,
    "inner_block_length": 10,
    "inner_message_length": 4,
    "inner_oracle_count": 9,
    "inner_oracle_field_elements": 90,
    "inner_randomness_length": 1,
    "main_block_length": 10,
    "main_message_length": 4,
    "main_oracle_field_elements": 10,
    "main_randomness_length": 1,
    "n0": 4,
    "oracle_prover_field_elements": 154,
    "other_direct_field_elements": 4,
    "outer_block_length": 18,
    "outer_evaluation_field_elements": 3,
    "outer_message_length": 8,
    "outer_oracle_count": 3,
    "outer_oracle_field_elements": 54,
    "outer_randomness_length": 1,
    "query_bound_per_oracle": 1,
    "r1cs_constraint_count": 8,
    "r1cs_matrix_side": 8,
    "r1cs_variable_count": 8,
    "sumcheck_polynomial_field_elements": 24,
    "sumcheck_variables": 3,
    "total_prover_field_elements": 185,
    "verifier_field_elements": 8,
}
EXPECTED_HEGEMON_SECTION11_PROJECTION = {
    "authoritative_carrier": False,
    "candidate_embedded_matrix_nonzeros": 123_057_296,
    "carrier_matrix_side": 67_108_864,
    "carrier_nonconstant_variables": 67_108_863,
    "ell": 33_554_432,
    "matrix_embedding_constructed": False,
    "n0": 33_554_432,
    "parser_padding_binding_proved": False,
    "public_zero_padding_elements": 33_544_279,
    "remaining_zero_rows": 32_398_608,
    "section11_hvzk_oracle_hybrid_count": 105,
    "section11_main_message_elements": 33_554_432,
    "section11_sumcheck_variables": 26,
    "semantic_refinement_proved": False,
    "source_constraints": 20_457_227,
    "source_matrix_nonzeros": 94_551_238,
    "source_nonconstant_variables": 19_311_555,
    "source_public_variables": 10_152,
    "source_witness_variables": 19_301_403,
    "witness_zero_padding_elements_and_rows": 14_253_029,
    "whir_codeword_elements_defined": False,
}
EXPECTED_PAPER_ANCHOR_LOCATIONS = {
    "RS_QUERY_ZK": "printed page 29, Proposition 3.19",
    "NONADAPTIVE_DISTINGUISHERS": "printed page 34, Definition 4.7",
    "SUCCINCT_LINEAR_FORM_TYPES": "printed page 35, Definitions 5.1, 5.2, and 5.4",
    "TARGET_OUTPUT_RELATION": "printed pages 35-36, Definition 5.8",
    "R1CS_IOR_THEOREM": "printed pages 66-67, Theorem 11.3",
    "LITERAL_MASK_FACTOR": "printed page 67, Construction 11.4 Steps 1-3",
    "OUTER_MASK_SUMCHECK": "printed pages 67-69, Construction 11.4 Steps 4-7",
    "COEFFICIENT_CONTRADICTION": "printed page 69, Construction 11.4 Step 8",
    "OUTPUT_STATE_TYPE": "printed pages 69-70, Construction 11.4 Steps 9-10",
    "HVZK_VALUE_CLAIM": "printed pages 70-71, proof sketch of Theorem 11.3",
}
EXPECTED_PAPER_ANCHOR_OBSERVATIONS = {
    "RS_QUERY_ZK": "RS polynomial dimension is message length plus t random coefficients; error is zero for at most t queries",
    "NONADAPTIVE_DISTINGUISHERS": "the query-bounded distinguishers used by the theorem are non-adaptive",
    "SUCCINCT_LINEAR_FORM_TYPES": "a succinct form returns a t-by-n matrix, identity takes that matrix as state, and scalar multiplication is a distinct form",
    "TARGET_OUTPUT_RELATION": "the main and mask messages are constrained by their typed succinct linear-form matrices and targets",
    "R1CS_IOR_THEOREM": "ell equals n0, ell is a power of two, the IOR is queryless, and HVZK has explicit odd-characteristic and code premises",
    "LITERAL_MASK_FACTOR": "inner masks vanish at zero and one and Step 3 adds one copy of each inner-mask sum",
    "OUTER_MASK_SUMCHECK": "outer masks define the affine sumcheck messages, final non-Boolean challenge, and outer evaluation targets",
    "COEFFICIENT_CONTRADICTION": "the first displayed equality contains one mask sum and the immediately following equality contains two",
    "OUTPUT_STATE_TYPE": "Step 9 pairs inner sl_id with a pair-valued state and main sl_id with an entire matrix instead of the required one-by-ell alpha-fixed row; Step 10 exports those unresolved claims",
    "HVZK_VALUE_CLAIM": "the simulator samples the affine space and the value claim relies on coefficient two and odd characteristic; the hybrid count is 4 log ell plus 5",
}
REQUIRED_FALSE_CAPABILITIES = {
    "adaptive_query_simulator",
    "bounded_consensus_parser",
    "complete_zk",
    "exact_padding_parser_refinement",
    "full_hegemon_section11_carrier",
    "paper_hvzk_reduction_instantiated",
    "paper_output_relation_unambiguous",
    "pcs_commitment_opening_simulator",
    "plonky3_section11_carrier",
    "production_authorized",
    "public_sampler_distributional_proof",
    "rbr_bound_instantiated",
    "strict_pq128",
    "unequal_geometry_native_paper_carrier",
    "whole_fiat_shamir_view_simulator",
}
REQUIRED_TRUE_CAPABILITIES = {
    "both_mask_coefficient_branches_executable",
    "canonical_json_transcript_parser",
    "derived_branch_output_relation_diagnostic",
    "deterministic_honest_transcript",
    "direct_sumcheck_verifier",
    "public_only_affine_view_simulator",
    "section11_padding_arithmetic_diagnostic",
    "typed_succinct_linear_form_diagnostic",
}
EXPECTED_MANIFEST_FILES = {
    "README.md",
    "cfw26_r1cs_ior.py",
    "check_cfw26_r1cs_ior.py",
    "mutation-ledger.json",
    "test_cfw26_r1cs_ior.py",
}


class CheckFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def canonical_pretty_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_canonical_json(path: Path) -> Any:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CheckFailure(f"invalid JSON: {path.name}") from exc
    require(canonical_pretty_json(value) == raw, f"non-canonical pretty JSON: {path.name}")
    return value


def sha512_file(path: Path) -> str:
    return hashlib.sha512(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CheckFailure(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def flatten_test_ids(suite: unittest.TestSuite) -> set[str]:
    result: set[str] = set()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.update(flatten_test_ids(item))
        else:
            parts = item.id().split(".")
            require(len(parts) >= 2, "malformed unittest id")
            result.add(".".join(parts[-2:]))
    return result


def check_manifest(certificate: dict[str, Any]) -> None:
    manifest = load_canonical_json(MANIFEST_PATH)
    require(manifest.get("schema") == EXPECTED_MANIFEST_SCHEMA, "source manifest schema drift")
    require(manifest.get("hash_algorithm") == "SHA-512", "source manifest hash algorithm drift")
    files = manifest.get("files")
    require(isinstance(files, list), "source manifest files are not a list")
    seen: set[str] = set()
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha512"}, "bad source entry")
        relative = entry["path"]
        require(isinstance(relative, str), "non-string manifest path")
        path = Path(relative)
        require(not path.is_absolute() and ".." not in path.parts, "unsafe source manifest path")
        require(relative not in seen, "duplicate source manifest path")
        seen.add(relative)
        require(sha512_file(HERE / relative) == entry["sha512"], f"source hash drift: {relative}")
    require(seen == EXPECTED_MANIFEST_FILES, "source manifest file set drift")
    require(
        sha512_file(MANIFEST_PATH) == certificate.get("source_manifest_sha512"),
        "certificate source-manifest hash drift",
    )


def check_mutation_ledger(test_ids: set[str], certificate: dict[str, Any]) -> None:
    ledger = load_canonical_json(MUTATION_PATH)
    require(ledger.get("schema") == EXPECTED_MUTATION_SCHEMA, "mutation schema drift")
    cases = ledger.get("cases")
    require(isinstance(cases, list) and len(cases) == EXPECTED_MUTATIONS, "mutation count drift")
    ids: set[str] = set()
    for case in cases:
        require(
            isinstance(case, dict)
            and set(case) == {"expected", "id", "mutation", "surface", "test"},
            "mutation entry shape drift",
        )
        require(case["expected"] in {"reject", "direct_accept_output_reject"}, "bad mutation outcome")
        require(isinstance(case["id"], str) and case["id"] not in ids, "duplicate mutation id")
        ids.add(case["id"])
        require(case["test"] in test_ids, f"mutation has no retained test: {case['id']}")
        require(bool(case["mutation"]) and bool(case["surface"]), "empty mutation description")
    claimed = certificate.get("mutations")
    require(
        claimed
        == {
            "case_count": EXPECTED_MUTATIONS,
            "ledger_sha512": sha512_file(MUTATION_PATH),
            "negative_outcomes_fail_closed": True,
        },
        "certificate mutation ledger drift",
    )


def check_reference(cfw: Any, certificate: dict[str, Any]) -> None:
    require(cfw.MASK_FACTORS == {name: data["factor"] for name, data in EXPECTED_BRANCH_WIRES.items()}, "branch factors drift")
    binding = cfw.sha512_frame(b"test-only-unbound-compiler", b"fixture").hex()
    require(binding == EXPECTED_BINDING, "fixture compiler binding drift")
    instance, witness = cfw.toy_instance(binding)
    profile = cfw.ReferenceProfile()
    require(instance.digest == EXPECTED_INSTANCE_DIGEST, "fixture instance digest drift")
    require(profile.digest == EXPECTED_PROFILE_DIGEST, "fixture profile digest drift")
    require(cfw.exact_dimensions(instance, profile) == EXPECTED_DIMENSIONS, "exact dimensions drift")
    require(
        certificate.get("fixture")
        == {
            "compiler_binding_digest": binding,
            "dimensions": EXPECTED_DIMENSIONS,
            "field_modulus": cfw.GOLDILOCKS_MODULUS,
            "instance_digest": instance.digest,
            "profile_digest": profile.digest,
            "seed_hex": b"cfw26-reference-fixture".hex(),
            "unit_test_count": EXPECTED_UNIT_TESTS,
        },
        "certificate fixture drift",
    )
    projection = cfw.section11_padding_projection(cfw.REPORTED_HEGEMON_MIXED_SOURCE_GEOMETRY)
    require(projection == EXPECTED_HEGEMON_SECTION11_PROJECTION, "Hegemon Section 11 projection drift")
    require(
        certificate.get("reported_hegemon_section11_projection")
        == EXPECTED_HEGEMON_SECTION11_PROJECTION,
        "certificate Hegemon Section 11 projection drift",
    )

    observed_wires: dict[str, dict[str, Any]] = {}
    for convention, expected in EXPECTED_BRANCH_WIRES.items():
        first = cfw.honest_prove(
            instance,
            witness,
            profile,
            seed=b"cfw26-reference-fixture",
            convention=convention,
        )
        second = cfw.honest_prove(
            instance,
            witness,
            profile,
            seed=b"cfw26-reference-fixture",
            convention=convention,
        )
        require(first == second, f"nondeterministic branch: {convention}")
        encoded = first.transcript.to_bytes()
        cfw.verify_direct(instance, profile, first.transcript)
        cfw.verify_derived_output_relation(instance, profile, first.transcript, first.output_witness)
        typed = tuple(
            cfw.typed_joint_output_claim(
                instance,
                profile,
                first.transcript,
                first.output_witness,
                repair=repair,
            )
            for repair in cfw.TYPED_OUTPUT_REPAIRS
        )
        require(typed == (first.transcript.joint_mu,) * 2, f"typed repair drift: {convention}")
        observed = {
            "factor": cfw.MASK_FACTORS[convention],
            "joint_mu": cfw.fe_hex(first.transcript.joint_mu),
            "transcript_bytes": len(encoded),
            "transcript_sha512": hashlib.sha512(encoded).hexdigest(),
        }
        require(observed == expected, f"retained branch wire drift: {convention}")
        observed_wires[convention] = observed
        other = next(name for name in EXPECTED_BRANCH_WIRES if name != convention)
        try:
            cfw.verify_derived_output_relation(
                instance,
                profile,
                replace(first.transcript, convention=other),
                first.output_witness,
            )
        except cfw.ReferenceError:
            pass
        else:
            raise CheckFailure(f"branch retag accepted: {convention} -> {other}")
    require(certificate.get("branches") == observed_wires, "certificate branch wire drift")

    try:
        cfw.evaluate_paper_printed_inner_state((1, 2, 3, 4), 9, 11)
    except cfw.SuccinctLinearFormTypeError:
        pass
    else:
        raise CheckFailure("printed Step 9 identity state unexpectedly type-checks")
    try:
        cfw.evaluate_paper_printed_main_state(instance, witness)
    except cfw.SuccinctLinearFormTypeError:
        pass
    else:
        raise CheckFailure("printed Step 9 main matrix state unexpectedly type-checks")
    try:
        cfw.verify_paper_literal_output_relation(instance, profile, first.transcript, first.output_witness)
    except cfw.PaperAmbiguityError:
        pass
    else:
        raise CheckFailure("paper-literal output relation unexpectedly authorized")

    capabilities = cfw.source_capabilities()
    require(set(capabilities) == REQUIRED_FALSE_CAPABILITIES | REQUIRED_TRUE_CAPABILITIES, "capability key drift")
    require(all(not capabilities[name] for name in REQUIRED_FALSE_CAPABILITIES), "false capability became true")
    require(all(capabilities[name] for name in REQUIRED_TRUE_CAPABILITIES), "diagnostic capability became false")
    require(certificate.get("authority") == capabilities, "certificate capability drift")
    require("witness" not in inspect.signature(cfw.simulate_public_view).parameters, "public sampler gained witness input")


def run_tests() -> set[str]:
    tests = load_module("cfw26_r1cs_ior_tests_for_checker", TEST_PATH)
    suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
    test_ids = flatten_test_ids(suite)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    require(result.testsRun == EXPECTED_UNIT_TESTS, "unit-test count drift")
    require(result.wasSuccessful(), "unit tests failed:\n" + stream.getvalue())
    return test_ids


def main() -> int:
    certificate = load_canonical_json(CERTIFICATE_PATH)
    require(
        set(certificate)
        == {
            "authority",
            "branches",
            "decision",
            "fixture",
            "mutations",
            "paper",
            "reported_hegemon_section11_projection",
            "schema",
            "simulator",
            "source_manifest_sha512",
            "typed_output",
        },
        "certificate top-level shape drift",
    )
    require(certificate.get("schema") == EXPECTED_SCHEMA, "certificate schema drift")
    decision = certificate.get("decision")
    require(
        decision
        == {
            "candidate_eligible": False,
            "production_authorized": False,
            "status": "BRANCH_RELATIVE_DIAGNOSTIC_ONLY",
            "theorem_authority": False,
        },
        "certificate decision drift",
    )
    paper = certificate.get("paper", {})
    require(paper.get("pdf_sha256") == EXPECTED_PDF_SHA256, "paper SHA-256 drift")
    require(paper.get("pdf_sha512") == EXPECTED_PDF_SHA512, "paper SHA-512 drift")
    require(paper.get("coefficient_branch_selected") is False, "paper branch selection overclaim")
    require(paper.get("printed_step9_state_typechecks") is False, "paper Step 9 type overclaim")
    require(paper.get("public_erratum_identified") is False, "unexpected erratum authority")
    require(paper.get("reviewed_on") == "2026-08-22", "paper review date drift")
    require(paper.get("title") == "Zero-Knowledge IOPPs for Constrained Interleaved Codes", "paper title drift")
    require(paper.get("url") == "https://eprint.iacr.org/2026/391", "paper URL drift")
    require(
        set(paper)
        == {
            "anchors",
            "coefficient_branch_selected",
            "pdf_sha256",
            "pdf_sha512",
            "printed_step9_state_typechecks",
            "public_erratum_identified",
            "reviewed_on",
            "title",
            "url",
        },
        "paper certificate shape drift",
    )
    anchors = paper.get("anchors")
    require(isinstance(anchors, list) and len(anchors) == 10, "paper anchor ledger drift")
    observed_anchor_locations: dict[str, str] = {}
    observed_anchor_observations: dict[str, str] = {}
    for anchor in anchors:
        require(
            isinstance(anchor, dict) and set(anchor) == {"id", "location", "observation"},
            "paper anchor shape drift",
        )
        require(anchor["id"] not in observed_anchor_locations, "duplicate paper anchor id")
        require(isinstance(anchor["observation"], str) and bool(anchor["observation"]), "empty paper observation")
        observed_anchor_locations[anchor["id"]] = anchor["location"]
        observed_anchor_observations[anchor["id"]] = anchor["observation"]
    require(observed_anchor_locations == EXPECTED_PAPER_ANCHOR_LOCATIONS, "paper anchor location drift")
    require(observed_anchor_observations == EXPECTED_PAPER_ANCHOR_OBSERVATIONS, "paper anchor observation drift")
    require(
        certificate.get("simulator")
        == {
            "adaptive_queries": False,
            "affine_public_sampler": True,
            "distributional_proof": False,
            "fixed_nonadaptive_query_plan": True,
            "pcs_commitment_opening_simulator": False,
            "whole_fiat_shamir_view_simulator": False,
        },
        "simulator boundary drift",
    )
    require(
        certificate.get("typed_output")
        == {
            "paper_printed_state_errors": [
                "inner identity receives a pair instead of a t-by-n matrix",
                "main identity receives an entire square matrix instead of a one-by-ell alpha-fixed witness-column row",
            ],
            "repairs": ["identity_premultiplied_state", "scaled_identity_form"],
            "repairs_agree_for_both_diagnostic_branches": True,
            "theorem_authority": False,
        },
        "typed output boundary drift",
    )
    check_manifest(certificate)
    cfw = load_module("cfw26_r1cs_ior_for_checker", SOURCE_PATH)
    check_reference(cfw, certificate)
    test_ids = run_tests()
    check_mutation_ledger(test_ids, certificate)
    print("CFW26_R1CS_IOR_RETAINED_CERTIFICATE_PASS")
    print(f"unit_tests={EXPECTED_UNIT_TESTS}")
    print(f"mutations={EXPECTED_MUTATIONS}")
    print("paper_output_relation_unambiguous=false")
    print("distributional_or_pcs_whole_view_simulator=false")
    print("complete_zk=false")
    print("strict_pq128=false")
    print("production_authorized=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailure as exc:
        print(f"CFW26_R1CS_IOR_RETAINED_CERTIFICATE_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
