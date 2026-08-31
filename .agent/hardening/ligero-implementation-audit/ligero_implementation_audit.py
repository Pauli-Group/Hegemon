#!/usr/bin/env python3
"""Generate the canonical, fail-closed Ligero implementation audit ledger.

This is a source audit, not a prover, verifier, benchmark, or security
calculator.  It deliberately emits no proof-byte or composed-security claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
LEDGER_PATH = HERE / "ledger.json"
LIBIOP_ROOT = Path(
    "/private/tmp/aurora-libiop-audit-a2ed/"
    "libiop-a2ed2ec2f3e85f29b6035951553b02cb737c817a"
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


PRIMARY_SOURCES = [
    {
        "id": "ligero_2022_1608",
        "title": "Ligero: Lightweight Sublinear Arguments Without a Trusted Setup",
        "official_version": "20221118:030830",
        "url": "https://eprint.iacr.org/2022/1608.pdf",
        "archive_url": "https://eprint.iacr.org/archive/2022/1608/20221118:030830/",
        "local_path": "/private/tmp/ligero-2022-1608.pdf",
        "sha512": "04ddcdfc4f95ba68c3149e0d8efab8f3818eb8b5966b15f3f3917a21ff7d22e91c06bd2bad9406c5bc169091b437eb8005aa5cd63b98f297d6cb6de36428d054",
        "anchors": [
            "Section 4.7 and Figure 4",
            "Lemma 4.15",
            "Theorem 4.7",
            "Sections 5.2 and 5.3",
            "Appendix C",
        ],
    },
    {
        "id": "cms_2019_834",
        "title": "Succinct Arguments in the Quantum Random Oracle Model",
        "url": "https://eprint.iacr.org/2019/834.pdf",
        "local_path": "/private/tmp/cms19-834.pdf",
        "sha512": "1fc3a6cfce5c1ab2e9e0352581f6725c48ee1b52fa6773d456614d4137cb541443010c127a9fbdfd642ebf5249c05503c4ff531f2995e2918ad1190df334367f",
        "anchors": ["Section 8.2", "Remark 8.2", "Theorem 8.6"],
    },
    {
        "id": "bcs_2016_116",
        "title": "Interactive Oracle Proofs",
        "url": "https://eprint.iacr.org/2016/116.pdf",
        "local_path": "/private/tmp/bcs-2016-116.pdf",
        "sha512": "66557007b59ec3ce3657b22b6b4c5047ef60762b2e6b7d0c2baff16ad5d4dfa77b2f3aa5e8f068f8d260ae9919cf862a23ff685ff0c82356d207ebac3c3f6914",
        "anchors": ["Theorem 7.1", "Lemma 7.5"],
    },
]


def source(path: str, lines: int, sha512: str, role: str, anchors: list[str]) -> dict[str, Any]:
    return {
        "path": path,
        "lines": lines,
        "sha512": sha512,
        "role": role,
        "anchors": anchors,
    }


LIBIOP_SOURCE_MAP = [
    source(
        "README.md",
        180,
        "7e05d78416ebc1996916c2e9a6cd813bf2c5c1ffb6aa8a73e8b0b407fe6df60db9abc1f994c7ee5b27d600ba24f84be144fa4f4767fab89fa33eae39dbdce6eb",
        "upstream protocol and production boundary",
        ["11", "15-17", "22-32", "85-92"],
    ),
    source(
        "LICENSE",
        19,
        "05c7b8c925af9cc8a58c056f9cb2b9eeccd85146786396c798842448475a4019a9ff82168e9126ff466a0e8b76b929a2b8452833b90ae6b938589b680033ba44",
        "MIT license text",
        ["1-19"],
    ),
    source(
        ".gitmodules",
        18,
        "92dbce83240b111e9c443a125ff02156c23ea90093e8ed1c4b6ebd62f3f5a3bbfeb84881dac6d42977edcbe2b5c7add1daef6bc9257b2e117c5777759997938a",
        "vendored dependency closure",
        ["1-18"],
    ),
    source(
        "CMakeLists.txt",
        163,
        "b2a7be1a105422f54375b99b269f2673a3c8750bda2523938ba03dffd8fd46d254549a70750ddc2bd1649256dfb7809dc64b6dee837ba008cb84d31c00678049",
        "C++14 and Boost build surface",
        ["1-9", "134-147", "160-163"],
    ),
    source(
        "depends/CMakeLists.txt",
        21,
        "120fe5b753d7683613bc1faadba17b0f89b88def4b32b747f269db2a02ec55a18dacc90c2c15770be624c6c77b7a5c9972038c3f61112c3f9718093a1102f0b8",
        "unconditional ate-pairing/xbyak/libff/libfqfft build surface",
        ["1-21"],
    ),
    source(
        "libiop/CMakeLists.txt",
        402,
        "b7fe28580e6b602a4fded369c8595206761b3088297d1b7337d93fa937d1092f14328a61a6a9025f8a92008496e0155207531daf982e67d258322d4abea29166",
        "libsodium/libff linkage and test targets",
        ["1-34", "38-57", "345-385"],
    ),
    source(
        "libiop/protocols/ligero_iop.hpp",
        109,
        "f6e44e8b370d19e72aac0b9fec347ad4008604b435ff30c4e7fcadccf5d71bbdd4dc013390df1119cd01b3dbcecfc4a2b148be678205689128c26d860378444c",
        "top-level R1CS Ligero IOP declarations",
        ["1-109"],
    ),
    source(
        "libiop/protocols/ligero_iop.tcc",
        398,
        "ac771bc29cd3dde224bce6823017450b883f138e103f3ed4ea7a7c35474d42f34eeb231e62ca0d15ab02681005a4e27a29be30b0a7f36a011a812c143d40d3d0",
        "four-error parameterization and LDT composition",
        ["30-71", "303-335", "359-385"],
    ),
    source(
        "libiop/protocols/encoded/ligero/ligero.hpp",
        130,
        "97c72f28507a4f66286a6dd4586374e08b16c3398ec2ff981ccf255c03b5314e3bae76a2a36a1cb832c247223f0ab61044179aa9af2ee23b168c633255f7115c",
        "AHIV17/Aurora R1CS adapter declaration",
        ["1-10", "35-130"],
    ),
    source(
        "libiop/protocols/encoded/ligero/ligero.tcc",
        483,
        "6811a2e9b690ab99634369fcd0052e781155f4ccd392f5783e731092232eb290da5dfb36e8fa831316f2d9856611f8711c446902219d165412e8e6aa6010367b",
        "R1CS witness/Az/Bz/Cz oracles and ZK masks",
        ["35-58", "218-333", "336-383"],
    ),
    source(
        "libiop/protocols/encoded/ligero/interleaved_lincheck_ot.hpp",
        112,
        "dd9eaa61b010dff659f2f9b71c0f2dcf65e79e6f1a41f5387ae72218c8328b4a4b39699a2519ae665e5ee374e768f1070c6380b23d4157592a814574472bc273",
        "interleaved lincheck declarations",
        ["1-112"],
    ),
    source(
        "libiop/protocols/encoded/ligero/interleaved_lincheck_ot.tcc",
        698,
        "a19ca18b19498c84a810055f79e25836403852c5bb310605853a51f8a66d44c727db13c45686ba12efab9fbed473ecdb65bde4ed3e7ae7f58e136f7e2a9f63d6",
        "interleaved lincheck implementation",
        ["1-698"],
    ),
    source(
        "libiop/protocols/encoded/ligero/interleaved_rowcheck.hpp",
        99,
        "464380089f9717322b65e7830eda7a4d87931166457e482522ed8ad6b5a7a6d7d3f3b7c95f56e580d9a80096dfba7baa95db0725be47ffda3bd96527623eadc1",
        "interleaved rowcheck declarations",
        ["1-99"],
    ),
    source(
        "libiop/protocols/encoded/ligero/interleaved_rowcheck.tcc",
        297,
        "f0cec1bdd98a1e1fbb8c0b4b054942c3b049dfc540272f0b2436f3e5d04ede3aacfff62d37794f52fdd307a4340df1eef2a7f81addd03d8cfd653b9ca82ea09d",
        "interleaved rowcheck implementation",
        ["1-297"],
    ),
    source(
        "libiop/protocols/ldt/ldt_reducer.hpp",
        121,
        "fadb978b89f6e82fe2f727206d17a2fca2e015c03aab48097342b622bd1565b95056729054095fc2938b8b385c61d57d9863b3f1619149dd37f6678edb7e708b",
        "LDT reducer declarations",
        ["1-121"],
    ),
    source(
        "libiop/protocols/ldt/ldt_reducer.tcc",
        288,
        "c8d2969c2c971c565a2d3c57ac7151975aa376af7d786a216199534de3e3ce1519973569b7879c9e3213c5ce8b01a7eabdf3af0bb4b7d03889e2b26d775b8eeb",
        "LDT reducer implementation",
        ["1-288"],
    ),
    source(
        "libiop/protocols/ldt/direct_ldt/direct_ldt.hpp",
        91,
        "2dbeecd05689c39b669feeabaaf20796dac32189462ff7d919487ab98c4702a04b55b1ad9900b82d4121b2d0ada50f9cd2a0a306ffbd63f6925a2541165db7b3",
        "direct LDT declarations",
        ["1-91"],
    ),
    source(
        "libiop/protocols/ldt/direct_ldt/direct_ldt.tcc",
        158,
        "bd463762ba9ef51ab1ea3f08abebc10ed90f5e240ec4baf6d2d389e58c48f7072a2cea8adfb00e5d594bff0cc52994629ea924ddc72f283277bef03602b2e6d1",
        "direct LDT implementation",
        ["1-158"],
    ),
    source(
        "libiop/snark/ligero_snark.hpp",
        59,
        "5c41cef6a820e7478be7f43feec54bd067428d504e77cb0a5c5044af74f679197f4b831c2248205230f48e6219eb6c0d58c513c56a6b9622757a7e74523d2432",
        "in-memory SNARK API declarations",
        ["1-59"],
    ),
    source(
        "libiop/snark/ligero_snark.tcc",
        113,
        "9bbbcc42e2cac79387cded23e23b8aeb6aecc6e440736a1f669875211124d7bab526d04c7954ec2132cca4dd1bd47ca506dd2fa9bb60d50696dd8a50f334d318",
        "in-memory prover/verifier composition",
        ["40-71", "75-110"],
    ),
    source(
        "libiop/bcs/bcs_common.hpp",
        192,
        "3c179cb6fd4673caadcfde55b4dda5b2b52b097181967df9d05b8ee85d7ac30a4b61c8b1cee8912d80f7512065a441ef73c56075c4dd297c3da1c13471230a12",
        "transcript object and statement-binding TODO",
        ["37-106", "128-165"],
    ),
    source(
        "libiop/bcs/bcs_common.tcc",
        829,
        "8f4af4f53d75783e3b3535dd093f2037d00223df27feebd29a41c329f98a55d9aa3d4305dc4a8f37fc71a6a5148f66843b60c0e6e5fad7702aa2726cfb6c2e02",
        "reported-size formula, incomplete serializer, custom hash chain and PoW",
        ["12-73", "93-205", "262-390", "400-431", "551-612"],
    ),
    source(
        "libiop/bcs/bcs_prover.tcc",
        261,
        "74e344c3f09c3f9e93f2e9644a0697dfc80661492f3ef6dadf531d8dfdb49105e9227d87c7f1e75d1329717572383f29383375ce30eefb04af9c89996fb60d3a",
        "in-memory BCS transcript construction",
        ["150-236"],
    ),
    source(
        "libiop/bcs/bcs_verifier.tcc",
        226,
        "efcab5d6d8cd8306e1ff191050dded69509c10275ddb55db708b52b8fe6abf832606520e0f428aefb6f8586ac847878a9c8b467228bc634e48bdccb00ef8fea8",
        "unbounded in-memory transcript verifier",
        ["35-105", "109-150"],
    ),
    source(
        "libiop/bcs/merkle_tree.hpp",
        128,
        "7f43bf12ab9b199d69a6b39d9127915d1ae5f7ce355b1bf16f73cfc467684a959a6a20bf203a6352a21563f4e51eb9f9c33c2eb8de682c696192310f3b12cd9e",
        "Merkle proof object and reported-size formula",
        ["23-42", "45-122"],
    ),
    source(
        "libiop/bcs/merkle_tree.tcc",
        542,
        "02791aa46f1feead816f4a7859bf4968c188b4d9a785cccb2b0c8d15dbf8f34d8a188727c05db3d139fa27519f9b9d02dfcf17f19472d8a992d979f916dc5746",
        "libsodium salts and unchecked proof iterators",
        ["37-71", "338-482"],
    ),
    source(
        "libiop/bcs/hashing/blake2b.hpp",
        86,
        "42c8bbdbbeb2b6afb8a1a9b8fd925fc5b29aa1fc642ac096d53ee040b681f5208a89165f30869df4a7728ad12aa5d1408a8755a9f1d4c0e88fc8100897cef03b",
        "BLAKE2b interfaces",
        ["1-86"],
    ),
    source(
        "libiop/bcs/hashing/blake2b.tcc",
        259,
        "44da54a60d5c3888485abd2e07c16dce21f01415decb29098487e108eabdd610ba924c15293c0b48c88bcd3ce6e17cde83f2849896fa23771cc4f2956a846382",
        "BLAKE2b hash chain and native-memory field/index framing",
        ["11-18", "51-73", "138-180", "232-249"],
    ),
    source(
        "libiop/bcs/hashing/blake2b.cpp",
        76,
        "ea3376fd20931e586291dea878d422156d4571cf84348b2c4c35038eb47e77aefa77f6db72b06a142a411f40bea315eb421de36f2c1e16082156e39ab2aaea03",
        "native-size query sampler",
        ["9-25", "28-48", "50-73"],
    ),
    source(
        "libiop/bcs/hashing/hash_enum.hpp",
        45,
        "ffea14e478a5bbfd5e2fe0902d7c5bd798e4b34eefdbc33d542c54814b1b172e6ded2cf375e889c0d8093dcdcc15e42803fd1ab7b486be7d03b175be170c4c6c",
        "BLAKE2b/Poseidon selection surface",
        ["11-28"],
    ),
    source(
        "libiop/bcs/hashing/hash_enum.tcc",
        167,
        "2a1e913b201ec30402efa7876bc5f2761f184437f71cef1aa5c7a7e0a75ae68fd1f98cb424350dde7c1a50012986e2a1bf9d53dec61e124c1978747ea5b8f4a6",
        "hash backend dispatch",
        ["1-167"],
    ),
    source(
        "libiop/tests/snark/test_ligero_snark.cpp",
        88,
        "5381278d940f8524dc73d61aaf2dd492581337a61fe564d05f1dbabd0f114f1f6e0de4e83d638d18a45c6e07afd1d2d928d73dc3fe579be1e4eee7f4b5a51a64",
        "tiny in-memory GF64 and alt_bn128 Ligero tests",
        ["14-49", "52-85"],
    ),
    source(
        "libiop/tests/snark/test_serialization.cpp",
        97,
        "4e0cc5fea06933033d6217e1230982d0be7d10e74642fe6eb91e82dad3cd8524c27ff5bcc76de8c18436cca625ed1b68c41edb5183138d48d6f30ec2f7d83ce7",
        "non-ZK alt_bn128/Poseidon-only serializer test",
        ["24-36", "38-95"],
    ),
]


CRITICAL_BLOCKERS = [
    "protocol_revision_mismatch",
    "hardcoded_three_wise_zk_masks",
    "whole_iop_rbr_missing",
    "cms_modified_bcs_chain_missing",
    "statement_and_context_not_transcript_bound",
    "binary_or_conventional_hash_serializer_unimplemented",
    "reported_size_is_not_wire_bytes",
    "canonical_bounded_parser_missing",
    "sha512_shake_framing_missing",
    "native_memory_hash_inputs",
    "custom_pow_uncomposed",
    "forbidden_dependency_closure",
    "exact_relation_not_frozen",
    "rust_prover_verifier_missing",
    "qrom_concrete_composition_missing",
    "retained_proof_artifact_missing",
    "native_and_formal_refinement_missing",
]


def build_ledger() -> dict[str, Any]:
    selected_loci = sum(
        item["lines"]
        for item in LIBIOP_SOURCE_MAP
        if item["path"].startswith("libiop/")
        and item["path"] != "libiop/CMakeLists.txt"
    )
    return {
        "schema": "hegemon-ligero-implementation-audit-v1",
        "frozen_at": "2026-08-22",
        "claim_boundary": {
            "kind": "read_only_source_audit",
            "build_run": False,
            "clone_run": False,
            "proof_generated": False,
            "proof_measured": False,
            "security_instantiated": False,
            "production_code_changed": False,
            "summary": "Frozen negative implementation-readiness verdict; paper theorems, source behavior, and implementation work are kept distinct.",
        },
        "primary_protocol": {
            "id": "ligero-2022-1608-20221118-section-4.7",
            "source_id": "ligero_2022_1608",
            "exact_construction": "Section 4.7 final ZKIPCP for arithmetic circuits",
            "oracle_layout": "randomized U_w,U_x,U_y,U_z codewords plus per-repetition blinding codewords; two challenge stages and final Q queries",
            "perfect_hvzk": {
                "established_for_exact_protocol": True,
                "anchor": "Lemma 4.15",
                "premise": "k > ell + t",
                "simulator_explicit": True,
            },
            "malicious_verifier_identical_view_claim": {
                "established_for_exact_protocol": True,
                "anchor": "Theorem 4.7",
            },
            "printed_soundness": {
                "anchor": "Theorem 4.7",
                "premise": "e < (n-k)/4",
                "expression": "(d+2)/|F|^sigma + (1-e/n)^t + 2*((e+2*k)/n)^t",
            },
            "protocol_specific_round_by_round": {
                "anchor": "Section 5.2",
                "first_challenge_error": "(d+2)/|F|^sigma",
                "third_challenge_error": "(1-e/n)^t + 2*((e+2*k)/n)^t",
                "applies_only_to_section_4_7_protocol": True,
                "qrom_result": False,
            },
            "optimized_profile_caveat": {
                "anchor": "Section 5.3 and Appendix C",
                "profile": "e=k and n=3*k",
                "printed_theorem_4_7_premise_satisfied": False,
                "ordinary_soundness_refinement": "uses later e<d/2 analysis and Appendix C joint test analysis",
                "protocol_specific_rbr_state_function_reproved_for_refinement": False,
                "eligible_for_cms_without_new_rbr_proof": False,
            },
        },
        "pinned_executable": {
            "repository": "https://github.com/scipr-lab/libiop",
            "revision": "a2ed2ec2f3e85f29b6035951553b02cb737c817a",
            "revision_date": "2021-05-13",
            "release": "v0.2.0",
            "release_date": "2020-08-13",
            "license": "MIT",
            "language": "C++14",
            "upstream_status": "academic proof-of-concept; README says not production-ready",
            "local_source_root": str(LIBIOP_ROOT),
            "selected_source_lines": selected_loci,
            "selected_source_map": LIBIOP_SOURCE_MAP,
            "implemented_protocol": "AHIV17 Ligero adapted to R1CS by Aurora 2018/828 Appendix B, composed with libiop's LDT reducer/direct LDT and its slightly modified BCS plus final PoW",
            "implemented_protocol_specification": {
                "source": "Aurora: Transparent Succinct Arguments for R1CS",
                "url": "https://eprint.iacr.org/2018/828.pdf",
                "anchors": [
                    "Appendix B.3 Interleaved ZKIPCP for R1CS",
                    "Appendix B.4 From encoded IPCP to regular IPCP",
                ],
                "source_level_zk_intent": "Appendix B.3 parameter b is the query bound for zero knowledge",
                "executable_refinement_established": False,
            },
            "matches_exact_2022_section_4_7": False,
            "match_reasons": [
                "README lines 11 and 85-92 identify AHIV17 and the Aurora Appendix-B R1CS extension as the implementation.",
                "The encoded frontend sends extended witness and Az/Bz/Cz R1CS products, not the exact Section-4.7 circuit wire oracles and checks.",
                "The top-level IOP adds an LDT reducer/direct LDT and allocates four independent soundness errors, so its round structure and state transitions differ from Section 5.2.",
                "The BCS layer adds a custom final proof of work and uses a non-CMS hash chain.",
            ],
            "theorem_inheritance": {
                "lemma_4_15_simulator_applies": False,
                "theorem_4_7_identical_view_applies": False,
                "section_5_2_rbr_applies": False,
                "reason": "No refinement maps this R1CS/LDT/BCS executable to the exact 2022 protocol; source-visible masking and transcript differences violate direct syntactic reuse.",
            },
            "zero_knowledge": {
                "make_zk_toggle_exists": True,
                "complete_zk_established": False,
                "encoding_independence": 3,
                "solved_query_bound_forwarded_to_mask_sampler": False,
                "source_admits_bug": True,
                "anchors": [
                    "libiop/protocols/ligero_iop.tcc:61-67",
                    "libiop/protocols/encoded/ligero/ligero.tcc:44-49",
                ],
                "claim": "The hardcoded three-wise mask is not a proof that every verifier-opened view is independent of the witness; the authors explicitly flag the missing query-bound plumbing as a bug.",
            },
        },
        "other_implementation_sources": [
            {
                "repository": "https://github.com/ligeroinc/ligero-prover",
                "revision": "a40868f6045ddf27a488f65498a9f17832c1cda0",
                "tag": "v1.7.0",
                "release_date": "2026-08-04",
                "license": "Apache-2.0",
                "maintenance": "active at audit date",
                "usable_as_exact_backend": False,
                "blockers": [
                    "BN254 field rather than frozen HX512 relation field",
                    "SHA-256 transcript rather than exact wide SHA-512/SHAKE framing",
                    "protobuf plus gzip is not a canonical consensus wire",
                    "metadata fields are not all verifier-enforced",
                    "no self-contained Rust prover/verifier",
                    "no exact 2022 simulator/RBR/QROM refinement",
                ],
            },
            {
                "repository": "https://github.com/NP-Eng/ligero",
                "revision": "472e7e1af85f9db0bcb44557112ff9d549490ad6",
                "revision_date": "2024-10-28",
                "license": "MIT OR Apache-2.0",
                "maintenance": "stale demo at audit date",
                "usable_as_exact_backend": False,
                "blockers": [
                    "README explicitly says noninteractive non-zero-knowledge and not production-ready",
                    "parameter/dimension and Fiat-Shamir absorptions remain TODO",
                    "no canonical proof wire/parser",
                    "alpha arkworks/git dependencies include ark-ec and Poseidon test surfaces",
                ],
            },
            {
                "repository": "https://github.com/ligeroinc/NFLlib",
                "revision": "4b0bfcca68e999546020538771d0fcc42017a209",
                "revision_date": "2021-04-21",
                "license": "GPL-3.0",
                "maintenance": "stale",
                "usable_as_exact_backend": False,
                "blockers": [
                    "finite-field/NTT library only, not a public protocol implementation",
                    "paper does not pin a released protocol source revision",
                ],
            },
        ],
        "exact_relation": {
            "target": "all-W64 HX512 transaction R1CS",
            "source_identity": "HX512B01 with all-W64 HGMAIDV2/HGMAROOT specialization",
            "frozen": False,
            "freeze_blocker": "red-team review invalidated the count-only compiler; repaired executable IR, final semantic suite, geometry, and source hashes have not landed",
            "stable_interface_only": {
                "statement_bytes": 1141,
                "verifier_context_bytes": 72,
                "verifier_context_grammar": "manifest_root[64] || parent_height:u64le",
                "public_bits_lsb_first": 9704,
                "private_transport_bits": 88000,
                "private_transport_bytes": 11000,
            },
            "field": None,
            "constraints_m": None,
            "variables_n": None,
            "matrix_nonzeros": None,
            "relation_manifest_sha512": None,
            "relation_certificate_sha512": None,
            "native_refinement": False,
            "production_authority": False,
        },
        "executable_wire_and_size": {
            "proof_bytes": None,
            "proof_bytes_lower_bound": None,
            "proof_bytes_upper_bound": None,
            "retained_proof_path": None,
            "reported_size_expression": "field_bytes*(sum prover-message elements + sum query-response elements) + sum root digest bytes + sum auxiliary/salt digest bytes + PoW digest bytes",
            "reported_size_is_serialized_wire": False,
            "reported_size_omissions": [
                "query positions are carried but deliberately not counted",
                "container lengths, field tags, profile/version/network/relation/statement domains and canonical framing",
                "textual serializer omits proof_of_work",
                "textual membership-proof serializer omits ZK randomness hashes",
                "binary-field or non-algebraic-hash serialization is unimplemented",
            ],
            "canonical_bounded_parser": False,
            "exact_consume_and_trailing_byte_rejection": False,
            "malformed_shape_safety": False,
            "malformed_shape_evidence": "bcs_verifier indexes proof-supplied vectors before exact shape checks; Merkle validation dereferences salt and auxiliary iterators before exact-count checks",
            "round_trip_test_for_binary_field_blake2b_ligero": False,
            "only_serialization_test": "non-ZK alt_bn128 field with Poseidon",
        },
        "hash_and_transcript": {
            "conventional_hash_available": "libsodium BLAKE2b",
            "poseidon_also_in_dependency_surface": True,
            "sha512_available": False,
            "shake_available": False,
            "exact_hegemon_domain_framing": False,
            "statement_relation_context_bound_before_first_challenge": False,
            "native_field_memory_hashed": True,
            "native_size_t_hashed": True,
            "canonical_cross_platform_transcript": False,
            "digest_formula": "bcs_protocol uses 2*floor(security_parameter/8) bytes; blake2b_hashchain uses ceil(2*security_parameter/8) bytes",
            "digest_formula_anchor": "libiop/bcs/bcs_common.tcc:405 and libiop/bcs/hashing/blake2b.tcc:14-17",
            "rfc7693_max_output_bytes": 64,
            "cms_modified_chain": {
                "required": "m_j=H(sigma_(j-1),encode(j)); sigma_j=H(m_j,rt_j); m_(k+1)=H(sigma_k,encode(k+1))",
                "implemented": False,
                "implemented_chain": "sequentially absorb each root, absorb a hash of concatenated field messages, then squeeze; initial state is spaces and statement binding remains TODO",
            },
        },
        "qrom_and_zk_composition": {
            "paper_only_conditional_route": {
                "exact_section_4_7_printed_profile_has_hvzk_and_protocol_specific_rbr": True,
                "abstract_cms_premise_shape_matches": True,
                "conditions": [
                    "use parameters satisfying every printed Theorem 4.7 and Lemma 4.15 premise",
                    "implement the exact Section 4.7 round graph and prove refinement",
                    "implement CMS Section 8.2 modified BCS and its syntactic checks",
                    "instantiate privacy-preserving salted commitments and exact BCS p(x)",
                    "instantiate the finite-QROM budget, arity, constants and concrete hash mapping",
                ],
                "executable_composition_established": False,
                "composed_security_claim": False,
                "optimized_section_5_3_route_included": False,
            },
            "underlying_whole_iop_rbr": None,
            "cms_theorem_8_6_applicable": False,
            "cms_reason": "CMS requires whole-IOP RBR and its modified round-number hash chain; neither is established by libiop's component soundness or custom chain.",
            "stronger_rbr_for_original_bcs_chain": None,
            "bcs_zero_knowledge_loss": "z_prime = z + p(x)*2^(-lambda/4+2)",
            "exact_total_iop_proof_length_p_bits": None,
            "exact_random_oracle_output_lambda_bits": None,
            "augmented_qrom_query_budget": None,
            "base_game_arity": None,
            "iop_soundness_advantage": None,
            "pcs_binding_advantage": None,
            "pcs_hiding_advantage": None,
            "fiat_shamir_advantage": None,
            "concrete_hash_to_qro_advantage": None,
            "grinding_advantage": None,
            "rng_failure_advantage": None,
            "retry_abort_advantage": None,
            "lifetime_union_advantage": None,
            "composed_advantage": None,
            "composed_security_bits": None,
            "custom_pow_composed": False,
            "complete_noninteractive_zero_knowledge": False,
        },
        "dependency_closure": {
            "pinned_executable_direct": ["C++14", "libsodium", "libff", "libfqfft", "Boost program_options"],
            "vendored_or_build_surface": ["google benchmark", "googletest", "ate-pairing", "xbyak", "Poseidon", "alt_bn128", "Edwards"],
            "forbidden_ecc_or_pairing_surface_present": True,
            "poseidon_surface_present": True,
            "self_contained_rust": False,
            "acceptable_for_production_reuse": False,
        },
        "rust_clean_room_plan": {
            "decision": "Do not transliterate libiop. Implement the exact 2022 Section-4.7 arithmetic-circuit protocol so its simulator and RBR analysis have a plausible refinement target; compile the frozen R1CS checker to that circuit. An Aurora-Appendix direct R1CS port requires new whole-protocol ZK and RBR proofs.",
            "target_loc": None,
            "target_loc_reason": "No honest exact LoC estimate exists before the relation and wire specifications freeze; the pinned reference surface is 6,152 selected libiop lines but is a different protocol.",
            "modules": [
                {"path": "field.rs", "responsibility": "canonical fixed-endian field encoding, arithmetic, rejection sampling and KATs", "dependencies": []},
                {"path": "relation.rs", "responsibility": "stream frozen sparse R1CS, enforce exact assignment/public/context grammar and manifest digests", "dependencies": []},
                {"path": "circuit_adapter.rs", "responsibility": "compile R1CS satisfaction to the exact arithmetic-circuit/wire relation accepted by Section 4.7 and emit a refinement certificate", "dependencies": []},
                {"path": "parameters.rs", "responsibility": "fixed theorem-safe n,m,ell,k,t,e,sigma and exact rational premise/error checks; optimized e=k profile disabled absent RBR proof", "dependencies": []},
                {"path": "reed_solomon.rs", "responsibility": "deterministic RS encoder/decoder and domain validation with independent vectors", "dependencies": []},
                {"path": "iop.rs", "responsibility": "exact Section-4.7 U_w/U_x/U_y/U_z, affine masks, two challenge phases, Q openings and verifier", "dependencies": []},
                {"path": "simulator.rs", "responsibility": "executable Lemma-4.15 view simulator, malicious-verifier wrapper, distribution/refinement tests", "dependencies": []},
                {"path": "merkle.rs", "responsibility": "salted hiding commitments, fixed tree grammar, exact multiproofs, strict counts", "dependencies": ["sha3"]},
                {"path": "transcript.rs", "responsibility": "exact CMS Section-8.2 chain, unique round encodings, network/version/relation/statement/action domains, SHAKE output", "dependencies": ["sha3", "sha2"]},
                {"path": "wire.rs", "responsibility": "one canonical bounded proof object, fixed-endian fields/counts, verifier-derived shapes, exact-consume parser", "dependencies": []},
                {"path": "prover.rs", "responsibility": "deterministic API over explicit CSPRNG with zeroization and no sidecars", "dependencies": ["rand_core", "zeroize"]},
                {"path": "verifier.rs", "responsibility": "fail-closed verifier with compile-time profile and no attacker-selected parameters", "dependencies": []},
                {"path": "security.rs", "responsibility": "machine-readable PCS/IOP/RBR/BCS/CMS/hash/grinding/RNG/retry/union terms", "dependencies": []},
                {"path": "refinement/", "responsibility": "Lean/Rust equivalence for relation, bytes, transcript, sampling and acceptance plus mutation corpus", "dependencies": []},
            ],
            "allowed_dependency_profile": ["sha2", "sha3", "rand_core", "zeroize"],
            "forbidden_dependency_profile": ["C++", "libsodium", "libff", "libfqfft", "Boost", "protobuf", "gzip", "ark-ec", "ECC", "pairings", "Poseidon"],
            "minimum_acceptance_tests": [
                "paper-step transcript vectors and independent field/RS KATs",
                "explicit simulator view tests for every query count and adversarial verifier schedule",
                "whole-IOP RBR state-function/refinement certificate for the implemented round graph",
                "CMS modified-chain transcript vectors including unique round encoding and final query stage",
                "canonical parse/serialize round trip and mutation tests for every length, field, index, root, salt, domain and trailing byte",
                "exact frozen HX512 relation satisfaction and counterfeit/host-predicate mutation corpus",
                "retained same-relation proof, exact byte count, independent fresh-process verification and restart/reorg lifecycle",
                "full composed QROM/PQ128 ledger and release manifest",
            ],
        },
        "critical_blockers": CRITICAL_BLOCKERS,
        "authority": {
            "architecture_winner": False,
            "protocol_match": False,
            "complete_zero_knowledge": False,
            "whole_iop_rbr": False,
            "cms_qrom": False,
            "pq128": False,
            "exact_relation": False,
            "canonical_wire": False,
            "measured_proof": False,
            "rust_refinement": False,
            "consensus_integration": False,
            "production_authorized": False,
        },
        "verdict": {
            "implementation_ready": False,
            "backup_qualified": False,
            "result": "DISQUALIFIED",
            "reason": "No available executable simultaneously matches the 2022 perfect-ZK/RBR protocol, the frozen exact relation, CMS modified BCS, a canonical conventional-hash wire, and a composed PQ128/QROM ledger. libiop is useful reference code only.",
        },
        "primary_sources": PRIMARY_SOURCES,
    }


def write_ledger(path: Path = LEDGER_PATH) -> None:
    path.write_text(canonical_json(build_ledger()), encoding="utf-8")


if __name__ == "__main__":
    write_ledger()
