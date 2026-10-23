#!/usr/bin/env python3
"""Source-owned authorization for the common PrivateSpend SMZD release.

Missing source-reviewed records always reject. Caller manifests cannot supply
an authorization record. This checks qualified source and retained evidence;
actual production deployment is a separate operator receipt. No compiler,
node, network request, dynamic evidence command or PATH lookup runs here.
"""
import argparse
import hashlib
import json
import posixpath
import re
import subprocess
import sys
import struct
import zlib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "scripts/private_spend_launch_authorized_registry.json"
CONTRACT = "config/private-spend-launch-evidence-contract.json"
FIELD_P = 0xffff_ffff_0000_0001
GATES = ("G1", "G2", "G3", "G4", "G5", "G6")
ASSUMPTIONS = ("PR205_TRUSTED_IMPLEMENTATION_COMPILER_SERIALIZATION", "IDEAL_SHA512_QRO",
               "PR205_F4_BLAKE2B_INTERPRETATION_AND_BINDING", "INDEPENDENT_IDEAL_COINS",
               "EXTERNAL_ADAPTIVE_GHHM", "Q_LE_3_TIMES_2_POW_64")
FIXED = {"kind": "PrivateSpend", "circuit": 11, "crypto": 7, "family": 1,
         "action": 15, "backend": 2, "profile": 12, "domain_set": 8,
         "compression_mode": "hegemon-p2w16-compress14-left-feedforward-v1",
         "emission_schedule": "hegemon-native-emission-21m-atoms1e8-5hgn-epoch2100000-prefix-v1"}
AUTHORITY_FILES = {REGISTRY, CONTRACT, "scripts/check_private_spend_launch_authorization.py"}
RECORDED_SOURCE_ROOT = "/Users/pldd/.codex/worktrees/premainnet-integration/Hegemon"
RECORDED_PROJECT_ROOT = "/Users/pldd/Projects/Reflexivity/Hegemon"
# Exact finite F1 runtime changes needed for ordinary source-authorized wallet/RPC use.
# This pin remains unset until actual scoped compiler/regression checks and an
# independent review exist. Prepared postimages cannot authorize themselves.
SOURCE_RUNTIME_DELTA_REVIEW_SHA256 = None
# Set only after independent readback of the final exact current reuse catalog.
SOURCE_CURRENT_GATE_REUSE_SHA256 = '8d4a197d0604935c47407ec745e6aa59dc68ae6becbd3f2a6db21d24ce956ec3'
# Exact source-approved original paths resolve only to these unchanged packaged bytes.
SOURCE_RETAINED_PATH_ALIASES = "release-evidence/current-retained-path-aliases.json.zlib"
SOURCE_RETAINED_PATH_ALIASES_SHA256 = 'd433f07ca545ee4ade0a464a991712b4de194d93e090a4cbde8f08f39a40055a'
_RETAINED_PATH_ALIAS_CACHE = None
# Exact authentic historical terminal records; individual CLI0 evidence only.
SOURCE_LEGACY_COMPONENT_REAPS = {'c634a7f49fee834265939a0d8f02f5505a3eb5e5ebb910c07d479a4d41b17cc5': ('HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics', '7266b7e9e06a50ab46f86d7c40de217150b83bfaf8560bd0fafbf6b775ac266a', 'e9342da18a2b64196be3ef34ed1aca07b1799d1ff439f55a9e737028a15a21c5'), '025756df04787d41a09799a42753a24d3bea48e18deff203665451fe38a656d0': ('HegemonCrypto.NativePrivateSpendCurrentAcceptedHistory', '89e1b536b72a765a059930e4d8f80416b6899cfbfa093d9604d02ffc3c28ce26', 'e0c4a31ab39e125eb5d486dc8afc818e31fa77f69cae0736d8c2b4eddacdb23e'), '60c860807e8dec295ee5e7145008762b7963462f0143713de5878960c16836d3': ('HegemonCrypto.NativePrivateSpendGenericSpongeAbsorption', '4f0787ef43ae82f7727774c8bf1309d80861f836e29b013107c5a798f1945a71', '91246c7ea757c8dfac235ae3ef2b255279b68170c82ff130964eee55ee339578'), '6dab596c0d184c19dc0fdbb42b8e45acb29eb9a3b74727b149f35d025702c86f': ('HegemonCrypto.NativePrivateSpendCurrentEvaluatorIdentity', '1e795c7558fbe585b0ea91ca4b950595eba0c6910135bb15ca62d8d6352616dc', 'd26f7c2f4572cc35b295032786dfe39b2bba2da9b65039bb170f3fd94f61ffbc'), '81b195153a680a8d5698b5a2a972a9deab630ddd4fc508cc1ee436b2b6dc8d49': ('HegemonCrypto.NativePrivateSpendCurrentSpongeEvaluatorIdentity', 'f68461c6adde26682fe86a556f1cb59a3ee06beab68fbfcf8212d52c3dd12e49', '4035d53157fb52aab5a5b072b925e321d9b70a907808ab1e9a80426d4af1d748'), 'c85adc1e76171d2b5e0d9017c8b2e6082b05cfa8e40472c0aac3a4db268346f7': ('HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory', '97840d31760ba3b068201e08fc9cc3887d279c54b4e5aacc47dc3260d99dd553', '50777e54ce318984734d7b8c5377cb3eba35e132105aafa4cdc1db6acbfcad63'), '0be3c0ad20251ae4a49bbbd75f1f00b88b48e4a414533c9d8222e94b2abb0be9': ('HegemonCrypto.NativePrivateSpendCurrentFinalHistory', '4ecd5482bf48176f33b9cc9790d7f7f8f2a186a2bfefc7a6427221c4ba238705', 'fbfd3447090fcb07dddb12c3f9c132e1996b3a016736aea7b9ace7f8a1997c47'), '06f3ee2301068958ff9e18f77ab3138613d68f4327a448ec8f40895d2251e07d': ('HegemonCrypto.NativePrivateSpendCurrentMerklePath', '1c19eceaa0932d0222fa93cbcfb18fc04373180245abb944dc47ed9bd4208fb5', '34017f7b61ed57c7f611755ca0ce6bbf75a7d9ac549ecc4f5cf4165e6a2f725d')}
SOURCE_RUNTIME_DELTA_POSTIMAGES = {
    "node/src/native/rpc.rs": [
        "16e981c9c7dc1e1ecb745d51f21cabaae5b70f2e782cdc5a0da0c505b00e9ce1",
        "183589d2503694f78ff0a0a1eb9343cf0a924f1eab87d4d132e1a918701cdbb8"
    ],
    "wallet/Cargo.toml": [
        "1e78a9a52ffb270ba5f397c89a3ec33a858bdd8da2d871a69beec30286ebef93",
        "8791ff7224f0efa67546b1fb1e08155a4f27311f01c4d47b1cdc8b0017827c53"
    ],
    "wallet/src/bin/private_spend.rs": [
        "fa82ef6ccd5c39962cf13a07c8cb20a710784daeb024cbe60c29d5b693ce8271",
        "ae76502737343235b5b8ac035a11a8c53a4121913ce5404df4851240a24409e7"
    ],
    "wallet/src/poseidon2_v8_launch_sync.rs": [
        "ad95befa7afef6061687f1c2e5314f7c42bc1a6628d9ee43eb85a02d93ef46b8",
        "2d6688746da6144538aeb97ab20aca571bb15748d22d70bf8aabc0a228ac9d3c"
    ],
    "wallet/src/poseidon2_v8_sync.rs": [
        "91ec06377817d4d56a6b6feb8aaab17f0774d9658a098de033e43a8f59695cae",
        "d9368ae718cbd79778f6a13675dfee66f202d309399cc0d0ac9cea1af040519a"
    ],
    "wallet/src/private_spend_journal.rs": [
        "53f0b5fd8c5e7a3820de8e5e411cd029e144c1053b18118dbf081e6258688b2f",
        "cc0dfd3b6b925bb8b1602c9704d659315da9b8ce048e246e0694805835702395"
    ],
    "wallet/src/private_spend_rpc.rs": [
        "7ba536a5ad9326b21ccd8d76cc1607524713fb6613578b8d2ba4ee8867f5f85c",
        "3035dfebc55ab7b5537c7d728b0965b6aeeedcfc110370c5c6fcde7f9892ba32"
    ],
    "wallet/src/store.rs": [
        "7790bd4f19964afe923d1f34ba401cdeef85c30e408f980b73c7fc4b532e5fc3",
        "4c44cfa5c56e851eda0dcfb11c3434186dbe41ab85f67b81a3c720fcae2b35d5"
    ]
}
SOURCE_RUNTIME_DELTA_CHECKS = {"production_wallet_compile", "source_authority_rejection",
    "private_spend_journal_regressions", "pending_observer_rejection_and_chunk_bounds"}

BASE_RUNTIME_SHA256 = "7f47443a61a53130cd39b938758845ace2fa8cfa74ac7580c43bf5a49aec2955"
BASE_RUNTIME_PATHS_SHA256 = "290e18918d2b701d8d8bf2bd9f57d0e367210899a6ddacec848b06a2dd796f63"
BASE_FORMAL_MAP_SHA256 = "a6aa702f014e7cb73f2f075dbd18cd456dcee6a7ac33dd60a5ee32c8f2468ca7"
G4_SHA256 = "df68e1cb5cf9119525170c38edfd03bd633435d37af8e5cee8aa64e2c2d76691"
G2_BINDING_SHA256 = "a727daf330e9df06d32158739382b621b376e76fce6655283bffa01a8c31c987"
G2_REVIEW_SHA256 = "5b5ac548d8a938ae3fb57c4bea51ae367ce3668e8fca7dea46acd64bb929a090"
G6_SHA256 = "de64963bc4894b6bcea01a9652779478ecbfb9d6d42298b6d1d987355718d9fa"
CURRENT_RELATION_ID = "Hegemon.PrivateSpend.Native2of3.CompFF01.v2"
CURRENT_RELATION = "3ef6aaa1f48dab0445801ae29573f8bf3ff9990872da57dee3c299c63013034b9c8a0a28f8390dac78008df2e8384c38d3a31f843cba0a8adfc10161e182756a"
CURRENT_RUNTIME_RELATION = '1fbb31faf70b87498ca8904d7eb70241552cd0a5460e3570edb85f3bd0378337171c84d8769c82edeabc0313a23b2ab8f332d2649b564766f028832027e9498d'
_F1_CURRENT_SOURCE_APPROVED = False
SOURCE_F1_CURRENT_SUCCESSOR = {'schema': 'hegemon.f1-fixed-current-source-successor.v1', 'retained_relation': '3ef6aaa1f48dab0445801ae29573f8bf3ff9990872da57dee3c299c63013034b9c8a0a28f8390dac78008df2e8384c38d3a31f843cba0a8adfc10161e182756a', 'runtime_relation': '1fbb31faf70b87498ca8904d7eb70241552cd0a5460e3570edb85f3bd0378337171c84d8769c82edeabc0313a23b2ab8f332d2649b564766f028832027e9498d', 'retained_runtime_delta_sha256': '87a6595c281698a3c23e2c9b4ec9c6a2678a3517f65c1b9a44343c694e2c8d3e', 'retained_wallet_manifest_sha256': 'e4d7bcff710a3269d6a36c8d5aa87152a7329bb2d41d91c5c67a3117243337c5', 'retained_lock_sha256': 'd7b4f95705cd88e3978dc771166b0042a6e3f3075e6874561f2c619ead26531d', 'current_lock_sha256': 'bae447660a12610766620cb7e2afacb6b0ad92a3370dd5f15db18e12e753b7ec', 'retained_checks': {'production_wallet_compile': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/production_wallet_compile.json', 'bytes': 4303, 'sha256': 'a2295f8970d7dce192a3ed8c093b6c9886fc230fe2b2050bac95a03d2b34d2a5'}, 'source_authority_rejection': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/source_authority_rejection.json', 'bytes': 3300, 'sha256': '7e8bc37d085a40c67349d8b3bd30d162d6e008fafdf1cedf2bf4a5d79c4efd3d'}, 'private_spend_journal_regressions': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/private_spend_journal_regressions.json', 'bytes': 3250, 'sha256': '4d34e8e16aa6f439da70c05d5d7f1befa4f03cfb6a874965d9f5a1485d71c947'}, 'pending_observer_rejection_and_chunk_bounds': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/pending_observer_rejection_and_chunk_bounds.json', 'bytes': 4537, 'sha256': '6c0c0a4430ec91ea62b4a99b70dff23985d76241c264d91c89c906125627cdac'}}, 'current_manifest_and_lock': [{'bytes': 2993, 'path': '/Users/pldd/.codex/worktrees/premainnet-integration/Hegemon/wallet/Cargo.toml', 'sha256': '8791ff7224f0efa67546b1fb1e08155a4f27311f01c4d47b1cdc8b0017827c53'}, {'bytes': 112118, 'path': '/Users/pldd/.codex/worktrees/premainnet-integration/Hegemon/Cargo.lock', 'sha256': 'bae447660a12610766620cb7e2afacb6b0ad92a3370dd5f15db18e12e753b7ec'}], 'production_commands': [['cargo', '+1.91.1', 'build', '--locked', '--offline', '--release', '--jobs', '2', '-p', 'wallet', '--no-default-features', '--features', 'rpc-client', '--bin', 'wallet', '--bin', 'private-spend', '--bin', 'treasury-v8'], ['cargo', '+1.91.1', 'build', '--locked', '--offline', '--release', '--jobs', '2', '-p', 'hegemon-node', '--no-default-features', '--bin', 'hegemon-node'], ['cargo', '+1.91.1', 'build', '--locked', '--offline', '--release', '--jobs', '2', '-p', 'walletd', '--bin', 'walletd']], 'relation_inputs': [{'bytes': 5921, 'path': 'circuits/transaction/src/private_spend.rs', 'sha256': '817c81998bf5c7e388657a27dac40827c014375022d1fadfe2db83597653e3f6'}, {'bytes': 6855, 'path': 'circuits/transaction/src/private_spend/types.rs', 'sha256': '2567449cf5464e5d8dd45652f61131973c0ce191928e4aa1018bcf651168026e'}, {'bytes': 17310, 'path': 'circuits/transaction/src/private_spend/circuit.rs', 'sha256': 'd53b1f9f49bc2565cf72fc4c1ff6ee24f9da10cc1dd821cb0d572cfc46db013d'}, {'bytes': 3670, 'path': 'circuits/transaction/src/private_spend/helpers.rs', 'sha256': '1e156f8d3894fbe721c011e0f54ba94b53d3484d950a7b7362ac1860de47af69'}, {'bytes': 3121, 'path': 'circuits/transaction/src/private_spend/proof.rs', 'sha256': 'c85cc11d7cf2aafd47d4c3c0471fee20cf7c907753962bf289e297ddfa5d6dfc'}, {'bytes': 37757, 'path': 'circuits/transaction/src/smallwood_htlc/circuit.rs', 'sha256': 'afb8db60285f6a2c1c403653c0f7b7a509294c72c87c343728d2d496a738b36f'}, {'bytes': 16099, 'path': 'circuits/transaction/src/smallwood_htlc/sha256.rs', 'sha256': 'd8e89fee084c66b04f4b86f3a118ce62881f4459a4eb37e8c1ee376370bcac2b'}, {'bytes': 29318, 'path': 'circuits/transaction/src/smallwood_htlc.rs', 'sha256': 'e5926e5bee015a4cdc5c09c316e4fc0640a45fd0a7d6fee94abcd0d6869b901f'}, {'bytes': 799599, 'path': 'circuits/transaction/src/smallwood_engine.rs', 'sha256': '628a87efaa62f96dc7895b0c359b264c500df4282fdc77699ec3476a45d4930c'}, {'bytes': 94228, 'path': 'circuits/transaction/src/smallwood_semantics.rs', 'sha256': 'f96f3a200eb70886a9fec71fd97bfe7efc1b2ce1cae172ad80c6d9246bc6c2cf'}, {'bytes': 165633, 'path': 'circuits/transaction/src/smallwood_hx512_transcript.rs', 'sha256': 'c9be52de7e56114727786c91a2b5c4347ae3ecfa90940b1cc8fa734c5fb7b104'}, {'bytes': 66023, 'path': 'circuits/transaction/src/smallwood_v6_transcript.rs', 'sha256': '4f5833df06e8c8794cd04ddc3f3af053b47f200fd5f70231205b45a02eac4350'}, {'bytes': 39660, 'path': 'circuits/transaction/src/smallwood_poseidon2_v8_rng_refinement.rs', 'sha256': '9671291f7ac84826cd3bea4617e41e1cf0adb7d829bdaa41113f7ea198669edc'}, {'bytes': 78203, 'path': 'circuits/transaction/src/smallwood_poseidon2_v8_hash_schedule.rs', 'sha256': 'f63bb415778dd2e0dacc7a2814861db24e48fb7f086f3f4799bf26cbf5dc955f'}, {'bytes': 103089, 'path': 'circuits/transaction/src/smallwood_poseidon2_v8_types.rs', 'sha256': '0d40897eb0699fa3f09fada0dced803140c7475deb40d6b03117c9306a2e7329'}, {'bytes': 6390, 'path': 'circuits/transaction-core/src/constants.rs', 'sha256': '3f1ec13a129bdd3bba8d0e07d3198ff1e8c6fa4b2ecec5e517743427264a20e4'}, {'bytes': 26955, 'path': 'circuits/transaction-core/src/poseidon2_width16.rs', 'sha256': 'b8f6f37bc0c2e687314b0b277eaebc84fde7955864c124ab7290eab7dc90d323'}, {'bytes': 3649, 'path': 'circuits/transaction-core/src/poseidon2.rs', 'sha256': '0432952fef6850604773e6f42b7f9e03b898da1ab316e476069e58450484ec25'}, {'bytes': 9481, 'path': 'circuits/transaction-core/src/hashing_pq.rs', 'sha256': '7d66a5cfe78d275b06f9f31cf7bd2b925690d8a6c3b028a1ee466292b05fb27f'}, {'bytes': 9190, 'path': 'circuits/hegemon-field/src/lib.rs', 'sha256': '6058cb6f76eae3f5e6ab89405da433e0c28aef09dfc4f38d62c36d6d20cd7d1c'}, {'bytes': 16042, 'path': 'crypto/src/private_note_encryption.rs', 'sha256': '4a3e256b01c3b541743b983fd34559d0b04968d2f35e07066a713ef480ab328a'}, {'bytes': 22147, 'path': 'crypto/src/private_note_payload.rs', 'sha256': '8274a686baa63e9332b6db32745af6d9dc97e3c6b02f4388f05998d206afc99c'}, {'bytes': 13191, 'path': 'crypto/src/ml_kem.rs', 'sha256': '8de074b11cb2c90a2d153e5351d6fc362b53eef0fbfab03bc5e37971c216dcd4'}, {'bytes': 1577, 'path': 'crypto/src/deterministic.rs', 'sha256': 'a552882af1525208bb5fc67cc682a23b3f57befd18bc0be497ed89f1beefa9d5'}, {'bytes': 1725, 'path': 'crypto/src/traits.rs', 'sha256': 'ccecb299964b31735b5499b7a15686cb168c0d79c6fbd08a67dc28544f58f631'}, {'bytes': 36998, 'path': 'crypto/hash384/src/lib.rs', 'sha256': '0f36a3887f33a07c504cd3e19b05c87b9b7c7059947cedb42e1ab8f025356a6e'}, {'bytes': 11944, 'path': 'protocol/shielded-pool/src/private_spend_transport.rs', 'sha256': '362ba6f8c483109434f806f41121751a60927de6939704279b69d19e22e71cad'}, {'bytes': 1514, 'path': 'protocol/versioning/src/launch_candidate_identity.rs', 'sha256': 'a5407bf56703c9ef7e6c60ba773adea63566144c9df4d6bd761a59ff1cf46f70'}, {'bytes': 112118, 'path': 'Cargo.lock', 'sha256': 'bae447660a12610766620cb7e2afacb6b0ad92a3370dd5f15db18e12e753b7ec'}], 'evidence': {'retained_finite_F1_review': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-final-actual-readback-floor20/REVIEW.json', 'bytes': 28136, 'sha256': '9eb695c57e1e59eedf34d7a81dec4ecbd3a446150c3cbee303ae951e13528877'}, 'retained_F1_result': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/RESULT.json', 'bytes': 37569, 'sha256': '9adccee020402772fe76b965749d33e3155662ff80d24fd3e47cb9afabb55484'}, 'retained_F1_ROOT_reap': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-rust-validation-floor20/successor02/run02/ROOT-TERMINAL-REAP.json', 'bytes': 541, 'sha256': 'f21871d41d9d5347d4ff253747ec53eb9ba31cdab8c7a0e2fbd1ec63e625e413'}, 'current_build_source_inventory': {'bytes': 79393, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-root-build-preparation-floor40-01/SOURCE-INVENTORY.json', 'sha256': 'b3a75f1595397b28716ddb366cbc6259fc43f3e07929d34214fce5ecfe060d71'}, 'current_five_binaries': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-root-current-build-scopes01/actual/FIVE-BINARIES.json', 'bytes': 11594, 'sha256': '0b7f07e4e244779b3029faaa14fcaf77231ea28a48079fb787bc700af844cca6'}, 'current_five_binary_review': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-actual-five-binaries-independent01/REVIEW.json', 'bytes': 11852, 'sha256': '64968d01315f24069b56702c0a166c51a3c13c335cc0d86834742e2ef140e62b'}, 'current_HTTP_result': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g8-wallet-http-rust-regression-src-current01/RESULT.json', 'bytes': 3392, 'sha256': '697a7cf29d7645483d0bcc7cc2aa9bec0370694bfdf6736568a5abf327966aff'}, 'current_HTTP_ROOT_reap': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g8-wallet-http-rust-regression-src-current01/ROOT-TERMINAL-REAP.json', 'bytes': 1556, 'sha256': '5dcf8c3f89d2c7416dafb0e44a4c4e897deb1d5070df09cc7dbb03d2637dcca9'}, 'relation_namespace_readback': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g8-current-relation-floor10-01/READBACK.json', 'bytes': 27166, 'sha256': '9c90c077982d5f2e1a6290b384a8907f5c13a939517d75dfdc67912deb9d97e4'}, 'current_producers': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/resource-floor20-successor01/g8-current-proof01/PRODUCERS.json', 'bytes': 13645, 'sha256': '556b914f055436f6005813c9b1d6f6f18adc6dafadfba49f1421135622c36a32'}}, 'authority_scope': 'EXACT_FINITE_SOURCE_NAMESPACE_AND_HISTORICAL_CHECK_REUSE_ONLY', 'universal_Rust_equivalence': False, 'production_authorized': False}
CASES = ("ordinary", "approval", "final", "lock", "claim", "refund")
PROFILE = {"K": 64, "degree": 2, "rho": 5, "openings": 6, "beta": 2,
           "N": 8388608, "q": 58, "eta": 5, "decs_grinding_bits": 0,
           "profile_wire_id": 12, "public_words": 77, "binding_bytes": 616,
           "inner_bytes": 1926125, "carrier_bytes": 1931869,
           "backend": "Sha512NativePrivateSpendSmzd", "domain": "Radix2DisjointCoset"}
# Narrow historical G6 node-reference exception. Candidate evidence cannot approve
# itself; this source pin stays closed until independent review accepts it.
SOURCE_HISTORICAL_G6_NODE_REFERENCE_SHA256 = '04f96f428b8f7aaeea006655ed54b650be7e6ccb18788e984ce76d3269877a76'
SOURCE_HISTORICAL_G6_NODE_REFERENCE = "release-evidence/ongoing-hgn/historical-g6-node-provenance-v2.json"
HISTORICAL_G6_NODE = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/build/retained-proof/hegemon-node', 'sha256': 'f1b2b02695293d9e93e43dac7ebf696b2a1ac55b56bc251d25105bfe08787cc8', 'bytes': 12888912}
HISTORICAL_G6_NODE_PACKAGED = {'path': 'release-evidence/retained/.agent/launchpad-2026-10-03/resume45/build/retained-proof/hegemon-node', 'sha256': 'f1b2b02695293d9e93e43dac7ebf696b2a1ac55b56bc251d25105bfe08787cc8', 'bytes': 12888912}
HISTORICAL_G6_RECEIPT = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/current-policy-lifecycle-floor10-v2/actual/lifecycle/run02/receipt.json', 'bytes': 198459, 'sha256': 'de64963bc4894b6bcea01a9652779478ecbfb9d6d42298b6d1d987355718d9fa'}
HISTORICAL_G6_FROZEN_INPUTS = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g7-final-frozen-review-inputs-floor20/INPUTS.json', 'bytes': 68804, 'sha256': '910be57161c88482b87dd7b828f870458d20deca978232a22f1b7603e998eb93'}
HISTORICAL_G6_RECOVERY = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/ongoing-hgn-20261022/security/actual86-privacy/G6-BINARY-RECOVERY.json', 'bytes': 15280, 'sha256': '02d95b7115353f7be7b30cd48489855062f133c59e6a96400100aec498564825'}

HISTORICAL_G2_QUALIFICATION = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/G2-QUALIFICATION.json', 'bytes': 6554, 'sha256': 'c582d70a67fbc57e164951a702b562fbb926493cd42e5ca471f5ee7292e8822b'}
HISTORICAL_G2_BINDING = {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/remaining-g2-config-floor60-20261011/BINDING.json', 'bytes': 93963, 'sha256': 'a727daf330e9df06d32158739382b621b376e76fce6655283bffa01a8c31c987'}
HISTORICAL_G2_NODE_CONTEXT = {'path': ['g6', 'binaries', 0], 'descriptor': {'bytes': 12888912, 'expected_sha256': 'f1b2b02695293d9e93e43dac7ebf696b2a1ac55b56bc251d25105bfe08787cc8', 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/build/retained-proof/hegemon-node', 'sha256': 'f1b2b02695293d9e93e43dac7ebf696b2a1ac55b56bc251d25105bfe08787cc8'}}

BASE_IMAGES = {}

STRICT_FLAGS = ("-j1", "-DElab.async=false", "-DwarningAsError=true", "-DautoImplicit=false",
                "-DmaxHeartbeats=0", "-DmaxRecDepth=0", "--tstack=262144", "-Dpp.raw=true")
LEAN_SHA256 = "1b370cfcbf44e80d1b004ab1b1ab9a4c73951f9f7c242140bcff9bc577576554"
STACK_SHIM_SHA256 = "280b73d26b4982036f46557c6fa8daa5619847d568a5b01c6df5a8a4d9c0dd8b"
RETAINED_REUSE_SHA256 = "5d0c8805ca76ce710f98b6dd721f69919e56b7da6347892a6eb0788739b87e62"
RETAINED_G4_CHECKS_SHA256 = "09afa3988df97fae83f6917046e519ff0fa95703562cad7a91eea10ef4faefbf"
STD_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
CRYPTOGRAPHIC_CLASS = {"max_total_oracle_queries": 3 * (1 << 64),
                       "max_total_proof_attempts": 1 << 21,
                       "attempts_include": ["failed", "unused", "successful"],
                       "continuation_queries": "uniform_all_context",
                       "attempt_bound": "external_conditional_hypothesis"}

# Ongoing chain operation has no accepted-proof quota or retirement height.
# This is still a conditional finite adversarial experiment class, not a
# runtime-enforced bound on failed/offline attempts or an infinite security claim.
ONGOING_IDENTITY_SCHEMA = "hegemon.private-spend.native-launch-identity.v2"
ONGOING_POLICY_RELATION = 'cd747b8430b51faee6c4bf94d7b0c8f8dfdb7863c6b927db53e7cea67c7a20a49aaf3ceda5b9ba2947dc9b89d070e1ac5fe9ab1c77cba6d859285c2f324b56f5'
ONGOING_POLICY_PROFILE = {'relation_id': 'Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4', 'relation_digest': 'cd747b8430b51faee6c4bf94d7b0c8f8dfdb7863c6b927db53e7cea67c7a20a49aaf3ceda5b9ba2947dc9b89d070e1ac5fe9ab1c77cba6d859285c2f324b56f5', 'public_words': 86, 'binding_bytes': 688, 'circuit': 12, 'carrier_magic': 'HGPSLC02', 'carrier_fixed_bytes': 5784, 'max_proof_bytes': 171848, 'max_carrier_bytes': 177632}
ONGOING_FIXED = dict(FIXED, circuit=12)
# The actual H0 shape is not a security qualification. This separate source pin
# remains closed until the exact current bounded-policy relation is qualified.
SOURCE_ONGOING_POLICY_QUALIFICATION_SHA256 = '0c7b76db682b65510eab6a8af38f44927bf50a72258c8d38a350d804e8ebfe39'
_ONGOING_POLICY_SOURCE_APPROVED = False
ONGOING_CRYPTOGRAPHIC_CLASS = {
    "max_total_oracle_queries": 3 * (1 << 64),
    "max_total_proof_attempts": 1 << 39,
    "max_total_verification_attempts": 1 << 39,
    "max_total_trace_attempts": 1 << 39,
    "max_ordinary_oracle_queries": 1 << 65,
    "attempts_include": ["failed", "unused", "successful"],
    "continuation_queries": "uniform_all_context",
    "attempt_bound": "external_conditional_hypothesis",
}
# An actual independently reviewed class-extension receipt is required in
# addition to the unchanged historical G1-G6 evidence. Prepared artifacts cannot
# install their own authority; the source pin stays closed pending that review.
SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256 = '0feac630cf0edfb67f95bc5583148c32c9dc7836e262e467761c5ccef33e384d'
SOURCE_ONGOING_RUNTIME_DELTA_REVIEW_SHA256 = '7561f35c21917c7ef8489f4c3d9ba98782f0ad38b73520d1745c2bb49f3a913f'
ONGOING_RUNTIME_CHECKS = {"production_node_compile", "production_wallet_compile",
    "production_walletd_compile", "ongoing_policy_regressions", "wallet_rpc_regressions"}

LIFECYCLE_GATES = set("all_exact_carriers_restart_fresh_node approval1 approval1_reorg_rollback approval1_unchanged_resubmission approval2 approval2_reorg_rollback approval2_unchanged_resubmission canonical_issuance claim claim_lock claim_lock_reorg_rollback claim_lock_unchanged_resubmission claim_payout claim_reorg_rollback claim_unchanged_resubmission fee_fund_1 fee_fund_1_reorg_rollback fee_fund_1_unchanged_resubmission fee_fund_2 fee_fund_2_reorg_rollback fee_fund_2_unchanged_resubmission final final_reorg_rollback final_unchanged_resubmission fresh_node_all_bodies persistent_restart refund refund_lock refund_lock_reorg_rollback refund_lock_unchanged_resubmission refund_payout refund_reorg_rollback refund_unchanged_resubmission treasury_canonical_value treasury_payout".split())

def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def retained_path_aliases():
    global _RETAINED_PATH_ALIAS_CACHE
    if _RETAINED_PATH_ALIAS_CACHE is None:
        file = path(SOURCE_RETAINED_PATH_ALIASES)
        require(digest(file) == SOURCE_RETAINED_PATH_ALIASES_SHA256,
                "source-approved original path aliases changed")
        value = json.loads(zlib.decompress(file.read_bytes()), object_pairs_hook=no_duplicates)
        exact_keys(value, ("schema", "aliases"), "source-approved original path aliases")
        require(value["schema"] == "hegemon.source-approved-original-path-aliases.v1" and
                isinstance(value["aliases"], list), "wrong source-approved path alias schema")
        aliases = {}
        for entry in value["aliases"]:
            exact_keys(entry, ("original", "target"), "exact original path alias")
            original, target = entry["original"], entry["target"]
            require(isinstance(original, str) and PurePosixPath(original).is_absolute() and
                    PurePosixPath(original).as_posix() == original and
                    all(part not in (".", "..") for part in PurePosixPath(original).parts) and
                    original not in aliases, "duplicate or noncanonical original alias")
            exact_keys(target, ("path", "bytes", "sha256"), "packaged original target")
            require(target["path"].startswith("release-evidence/retained/") or
                    target["path"] == "release-evidence/compiler/lean4.32.2" or
                    original.startswith(RECORDED_SOURCE_ROOT + "/") and
                    target["path"] == original[len(RECORDED_SOURCE_ROOT) + 1:],
                    "original alias outside retained evidence or exact source identity")
            hexadecimal(target["sha256"], 64, "original alias hash")
            require(type(target["bytes"]) is int and target["bytes"] >= 0,
                    "original alias length changed")
            aliases[original] = target
        _RETAINED_PATH_ALIAS_CACHE = aliases
    return _RETAINED_PATH_ALIAS_CACHE


def same_evidence_file(actual, original, expected):
    require(isinstance(original, str), "original recorded evidence path missing")
    return actual == evidence_file(original, expected)


def evidence_file(name, expected=None):
    # An authenticated predecessor is selected by exact original source path and
    # requested hash. Its pin enforces bytes/hash before any current-source alias.
    if name.startswith(RECORDED_SOURCE_ROOT + "/"):
        relative = name[len(RECORDED_SOURCE_ROOT) + 1:]
        if relative in BASE_IMAGES and expected == BASE_IMAGES[relative]["sha256"]:
            return pin(BASE_IMAGES[relative], "authenticated source predecessor")
    # Exactly two public continuation outputs retain their actual temporary
    # origins. Never open host files or translate an arbitrary temporary prefix.
    prefix_public = {
        "/private/tmp/hegemon-ongoing-hgn-20261022-final-lifecycle-v2/receipt.json":
            "release-evidence/retained/.agent/launchpad-2026-10-03/ongoing-hgn-20261022/binding/composite-stage/public-inputs/current/prefix-parent_receipt.json",
        "/private/tmp/hegemon-ongoing-hgn-20261022-final-lifecycle-continuation-v1/canonical-prefix-readback.json":
            "release-evidence/retained/.agent/launchpad-2026-10-03/ongoing-hgn-20261022/binding/composite-stage/public-inputs/current/prefix-readback.json",
    }
    if name in prefix_public:
        return path(prefix_public[name])
    alias = retained_path_aliases().get(name)
    if alias is not None:
        require(expected is None or alias["sha256"] == expected, "original alias hash changed")
        return pin(alias, "exact original evidence alias")
    # Immutable receipts keep original absolute paths. Only these two literal
    # origins are translated into the release checkout; never read a host path.
    if name.startswith(RECORDED_SOURCE_ROOT + "/"):
        relative = name[len(RECORDED_SOURCE_ROOT) + 1:]
        return path(relative)
    if name.startswith(RECORDED_PROJECT_ROOT + "/"):
        return path("release-evidence/retained/" + name[len(RECORDED_PROJECT_ROOT) + 1:])
    return path(name)

def evidence_pin(value, label):
    require(isinstance(value, dict) and {"path", "sha256"}.issubset(value), label + " pin missing")
    hexadecimal(value["sha256"], 64, label + " hash")
    file = evidence_file(value["path"], value["sha256"])
    require(digest(file) == value["sha256"] and
            ("bytes" not in value or file.stat().st_size == value["bytes"]), label + " bytes changed")
    return file

def evidence_pins(value):
    if isinstance(value, dict):
        if value.get("schema") == "hegemon.private-spend.canonical-prefix-continuation.v1":
            # Snapshot rows describe disposable database provenance, not public
            # files to package. Only this typed field is exempt from file reads;
            # composite_lifecycle_checks validates the complete continuation.
            canonical_prefix_continuation_shape(value)
            canonical_prefix_snapshot_files(value.get("snapshot_files"))
            for key, item in value.items():
                if key != "snapshot_files":
                    evidence_pins(item)
            return
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            evidence_pin(value, "retained prerequisite")
        for item in value.values():
            evidence_pins(item)
    elif isinstance(value, list):
        for item in value:
            evidence_pins(item)

def current_identity(value):
    require(isinstance(value, dict) and value.get("relation_id") == CURRENT_RELATION_ID and
            value.get("relation_digest_sha512") == CURRENT_RELATION and
            value.get("compression_mode") == FIXED["compression_mode"] and
            value.get("profile") == 12 and value.get("proof_magic") == "SMZD" and
            value.get("public_binding_words") == 77 and value.get("query_count") == 58,
            "gate does not bind the current exact relation/profile/common77")

def retained_actual_runtime_delta_review(binding, identity, deltas):
    require(SOURCE_RUNTIME_DELTA_REVIEW_SHA256 is not None,
            "actual independent wallet/RPC runtime delta review is not yet source-approved")
    item = binding["runtime_delta_review"]
    require(item["sha256"] == SOURCE_RUNTIME_DELTA_REVIEW_SHA256,
            "runtime delta review is not the source-owned actual review")
    review = load(pin(item, "actual finite F1 runtime delta review"))
    exact_keys(review, ("schema", "decision", "reviewer", "source_root", "identity", "assumptions",
        "runtime_predecessor_sha256", "runtime_delta_sha256", "postimages", "actual_checks"), "runtime delta review")
    require(review["schema"] == "hegemon.private-spend.actual-runtime-delta-review.v1" and
            review["decision"] == "GO_FINITE_F1_RUNTIME_DELTA" and
            isinstance(review["reviewer"], str) and review["reviewer"] and
            review["source_root"] == RECORDED_SOURCE_ROOT and review["identity"] == identity and
            review["assumptions"] == list(ASSUMPTIONS) and
            review["runtime_predecessor_sha256"] == BASE_RUNTIME_SHA256 and
            review["runtime_delta_sha256"] == canonical_hash([row for row in deltas if row["path"] in SOURCE_RUNTIME_DELTA_POSTIMAGES]) and
            review["postimages"] == {name: pins[1] for name, pins in SOURCE_RUNTIME_DELTA_POSTIMAGES.items()},
            "runtime delta review does not cover this exact finite source/native binding")
    checks = review["actual_checks"]
    exact_keys(checks, SOURCE_RUNTIME_DELTA_CHECKS, "actual affected compile/regression receipts")
    for name, checked in checks.items():
        value = load(pin(checked, name))
        exact_keys(value, ("schema", "check", "source_root", "runtime_delta_sha256", "commands"), name)
        require(value["schema"] == "hegemon.private-spend.actual-runtime-check.v1" and
                value["check"] == name and value["source_root"] == RECORDED_SOURCE_ROOT and
                value["runtime_delta_sha256"] == review["runtime_delta_sha256"], "actual runtime check identity")
        require(isinstance(value["commands"], list) and value["commands"], "actual runtime check has no commands")
        for command in value["commands"]:
            exact_keys(command, ("argv", "executable", "exit_code", "natural_exit", "reaped", "stdout", "stderr"), "actual scoped native command")
            require(isinstance(command["argv"], list) and command["argv"] and
                    all(isinstance(arg, str) for arg in command["argv"]) and
                    type(command["exit_code"]) is int and command["exit_code"] == 0 and
                    command["natural_exit"] is True and command["reaped"] is True,
                    "scoped runtime command did not actually complete naturally with CLI0")
            pin(command["executable"], "actual compiler/native executable")
            pin(command["stdout"], "actual scoped stdout")
            pin(command["stderr"], "actual scoped stderr")

def actual_runtime_delta_review(binding, identity, deltas):
    """Separate historical tests from this exact reviewed source successor."""
    global _F1_CURRENT_SOURCE_APPROVED
    _F1_CURRENT_SOURCE_APPROVED = False
    require(SOURCE_RUNTIME_DELTA_REVIEW_SHA256 is not None,
            "actual independent wallet/RPC runtime delta review is not yet source-approved")
    item = binding["runtime_delta_review"]
    require(item["sha256"] == SOURCE_RUNTIME_DELTA_REVIEW_SHA256,
            "runtime delta review is not the source-owned actual review")
    review = load(pin(item, "actual finite F1 runtime delta review"))
    if review.get("schema") == "hegemon.private-spend.actual-runtime-delta-review.v1":
        return retained_actual_runtime_delta_review(binding, identity, deltas)
    exact_keys(review, ("schema", "decision", "reviewer", "source_root", "identity", "assumptions",
        "runtime_predecessor_sha256", "runtime_delta_sha256", "postimages", "actual_checks",
        "source_successor", "current_production_compile"), "finite current-source F1 review")
    require(review["schema"] == "hegemon.private-spend.actual-runtime-delta-review.v2" and
            review["decision"] == "GO_FINITE_F1_CURRENT_SOURCE_SUCCESSOR" and
            isinstance(review["reviewer"], str) and review["reviewer"] and
            review["source_root"] == RECORDED_SOURCE_ROOT and review["identity"] == identity and
            review["assumptions"] == list(ASSUMPTIONS) and
            review["runtime_predecessor_sha256"] == BASE_RUNTIME_SHA256 and
            review["runtime_delta_sha256"] == canonical_hash([row for row in deltas if row["path"] in SOURCE_RUNTIME_DELTA_POSTIMAGES]) and
            review["postimages"] == {name: pins[1] for name, pins in SOURCE_RUNTIME_DELTA_POSTIMAGES.items()} and
            review["source_successor"] == SOURCE_F1_CURRENT_SUCCESSOR,
            "current source successor lacks exact independent approval")
    successor = SOURCE_F1_CURRENT_SUCCESSOR
    for value in successor["evidence"].values():
        pin(value, "fixed finite source-successor evidence")
    for value in successor["relation_inputs"]:
        pin(value, "current exact relation source")
    manifest = path("wallet/Cargo.toml").read_bytes()
    line = b'soketto = { version = "0.8.1", default-features = false }\n'
    require(manifest.count(line) == 1 and
            hashlib.sha256(manifest.replace(line, b'', 1)).hexdigest() == successor["retained_wallet_manifest_sha256"],
            "wallet manifest change is not the one reviewed dev-dependency line")
    checks = review["actual_checks"]
    require(checks == successor["retained_checks"], "retained F1 checks were replaced or relabeled")
    for name, checked in checks.items():
        value = load(pin(checked, name))
        exact_keys(value, ("schema", "check", "source_root", "runtime_delta_sha256", "commands"), name)
        require(value["schema"] == "hegemon.private-spend.actual-runtime-check.v1" and
                value["check"] == name and value["source_root"] == RECORDED_SOURCE_ROOT and
                value["runtime_delta_sha256"] == successor["retained_runtime_delta_sha256"],
                "historical check identity was rewritten")
        require(isinstance(value["commands"], list) and value["commands"], "empty historical check")
        for command in value["commands"]:
            exact_keys(command, ("argv", "executable", "exit_code", "natural_exit", "reaped", "stdout", "stderr"), "historical runtime command")
            require(type(command["exit_code"]) is int and command["exit_code"] == 0 and
                    command["natural_exit"] is True and command["reaped"] is True,
                    "historical runtime command did not pass naturally")
            for field in ("executable", "stdout", "stderr"):
                pin(command[field], "historical " + field)
    actual = review["current_production_compile"]
    exact_keys(actual, ("result", "ROOT_reap", "guard", "supervisor"), "actual current production compile")
    result, reap, guard, supervisor = (load(pin(actual[key], key)) for key in ("result", "ROOT_reap", "guard", "supervisor"))
    require(result.get("schema") == "hegemon.f1-current-production-compile-result.v1" and
            result.get("check") == "production_wallet_compile" and result.get("source_root") == RECORDED_SOURCE_ROOT and
            result.get("all_three_cli0") is True and result.get("original_target_unchanged") is True and
            result.get("production_authorized") is False and
            result.get("source_inventory") == successor["evidence"]["current_build_source_inventory"] and
            result.get("current_sources") == successor["current_manifest_and_lock"],
            "current production configurations were not actually compiled")
    require(reap.get("schema") == "hegemon.f1-production-compile-root-terminal-reap.v1" and
            reap.get("result") == actual["result"] and reap.get("guard") == actual["guard"] and
            reap.get("supervisor") == actual["supervisor"] and reap.get("terminal_exit_code") == 0 and
            reap.get("natural_completion") is True and reap.get("fully_reaped") is True and
            reap.get("native_running") is False and reap.get("owner_signal") == 0 and reap.get("stop_reason") == "none",
            "actual current production terminal was not naturally reaped")
    require(guard.get("exit_code") == 0 and guard.get("owner_signal") == 0 and guard.get("stop_reason") == "none" and
            guard.get("disk_reserve_bytes") == 5 * 2**30 and guard.get("no_heap_or_runtime_cap") is True and
            supervisor.get("guard_exit_code") == 0 and supervisor.get("reason") == "completed" and
            supervisor.get("owner_signal") == 0 and supervisor.get("test_only") is False and
            supervisor.get("guard_receipt") == guard,
            "current production guard/supervisor did not pass")
    commands = result.get("commands")
    require(isinstance(commands, list) and len(commands) == 3, "three production commands required")
    for command, expected in zip(commands, successor["production_commands"]):
        require(command.get("argv") == expected and type(command.get("exit_code")) is int and
                command["exit_code"] == 0 and command.get("natural_exit") is True and command.get("reaped") is True,
                "actual current production flags or result differ")
        for field in ("executable", "stdout", "stderr"):
            pin(command[field], "current production " + field)
    exact_keys(result.get("binaries"), ("hegemon-node", "wallet", "walletd", "private-spend", "treasury-v8"), "current production outputs")
    for value in result["binaries"].values():
        pin(value, "current production output")
    _F1_CURRENT_SOURCE_APPROVED = True

def current_proof_provenance(case, record, stage, outer, *, predecessor=False):
    require((_ONGOING_POLICY_SOURCE_APPROVED if predecessor else _F1_CURRENT_SOURCE_APPROVED),
            "retained proof namespace lacks approved finite source successor or explicit predecessor bridge")
    producers = load(pin(SOURCE_F1_CURRENT_SUCCESSOR["evidence"]["current_producers"], "current six producers"))
    require(producers.get("schema") == "hegemon.g8-six-current-proof-producers.v1" and
            producers.get("production_authorized") is False and
            record["native_stage"] == producers["result"] and record["native_stage_outer"] == producers["ROOT_reap"],
            "current proof uses unrelated stage records")
    expected_stages = ["prove-" + name for name in CASES]
    require([row.get("stage") for row in producers["producers"]] == expected_stages,
            "current producer case ordering changed")
    selected = producers["producers"][list(CASES).index(case)]
    for filename, field in (("result.json", "result"), ("source-config.json", "source_config"),
            ("proof.smzd", "proof"), ("carrier.hgps", "carrier")):
        require(record[field] == selected["proof_outputs"][filename], "current producer output substituted")
    require(record["migration_negative"] == selected["migration_negative"], "current migration receipt substituted")
    require(stage.get("schema") == "hegemon.g8-six-current-proofs-child-result.v1" and
            stage.get("status") == "ACTUAL_SIX_CURRENT_FIXTURES_VERIFIED_REQUIRES_OUTER_GUARD_FINALIZATION" and stage.get("all_owned_reaped") is True and
            len(stage.get("children", [])) == 7 and
            all(row.get("exit_code") == 0 and row.get("fully_reaped") is True for row in stage["children"]),
            "current producer children did not complete")
    require(outer.get("schema") == "hegemon.g8.six-current-proofs-root-terminal-reap.v1" and
            outer.get("status") == "ACTUAL_SIX_CURRENT_PROOFS_PASS" and outer.get("terminal_exit_code") == 0 and
            outer.get("natural_completion") is True and outer.get("fully_reaped") is True and
            outer.get("terminal_reaped") is True and outer.get("native_running") is False and
            outer.get("owner_signal") == 0 and outer.get("stop_reason") == "none" and
            outer.get("child_result") == producers["result"] and outer.get("ready") == producers["producer_READY"] and
            outer.get("independent_tooling_review") == producers["producer_independent_review"] and
            outer.get("actual_relation_digest_sha512") == CURRENT_RUNTIME_RELATION,
            "current producer root terminal provenance differs")
    for key in ("producer_READY", "producer_independent_review", "generator", "result", "ROOT_reap", "outer_guard", "outer_quota", "scope", "spec"):
        pin(producers[key], "fixed current producer " + key)
    evidence_pins(stage)
    evidence_pins(outer)


def normalized_capability_sha256(text):
    pattern = r"const\s+AUTHORIZED_LAUNCH_PROOF_CAPABILITIES\s*:\s*&\[LaunchProofCapability\]\s*=\s*(.*?);"
    matches = list(re.finditer(pattern, text, re.S))
    require(len(matches) == 1, "exact capability declaration required for normalization")
    match = matches[0]
    return hashlib.sha256((text[:match.start(1)] + "CAPABILITY" + text[match.end(1):]).encode()).hexdigest()


def ongoing_runtime_source_closure(binding, identity):
    global _F1_CURRENT_SOURCE_APPROVED
    _F1_CURRENT_SOURCE_APPROVED = False
    item = binding["runtime_delta_review"]
    require(SOURCE_ONGOING_RUNTIME_DELTA_REVIEW_SHA256 is not None and
            item.get("sha256") == SOURCE_ONGOING_RUNTIME_DELTA_REVIEW_SHA256,
            "ongoing runtime successor lacks source-owned independent review")
    review = load(pin(item, "ongoing finite F1 runtime review"))
    exact_keys(review, ("schema", "decision", "reviewer", "source_root", "identity", "assumptions",
        "parent_runtime_inventory", "current_runtime_inventory", "reviewed_runtime_delta",
        "proof_relation_inputs", "actual_checks", "normalized_capability_sha256", "hgn_only",
        "assets_enabled", "production_authorized", "universal_rust_equivalence"), "ongoing runtime review")
    require(review["schema"] == "hegemon.private-spend.ongoing-runtime-delta-review.v1" and
            review["decision"] == "GO_FINITE_F1_ONGOING_HGN_SOURCE" and
            isinstance(review["reviewer"], str) and review["reviewer"] and
            review["source_root"] == RECORDED_SOURCE_ROOT and review["identity"] == identity and
            review["assumptions"] == list(ASSUMPTIONS) and review["hgn_only"] is True and
            review["assets_enabled"] is False and review["production_authorized"] is False and
            review["universal_rust_equivalence"] is False,
            "ongoing runtime review scope or conditional boundary differs")
    require(review["parent_runtime_inventory"] == binding["runtime_predecessor"] and
            review["current_runtime_inventory"] == binding["runtime_inventory"] and
            review["reviewed_runtime_delta"] == binding["reviewed_runtime_delta"],
            "ongoing runtime review does not bind exact inventories/delta")
    baseline = load(pin(binding["runtime_predecessor"], "ongoing retained runtime inventory"))
    require(binding["runtime_predecessor"]["sha256"] == BASE_RUNTIME_SHA256 and
            baseline.get("schema") == "hegemon.current-policy.src-inventory.v2" and
            baseline.get("source_root") == RECORDED_SOURCE_ROOT, "ongoing runtime parent changed")
    base_rows = baseline["files"]
    require(len(base_rows) == 541 and canonical_hash(sorted(row["path"] for row in base_rows)) == BASE_RUNTIME_PATHS_SHA256,
            "ongoing runtime parent path set changed")
    expected = {row["path"]: row for row in base_rows}
    deltas = binding["reviewed_runtime_delta"]
    require(isinstance(deltas, list) and deltas and len({row["path"] for row in deltas}) == len(deltas),
            "ongoing runtime changed paths missing or duplicated")
    for row in deltas:
        exact_keys(row, ("path", "beforeimage", "after"), "ongoing reviewed runtime delta")
        require(row["path"] not in AUTHORITY_FILES and row["after"]["path"] == row["path"],
                "runtime delta cannot replace authority metadata or another path")
        old = row["beforeimage"]
        if row["path"] in expected:
            require(isinstance(old, dict) and old["sha256"] == expected[row["path"]]["sha256"] and
                    old["bytes"] == expected[row["path"]]["bytes"], "ongoing runtime beforeimage mismatch")
            pin(old, "ongoing runtime beforeimage")
            BASE_IMAGES[row["path"]] = old
        else:
            require(old is None, "new runtime source must have explicit absent predecessor")
        pin(row["after"], "ongoing exact reviewed postimage")
        expected[row["path"]] = row["after"]
    runtime = load(pin(binding["runtime_inventory"], "ongoing complete runtime inventory"))
    rows = runtime.get("files")
    require(runtime.get("schema") == "hegemon.private-spend.release-inventory.v1" and
            isinstance(rows, list) and len(rows) == len(expected) and {row["path"] for row in rows} == set(expected),
            "ongoing runtime inventory omits, duplicates or adds unreviewed paths")
    for row in rows:
        require(row["sha256"] == expected[row["path"]]["sha256"] and row["bytes"] == expected[row["path"]]["bytes"],
                "ongoing runtime inventory differs from exact reviewed postimages")
        pin(row, "ongoing runtime source")
    require(review["normalized_capability_sha256"] == normalized_capability_sha256(
        path("protocol/versioning/src/launch_candidate.rs").read_text()), "ongoing capability executable logic changed")
    native_capability(identity)
    policy_qualification = ongoing_policy_qualification(binding["ongoing_policy_qualification"])
    relation_inputs = policy_qualification["source_inputs"]
    require(review["proof_relation_inputs"] == relation_inputs, "ongoing proof relation/circuit closure changed")
    for row in relation_inputs:
        pin(row, "ongoing unchanged proof relation source")
    exact_keys(review["actual_checks"], ONGOING_RUNTIME_CHECKS, "ongoing affected compile/tests")
    for name, descriptor in review["actual_checks"].items():
        checked = load(pin(descriptor, name))
        require(checked.get("schema") == "hegemon.private-spend.actual-runtime-check.v1" and
                checked.get("check") == name and checked.get("source_root") == RECORDED_SOURCE_ROOT and
                checked.get("runtime_delta_sha256") == canonical_hash(deltas), "ongoing actual check source identity")
        commands = checked.get("commands")
        require(isinstance(commands, list) and commands, "ongoing actual check has no commands")
        for command in commands:
            require(isinstance(command.get("argv"), list) and command["argv"] and
                    all(isinstance(arg, str) for arg in command["argv"]) and
                    type(command.get("exit_code")) is int and command["exit_code"] == 0 and
                    command.get("natural_exit") is True and command.get("reaped") is True,
                    "ongoing native command lacks natural reaped CLI0")
            for key in ("executable", "stdout", "stderr"):
                pin(command[key], "ongoing actual command " + key)
    return formal_source_closure(binding)


def source_closure(binding, identity):
    if identity.get("schema") == ONGOING_IDENTITY_SCHEMA:
        return ongoing_runtime_source_closure(binding, identity)
    baseline_pin = binding["runtime_predecessor"]
    require(baseline_pin["sha256"] == BASE_RUNTIME_SHA256, "wrong retained runtime predecessor")
    baseline = load(pin(baseline_pin, "541-file runtime predecessor"))
    require(baseline.get("schema") == "hegemon.current-policy.src-inventory.v2" and
            baseline.get("source_root") == RECORDED_SOURCE_ROOT, "runtime predecessor identity")
    base_rows = baseline["files"]
    require(len(base_rows) == 541 and canonical_hash(sorted(row["path"] for row in base_rows)) == BASE_RUNTIME_PATHS_SHA256,
            "runtime predecessor must contain the exact 541 source paths")
    expected = {row["path"]: row for row in base_rows}
    require(len(expected) == 541, "duplicate predecessor paths")
    deltas = binding["reviewed_runtime_delta"]
    require(isinstance(deltas, list), "runtime delta must be a list")
    allowed = {"protocol/versioning/src/launch_candidate.rs", "scripts/check_transaction_proof_successor_authorization.py", "Cargo.lock"} | set(SOURCE_RUNTIME_DELTA_POSTIMAGES)
    require({row["path"] for row in deltas} == allowed and len(deltas) == len(allowed),
            "runtime delta must be exactly the two authority changes, eight reviewed wallet/RPC paths and reviewed Cargo.lock")
    actual_runtime_delta_review(binding, identity, deltas)
    for row in deltas:
        exact_keys(row, ("path", "beforeimage", "after"), "reviewed runtime delta")
        old = row["beforeimage"]
        require(old["sha256"] == expected[row["path"]]["sha256"] and old["bytes"] == expected[row["path"]]["bytes"], "delta predecessor mismatch")
        before = pin(old, "runtime beforeimage").read_text()
        after = pin(row["after"], "runtime postimage").read_text()
        require(row["after"]["path"] == row["path"], "delta changes another source path")
        if row["path"] in SOURCE_RUNTIME_DELTA_POSTIMAGES:
            fixed_before, fixed_after = SOURCE_RUNTIME_DELTA_POSTIMAGES[row["path"]]
            require(old["sha256"] == fixed_before and row["after"]["sha256"] == fixed_after,
                    "wallet/RPC runtime change is not the exact independently reviewed postimage")
        elif row["path"] == "Cargo.lock":
            require(old["sha256"] == SOURCE_F1_CURRENT_SUCCESSOR["retained_lock_sha256"] and
                    row["after"]["sha256"] == SOURCE_F1_CURRENT_SUCCESSOR["current_lock_sha256"],
                    "dependency lock is not the exact independently reviewed namespace successor")
        elif row["path"] == "protocol/versioning/src/launch_candidate.rs":
            pattern = r"const\s+AUTHORIZED_LAUNCH_PROOF_CAPABILITIES\s*:\s*&\[LaunchProofCapability\]\s*=\s*(.*?);"
            before_match, after_match = re.search(pattern, before, re.S), re.search(pattern, after, re.S)
            require(before_match and after_match and re.sub(r"\s", "", before_match.group(1)) == "&[]", "capability predecessor is not fail-closed")
            require(before[:before_match.start(1)] + "CAPABILITY" + before[before_match.end(1):] ==
                    after[:after_match.start(1)] + "CAPABILITY" + after[after_match.end(1):], "capability delta changes executable logic")
            native_capability(identity)
        else:
            workflow_sha512 = hashlib.sha512(path(".github/workflows/release.yml").read_bytes()).hexdigest()
            pattern = r"RELEASE_WORKFLOW_SHA512\s*=\s*\((.*?)\)"
            # This historical checker remains a separate fail-closed profile.
            before_match, after_match = re.search(pattern, before, re.S), re.search(pattern, after, re.S)
            require(before_match and after_match and "".join(re.findall(r'[\"\']([0-9a-f]+)[\"\']', after_match.group(1))) == workflow_sha512, "historical workflow compatibility pin missing")
            require(before[:before_match.start(1)] + "HASH" + before[before_match.end(1):] ==
                    after[:after_match.start(1)] + "HASH" + after[after_match.end(1):], "historical checker logic changed")
        BASE_IMAGES[row["path"]] = old
        expected[row["path"]] = row["after"]
    runtime = load(pin(binding["runtime_inventory"], "complete current runtime inventory"))
    require(runtime.get("schema") == "hegemon.private-spend.release-inventory.v1", "runtime inventory schema")
    rows = runtime.get("files")
    require(isinstance(rows, list) and len(rows) == 541 and {row["path"] for row in rows} == set(expected), "runtime inventory omits or adds finite source paths")
    for row in rows:
        require(row["sha256"] == expected[row["path"]]["sha256"] and row["bytes"] == expected[row["path"]]["bytes"], "runtime delta is not exactly reviewed")
        pin(row, "current runtime source")
    return formal_source_closure(binding)


def formal_source_closure(binding):
    base_formal = load(pin(binding["formal_predecessor"], "authenticated 70-formal postimage map"))
    postimages = base_formal.get("retained_postimages_after", {})
    formal = {name[len(RECORDED_SOURCE_ROOT) + 1:]: sha for name, sha in postimages.items() if name.startswith(RECORDED_SOURCE_ROOT + "/")}
    require(len(formal) == 70 and canonical_hash(formal) == BASE_FORMAL_MAP_SHA256, "wrong named current formal endpoint/source closure")
    formal_inventory = load(pin(binding["formal_inventory"], "current formal inventory"))
    require(formal_inventory.get("schema") == "hegemon.private-spend.release-inventory.v1", "formal inventory schema")
    rows = formal_inventory.get("files")
    require(isinstance(rows, list), "formal inventory missing")
    names = {row["path"] for row in rows}
    require(len(names) == len(rows) and set(formal).issubset(names), "formal inventory omits named checked current sources")
    for row in rows:
        require(row["path"].startswith("formal/"), "nonformal source in formal inventory")
        require(row["path"] not in formal or row["sha256"] == formal[row["path"]], "checked current formal source drift")
        pin(row, "current formal source")
    return names

def audit_readouts(text, expected):
    """Consume the complete native stdout; warnings and partial parses reject."""
    require(isinstance(expected, dict) and expected, "exact audit root map missing")
    rest, found = text.strip(), {}
    pattern = r"'([^']+)' (?:depends on axioms:\s*\[([^\]]*)\]|does not depend on any axioms)"
    while rest:
        match = re.match(pattern, rest)
        require(match is not None, "unconsumed compiler/audit output")
        root, payload = match.groups()
        require(root in expected and root not in found, "unexpected or duplicate audit root")
        tokens = [] if payload is None or not payload.strip() else payload.split(',')
        require(all(token.strip() for token in tokens), "empty axiom token")
        axioms = [token.strip() for token in tokens]
        require(set(axioms).issubset(STD_AXIOMS) and len(axioms) == len(set(axioms)),
                "nonstandard or duplicate axiom")
        require(axioms == expected[root], "actual axiom readout differs from declared exact root")
        found[root] = axioms
        rest = rest[match.end():].strip()
    require(set(found) == set(expected), "actual audit omits a declared root")
    return found

def actual_row(rows, module):
    require(isinstance(rows, list), "canonical provenance must be the actual native receipt list")
    selected = [row for row in rows if row.get("module", row.get("label")) == module]
    require(len(selected) == 1, "missing or duplicate actual module provenance")
    return selected[0]

def strict_native_row(check, row):
    require(type(row.get("exit_code")) is int and row["exit_code"] == 0 and
            type(check.get("exit_code")) is int and check["exit_code"] == 0,
            "actual compiler did not return natural integer CLI0")
    argv = row.get("native_argv")
    require(isinstance(argv, list) and len(argv) == 13 and tuple(argv[1:9]) == STRICT_FLAGS and
            argv[9] == "--root=" + row.get("cwd", "") and argv[10] == "-o",
            "new check does not use the exact ordered strict8 compiler options")
    source = row.get("source", argv[-1])
    obj = row.get("object", argv[-2])
    require(argv[-1] == source and argv[-2] == obj and check.get("native_argv") == argv,
            "actual source/object/argv join changed")
    require(check["compiler"]["sha256"] == LEAN_SHA256 and
            argv[0] == "/Users/pldd/.elan/toolchains/leanprover--lean4---v4.32.2/bin/lean",
            "new check compiler identity is not frozen Lean4.32.2")
    pin(check["compiler"], "actual retained compiler executable")
    for key, original in (("source", source), ("object", obj), ("log", row.get("log"))):
        file = pin(check[key], "new checked " + key)
        require(row.get(key + "_sha256") == check[key]["sha256"] and
                digest(evidence_file(original, check[key]["sha256"])) == check[key]["sha256"],
                "actual source/object/log bytes do not match current release evidence")
    stack = row.get("stack_receipt", row.get("native_stack_receipt", {}).get("path"))
    stack_hash = row.get("stack_receipt_sha256", row.get("native_stack_receipt", {}).get("sha256"))
    require(check["stack_receipt"]["sha256"] == stack_hash and
            load(pin(check["stack_receipt"], "actual effective stack")) ==
            {"schema": "q58-native-shell-stack-receipt-v46", "soft_kib": 65520, "hard_kib": 65520},
            "new check lacks the exact effective65520 stack receipt")
    require(digest(evidence_file(stack, stack_hash)) == stack_hash,
            "actual launcher stack receipt bytes changed")
    launcher = row.get("argv")
    require(isinstance(launcher, list) and len(launcher) == 17 and launcher[:2] == ["/bin/zsh", "-f"] and
            launcher[3] == stack and launcher[4:] == argv and check["argv"] == launcher,
            "actual launcher/source/compiler/stack join changed")
    require(check["stack_shim"]["sha256"] == STACK_SHIM_SHA256 and
            digest(evidence_file(launcher[2], STACK_SHIM_SHA256)) == STACK_SHIM_SHA256,
            "actual stack launcher identity changed")
    pin(check["stack_shim"], "retained native stack shim")
    return pin(check["log"], "complete canonical native output").read_text()


# Exact historical source evidence. No new strict8 or cache-byte-equivalence claim.
SOURCE_ORIGINAL_SOURCE_COMPONENTS = {'HegemonCrypto.NativeHtlcUniversalMatrix': '7ade50266d631343893082d27da7429fb35903331856c593346907a5cc37acf0',
 'HegemonCrypto.NativePrivateSpendQ58ActiveEventProjection': 'be2ecc1110e25a886fef2cbb4a93968d96835edc2a3a835333e1cb036fa16afa',
 'HegemonCrypto.NativePrivateSpendQ58ActiveProgramTransport': '2b7c84e40cd53275f330bc96b224e40dbda8283965447a97b2b1c1693f5b28d8',
 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedDecs': '81a53bd278edb25a4beeecb3f87bd1f29794b4405f849f1d4c64d7dd10a68d14',
 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedPcsFacts': 'd471c7e7fd9325e7b25c6270b07e700622f5f29d2053ac4a0bebc44797102537',
 'HegemonCrypto.NativePrivateSpendQ58CurrentCompactMerkle': '0bb527092732e8a296226a7f9ba3dc66fc4ecca928f4407f99af13e8e251376f',
 'HegemonCrypto.NativePrivateSpendQ58CurrentFullStageEnvelope': '9de2868c29d8046c5f9092dc93e91366dd18dc66b0b5aa15556bfe97ef221c06',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGeometry': '0f80bcd08e95feadc9670fae332171e327023f1ff1921876f4e3a26fb7a4acc1',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalAssembly': '53a0a861d363db676168159aae24901b77c04a8370d8aaecadf82ab6d0b65850',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalBranch': 'e317650f7bead637acc1f4e042897e8572225c517aed0ed55f77a0603fc4ec90',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalCount': '10a4238e4eb5e67a6178ade70dda834c3d8566466ffd93f7a08f0dd880c8b4aa',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalDescent': '3043badf24fea2542697921e36ee1294ecb5468e8b0855958e62754edd619cf8',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalHeights': '22483e70d1f614549505a2a930c228ef9e2d1f5ccc6e1513ea2b535d4e8906a0',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalIndependent': '8c108439e8fe6bda75bce2a25461e77cee378864dd6e0e28f13dc962b78cdccc',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalLocal': '0d2d3814ba82e8e3aec7db88dcceef607c4c036d0158cbd8c6c7e7f2dcda2636',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalNewton': '68ddbed2b537ea1cc095bb695a95003e7d5eb61f8d5783ff4cb87c85d113a7e2',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalNonaffine': 'c902554519559547d0833e4e25bca616e2aa52243bd3c2722dfb29aa7345ed1e',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalNumerator': '1769cfcb35f65070a882cfe6f90cc99ed8cbb55379c9017d6aecc8f72f4bff34',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalPartition': 'fe9fe539a89a7e32ce223f950decfb4541b1954d0189562929cb0abe86652011',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalPolynomial': '94348270f1470c44e59f2d76e4ef2dd9e7ecee74ddca665fbd8771ffc327582a',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalPosition': '2587acc6c8e65f4339c2845cb5522cdd118cfbee790de5f116eede37985b05b5',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalSupport': 'a5976eced21f7d6edb6d6d57add8d0215d84a8c3e9bd42ef5e26bd8ca14a8a92',
 'HegemonCrypto.NativePrivateSpendQ58CurrentGlobalWeights': '06d993b61a348354373a89841a49c66019d17366f1f136df3e386de676d5cebb',
 'HegemonCrypto.NativePrivateSpendQ58CurrentInterpolation': '915ed881d0ece46871973f2062b62539297aa4d31d715aa909c77c6d7c73fd52',
 'HegemonCrypto.NativePrivateSpendQ58CurrentRecovery': 'e53334d294adb0a749dc788528598d8d63ad351454a8689d603944f89182f9c4',
 'HegemonCrypto.NativePrivateSpendQ58CurrentRetainedResponseReadback': '9c7bce8d8bfc047a83722926a84cc3b318af2fbd8e74fd917b3dd83cb85b2308',
 'HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier': '309416edb4c8c8183b05ef8674ce24d57d06acf72111c804fd475683772a08c4',
 'HegemonCrypto.NativePrivateSpendQ58CurrentSuccessfulFiber': 'c7db40b6cf0687154c3d7f748c221cf8e2dbee330158b50d83ed9e374eaccbd4',
 'HegemonCrypto.NativePrivateSpendQ58EnvelopeInstability': '1fd46494a98098e753d9aff247c3199633b47272d5eaed1b80447f398a917955',
 'HegemonCrypto.NativePrivateSpendQ58Parameters': '04627236010bcf420424329ebea8e36f2f33299918f487c7891e468325e34da3',
 'HegemonCrypto.NativePrivateSpendQ58PartitionTransport': '8edef8b1c14e101a4d8e8f25fabd3ce0af8703d234d46f421204e72b6a7035e4'}
SOURCE_CURRENT_FAILED_COMPONENT_REAPS = {('303bea62c91613d6e5e2ea68e5e909f2fc282889552a31da7e3d5b7b2ced47bf',
  'AuditCurrentPrequeryEventsEventJoin',
  '9fde49113509dfab8995863e9384e3a44a33908364844749c9b55b3f27d809ec',
  'acd2a933a45ceba0066200a8ab5bccf42d94e5f96427387fba115afb74967bfb'),
 ('303bea62c91613d6e5e2ea68e5e909f2fc282889552a31da7e3d5b7b2ced47bf',
  'HegemonCrypto.NativePrivateSpendQ58CurrentPrequeryEvents',
  '9fde49113509dfab8995863e9384e3a44a33908364844749c9b55b3f27d809ec',
  'acd2a933a45ceba0066200a8ab5bccf42d94e5f96427387fba115afb74967bfb'),
 ('aa47e6a38d51f608a20026a74c00accdda28bfb93e47852c1b9c3b1e875f90e1',
  'HegemonCrypto.NativePrivateSpendQ58CurrentLvcsEventJoin',
  '27e34ae7bd0812204146d0bf41d6227d94e45093318528569ad5cab555fe86a9',
  '696e64040f3e1e5204294bc5ecd93587c03f4b7022aee6f0cd3a35f9a59eb382'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'AuditCurrentAcceptedLeafSupport',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'AuditCurrentLvcsEventJoinEventJoin',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'AuditCurrentOrdinaryRecoveryEventJoin',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'AuditCurrentPiopRestoration',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'AuditCurrentRecoveryGeometryEventJoin',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'HegemonCrypto.NativePrivateSpendQ58CurrentPiopRestoration',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('c866c9e78b19a4eef61a309165aa7506638bf78adc0bf20caf3563081e68d359',
  'HegemonCrypto.NativePrivateSpendQ58CurrentRecoveryGeometry',
  '86667e98502c948bca5e4b44f01b93e074bbd92675197181de79fa400749e0b9',
  '8c134e5b10820fbfc09407d6fe3feb9f921d9cb17c639dd1b6206e4f3b377fad'),
 ('dc5e37c15d416a30e53829241f238a1a66e27c20801b5cdf61d6944fb6fa7395',
  'HegemonCrypto.AuditNativePrivateSpendQ58CurrentScalarEventBridge',
  '6ea0781921f007215ea969610d79c43a895250ea466b850de91aff85e94e272e',
  '1e6a2ab97771f7d6ee81ddb6ac8a3c2be870ee01767afb7e70cd4049da2662e9'),
 ('dc5e37c15d416a30e53829241f238a1a66e27c20801b5cdf61d6944fb6fa7395',
  'HegemonCrypto.NativePrivateSpendQ58CurrentScalarEventBridge',
  '6ea0781921f007215ea969610d79c43a895250ea466b850de91aff85e94e272e',
  '1e6a2ab97771f7d6ee81ddb6ac8a3c2be870ee01767afb7e70cd4049da2662e9'),
 ('5beda294b2943334fab038055d01a0f711f369251d03559561ae009040156fc5',
 'HegemonCrypto.NativePrivateSpendQ58CurrentPiopEvents',
 'bf522b13bbaa8b3cd3453a1fa3cc04b9f5f91b9ef32192590201d5ed1845503c',
 '7ea79138b4667051c8069c18d19b1afdc28dfdcb02bd0bd54075f843e9cdc660'),
 ('5beda294b2943334fab038055d01a0f711f369251d03559561ae009040156fc5',
 'AuditCurrentPiopEventsEventJoin',
 'bf522b13bbaa8b3cd3453a1fa3cc04b9f5f91b9ef32192590201d5ed1845503c',
 '7ea79138b4667051c8069c18d19b1afdc28dfdcb02bd0bd54075f843e9cdc660'),
 ('4da433c2d386122e7ecfcd2740cd9ac7747baa94f92f141e2c8665d58384c2ca',
 'HegemonCrypto.NativePrivateSpendCurrentCanonicalHash',
 '3523095930ca7fb1d742a3b6c053af19a6042f69a6d58ecd0941c0360574aea6',
 'd657a98e020a9f1102882a48650ce342016068730c1fa65e2b73b482871db891'),
 ('e786e14ce0c4f9116ff48fb90234233698b283886351d371ff2b3cbf95f648fd', 'HegemonCrypto.NativePrivateSpendQ58CurrentPiopRecordJoin', '70ee9da37d63755f3fc1069e645d6732b66743171c422441df73750d2b70352c', 'bb87bfe441f88cc1b83d7a9d7f204c0f856a1e4c9ab44ddc5bc7fc19300c8f8f'),
 ('e786e14ce0c4f9116ff48fb90234233698b283886351d371ff2b3cbf95f648fd', 'AuditCurrentPiopRecordJoinEventJoin', '70ee9da37d63755f3fc1069e645d6732b66743171c422441df73750d2b70352c', 'bb87bfe441f88cc1b83d7a9d7f204c0f856a1e4c9ab44ddc5bc7fc19300c8f8f')}
SOURCE_HISTORICAL_IMPORT_VARIANTS = {('SmzaRp05CurrentPcsChunkReadback', 'SmzaRp05PcsWireProjection', 'd0fedc9dbdc95ea89cab147ffd5291ea848b65810dbe387b574bd1e1fc3c0dd4', '972f4f94004073d59b39938a91084fc2d704fdea7dddf2a2675d26241a66d9ec', 'c5d76e2a2d382a56005147f03dc15856a401ac8259f568d07c68c26c8ffbbb91'), ('SmzaRp05CurrentPcsPartialLength', 'SmzaRp05ExecutablePcsClosureStages', '1d01ee2c70bba4176ed18406500d4fe64a098974d4075f13d1504cb1f1ef5b6e', 'a72955bb17ec661f6b94da7d8dd150e3c845ac9844b002abf31822e745235ba5', '3180d4383e0a143063c05c3cdb82390006b0f6733c3ee2aa3988a79fe0d5d4ce'), ('SmzaRp05CurrentStageHeadReadback', 'SmzaRp05CurrentTwelveCalculated', '1e6e505961fe674a764456f9848918f8b6aad93c71725e1d44515f2abed44e37', '566f6fc59469f7d7012708c6e498bee35616dcf2787e6e41820cee7b1ba57a21', '9ebc03b8e29d0270917264e5f9c297de6df1646ad9c582a7c3786370b1d48a6c'), ('SmzaRp05CurrentPcsOpeningView', 'SmzaRp05ExecutablePcsClosureStages', '1d01ee2c70bba4176ed18406500d4fe64a098974d4075f13d1504cb1f1ef5b6e', 'a72955bb17ec661f6b94da7d8dd150e3c845ac9844b002abf31822e745235ba5', '3180d4383e0a143063c05c3cdb82390006b0f6733c3ee2aa3988a79fe0d5d4ce'), ('SmzaRp05CurrentPcsMaskAlgebra', 'SmzaRp05PcsWireProjection', 'd0fedc9dbdc95ea89cab147ffd5291ea848b65810dbe387b574bd1e1fc3c0dd4', '972f4f94004073d59b39938a91084fc2d704fdea7dddf2a2675d26241a66d9ec', 'c5d76e2a2d382a56005147f03dc15856a401ac8259f568d07c68c26c8ffbbb91')}
SOURCE_HISTORICAL_FOUNDATION_SHA256 = "a601c57006ecf9dfe5f58aa6ed2be69aedc330dda04eb4cb9324c80686e5c634"

# Exact genuine CLI0 prefix rows independently included in the final G3 cohort.
# Their pinned later aggregates remain failed; this table never asserts whole PASS.
SOURCE_CURRENT_FAILED_COMPONENT_REAPS |= {('71e89f7e595e8fe669fa953133e2bf33cbd0755e09d6201506f5eab0c48724a0', 'HegemonCrypto.NativePrivateSpendQ58CurrentSourceCompletion', 'fa7805291df7a6a0a50db0cc82d41232103bacf305d34261ddf4b2e3e70270e1', '668223b18e2cb6a8911be0006d6c2935453f21518fb36677ccdc26581bdda2b0'), ('14ee15c1fb23c77bb9cbd85fae14a1e0d8a60924c76e122a503c01e695d562b5', 'HegemonCrypto.NativePrivateSpendQ58CurrentMatrixDynamicMass', '0b309a703aae5fffb325cc6396ca702632cf589761279a350630e3151390fa2a', 'c80baf7dbf73296cf720aae5587d48c98abe34e4174e5832185b3f6a32b6c1a3'), ('95153567faa8030f14df76aab6a0e05e10d5f44553d456cf875dddd9f8839a57', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceTransport', '1214082b3e176dfda48f75f2e1404122cbbe31a905e040e88f181b5d0bcd83e7', '485fd78d082b2bed6bc600f9296893316b5933a2c33742d84ca1dc9fffab2e55'), ('64f9ef13a9e763803f7bf21ccd2dc5e413d9309d27dbfbdf2e4a3bd1d61e3eee', 'HegemonCrypto.NativePrivateSpendQ58CurrentFinalCoefficientNumerics', '7546997c8bc7061b2ba0375a760646d4aca7ba928bf5c82460cba3514142aada', 'f9e5dd51df13452cb5c5dc20a90f181524e025b689d3cabed7d00f5bf1ce6b6a'), ('07d9ca4fe058792655e7d79e818b25e38007b7cb34485e9c7dbac67d5e98736e', 'HegemonCrypto.NativePrivateSpendQ58CurrentConstructorGrouping', 'd879ccc39c810c697717a832aa213321833701ad22ff52b4fac6c7694cc90cff', '7de4b82adaebe387b49a318810cd313cebb65b55d4861dc9b0580bee55cc5561'), ('ff6c684d47b300e81d8cb9260c40ff712907ebec27a8b8221bae64ccc81bd4e0', 'HegemonCrypto.NativePrivateSpendQ58CurrentMatrixDynamicInsertion', '63fb3913af5e551d11b32a8c9547f28da69b9cdf3534daa2edbb0cefe3f8e211', '5df9c0d34d2038504394da225733e7cb3d7a14507b8b208f47fa6ade57e67fca'), ('3b9540c162bf518b8e917830a644745801b2d2636297f3de9ec75e87636cd3f0', 'HegemonCrypto.NativePrivateSpendQ58CurrentFiberMassTransport', 'afe12ecebcaacdfea1d75c7421ba6bf3e103f3fc7d4e4e642afffb9ff65c7abc', '27b69123a91b5fa6df7fa5affb32d9e136b6b6eef8ec79b01a24a92e28180398'), ('431e32f3a4b9252268c2d3c310e0c30b22fd510a603d9204e00dd5c78a44fe2b', 'HegemonCrypto.NativePrivateSpendQ58CurrentSelectedClaimFailureMass', 'dc52de486e13e0ddc69112f80363ac04f70730cfd25a2e7a882a25a612a214e4', '50e601f18b7c80e235665d732f9949b922831202e0f6a546192d2f4cb9bcf797'), ('8a865fe7eeabf7fc825ea7cdbd18ecd738e6ebf37b05babf05ed5782536de0c7', 'HegemonCrypto.NativePrivateSpendQ58CurrentTracePiopMass', 'a579ad2732adceb19cd2f834ddf743593d919b92423e8139853c8f6dbe114604', '0eb8d54d95a66cf7c9965f79bd738fec44e9a1ee66ea3429024d04492c00d177'), ('9e347ddd1478791efbeb34907a7962a3d6dea5d7735399eda3e59c4fec93f948', 'HegemonCrypto.NativePrivateSpendQ58CurrentDecsTraceDensity', '12206bd2cbb8f5034a8b4820ffcc18b7603fd24f588d21de27ad902f339459da', '357bd5bd4ba6c755f7cf4b8a3f829613435053591e927726a9be275e5ab39141'), ('b0d93210a54e3d1b8df5220035794763b5bdfbddc00277f5f69a5639c3e4416a', 'HegemonCrypto.NativePrivateSpendQ58CurrentRawPiopDensity', '8808157e1625978e470defa05faf30962395d91f03030dc121e05bd7bc362b7f', '94d29dc065112e32ffae4f4ce2961ac4535df49bd0b85fe9869a43509da092c0'), ('1e78a6eb7f33491b3aae259f13f9ea6093db012cd5befe006caa1d9dfc6e4cdc', 'HegemonCrypto.NativePrivateSpendQ58CurrentClaimMatrixReadback', '9b93a45c8439ad665d92b075df86f754a047a49d3136e03657d35d8f23881f3b', '717cc484dd34dde2e14a78a7c06881a9a3b53b7aa503fb48df1ea1f0064f30ba'), ('58c8c61a1f9957e8c800ed1e612bcc9113026df2cf5d69e54432ecf540b557e1', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceWitnessCut', 'a1c742f8430c5509b2758ccf6c9916b6daa6aef87d8b4dd68077a2229a2cfc99', '493da96ba4c8813085d78cda7ca116f8a5b22267f23ffffcaebd1a17c60010a7'), ('91aca33802da459783cf1363af3f6b5feb49b3221ca2673448ffd6c1fd8e8d7e', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceInitialized128', '027ca6e0410921e47ceb2b9c63102892244c8fcabd6b3fc34f4277afb9f4a5a2', '57d3cf7f4ba4e26b06d27d32b1d535423e405e5b09064d562db0e3441275fb08'), ('d872aa07ae70c31ce0133e75efc7211b780da68a8fdd4b414b640387673818a9', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceWitnessOrBad', '728961014a846f621a37f3d03537614eb5be438b11dd5d2e0ddce08de814f99d', 'f00c09af5bdd24a127e5d05f68533d0ef1cc393e846bb35877c9386882113e1f'), ('ad121b1e3902855f79a2ed35208310ebfb814aa3ddf9fd47dcdd0768403f60c1', 'HegemonCrypto.NativePrivateSpendQ58CurrentChallengeSourceDisjoint', '2e62857caeeee4d410bcffb103db0263264696395b9ae654138c08efec203ea5', '0d603245fbed6ac35fc61205b7afdf29db872896ebf0bad1fefa109fd5464471'), ('62d74e384bdc5a0000844bb9b9b9e051dfd42badfae3c9ac52cad697f0a4d5a9', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceCut', '37c22b1cb17b43833ae5a47be944aede14ead56b56ef95cd4c6db1ae9fea0980', 'b5dc3f4188a3f22abf98b2b4bba1bb60153f3226dfd9b327c82fb09cb461520d'), ('0883cc7f527b19d02d54449aac04c45248ef197a10d975498644d264d97ab6bc', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedEventJoin', '0eb511d4d716168cb208a73edecf3fb751f984ba4553fc6eb2a335173b9df114', 'c62c860d63eed876a4275ad13054b2a009ba145eb0d16dcc56d05fbef6f8310e'), ('6067763810aa9490286d9114840ec411ef62076661c387cdfbc6fa2f6f0d3a28', 'HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate', '2bcc144f31b3814b0f0a698ae45507979f04e769ff11c4fb43040182f1947c0e', '6ba0ee1071b9d64ff592a2514297756481715daf77f2dfb3d4167b5edee1b5bf'), ('9d0c4c58f022a028202969fd66d0c3e17fa101af5ac6b91ddde9a107be2ba663', 'HegemonCrypto.NativePrivateSpendQ58CurrentGroupedGamma', 'ab5a0c206dd720a8603de43fbddf44ce4ea49c7ccae882c37d2d4b830cb9aac5', 'c65b333950bf5c1e5e0d2a7eadf851f40b4d6bec94ad2b53cea7df2542a9505f'), ('6ace75065918ca0b3dd3b29bde80fede10339e49fd2958963040979d75607a82', 'HegemonCrypto.NativePrivateSpendQ58CurrentRoleEventPhysicalMass', '3400ef087b9afd98e4d703dcbb77b578e8b36ee5c591aa1ceea04d92a38d75fe', '8f0a88a7111b9c6555cb649254822dc99ff9e98e263bc038980a28995a441ccf'), ('a06e8d96451587f3ff95228de2833d802eecae5c1362e2cf86d0db352b8420e0', 'HegemonCrypto.NativePrivateSpendQ58CurrentSameDatabaseEventJoin', '869ccc74d98cecde2bc5bf7b1d6a4655a2cbb9b444b0e07f2260942983f6dd57', 'a374ae0689fe8e2086ec007d1e460271e11c300bd98b94f672e9308f1d2f9d98'), ('b271ff5ce4278ae8878fdc57e6328c0ba5d3c63c417c68ba47f07a1f595c9459', 'HegemonCrypto.NativePrivateSpendQ58CurrentConditionedBranchReadback', 'f794a5d0a862336a7d2392bb6a83222eadff32fa5746a34927d74dd08e715647', '0b0e2c6c3d70ef6ed6b9037f8dabbb53701995d6b58be817928663385fb87e16'), ('6ace75065918ca0b3dd3b29bde80fede10339e49fd2958963040979d75607a82', 'HegemonCrypto.NativePrivateSpendQ58CurrentOpeningVectorInsertion', '3400ef087b9afd98e4d703dcbb77b578e8b36ee5c591aa1ceea04d92a38d75fe', '8f0a88a7111b9c6555cb649254822dc99ff9e98e263bc038980a28995a441ccf'), ('380805c0707b829970fe33349193bce2f46bbcc4b0079892267fa579bb05f9e9', 'HegemonCrypto.NativePrivateSpendQ58CurrentGammaFiber', '4e6ffd1a2214f792f082a1161573d6aba4afcfee906279bc12c38a703711efb9', 'e2f07639562520ace63c8ed8dd925b6fd3e58f47224ac970ed9253a9f6bb1a31'), ('ad0ee18d319ff9e4f17f4259a648a8a0977ea4fd393e54142c7fa96babde71c0', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceArithmeticCollision', '9ee53f72e10c8b4176ad76abb3adb369f65f2e12887d2276dffb8e6b454089a6', 'b9066dd9c9737baa5fa537327ffb8b2abe4c8d74fa2b32383126c797cca053ad'), ('4c79a515ab8c7339bee013588a829aa8d52d800ae5e672b3d3a54b6fff6480a1', 'HegemonCrypto.NativePrivateSpendQ58CurrentDecsDynamicMass', '797d5095de63e96089c8ccfb705cdca639e5789ee1884b4bcea01bcbbc9606e9', 'f90d6515ffdd8100c9e20627365d374b0f918d3f74e52cb571380d89f715e3d4'), ('9d0c4c58f022a028202969fd66d0c3e17fa101af5ac6b91ddde9a107be2ba663', 'HegemonCrypto.NativePrivateSpendQ58CurrentGroupedFiberGamma', 'ab5a0c206dd720a8603de43fbddf44ce4ea49c7ccae882c37d2d4b830cb9aac5', 'c65b333950bf5c1e5e0d2a7eadf851f40b4d6bec94ad2b53cea7df2542a9505f'), ('a06e8d96451587f3ff95228de2833d802eecae5c1362e2cf86d0db352b8420e0', 'HegemonCrypto.NativePrivateSpendQ58CurrentDecsSampleDensity', '869ccc74d98cecde2bc5bf7b1d6a4655a2cbb9b444b0e07f2260942983f6dd57', 'a374ae0689fe8e2086ec007d1e460271e11c300bd98b94f672e9308f1d2f9d98'), ('01310111343d389fad319d72629ff7d045579b75c628ef8f194159894eeee688', 'HegemonCrypto.NativePrivateSpendQ58CurrentActiveBranchClaims', 'd7e4ce56035f053f8cfeb03623bf74417a37fd20ca12ce1badf749a5b0d34866', 'a90c5db1a4020d3b74c774caaffa06d665f950e1130c9e70fd21f803968da330'), ('6cab0754e72bfbe70f460719749ce538480c65878844f86cbf0babf6ff71fadf', 'HegemonCrypto.NativePrivateSpendQ58CurrentMatrixNativeJoin', 'e084f17d3fe3cebc344661370ef994d29c0dede89e171fa0d938fb6bd8adb838', 'a3acb2450ec4ace97324e8c91f655fb952948f0a1d024534a7b1034c27ab2fbc'), ('49451e876a78aa1c7d2b5c5299d650ff48be383658d2192d7e38269128e05c49', 'HegemonCrypto.NativePrivateSpendQ58CurrentMatrixRawOrder', '3537b7724cf25148cb00ea66b52cb64fadc359c5f7f1a0959568d565c4f4d042', '464cdfc189c702e08e7a0830d9c4f7c5d57a5e3c49cb53c9e6248f2afee4b192'), ('8320d05a1d109d0d474b00e688aa47485365f7b1b1ff053f154d2b36b5c61820', 'HegemonCrypto.NativePrivateSpendQ58CurrentSourceTraceReadback', 'd017f2ebff18b368ca44d2bbcb7b782afcf6f59504a8449fda68155230f8271a', '0c4ae30747145b78efddc6599854244b75f5bfa8b91d36f438ca9f2fc0803850'), ('44707aba1442fef796c5b4e111216e4c41b4b9e974b74b2fb5e3533d0f97b120', 'HegemonCrypto.NativePrivateSpendQ58CurrentNativeStageReplay', '5e4d525a4cb769d630b3ab9df79721495dcbc01bfc13105e99519fd6b247205a', '4d06a4fd4a97089a7dc32ed0c48f52effffff6c7ed141e5262149fbb8d441d2f'), ('5f386ed471b2444532fa77c95dc7f2c8eb2d89709461818673aa803c1e950a2a', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceFinal128', 'b99af04d5ff676b70375047bef0055b49dd16f7346c9b2226556d51af76fd8a9', '057073e5c13e77b0ee183afca73cf928cd8da5759b54e33d151dc3d267e1cd8b'), ('ad121b1e3902855f79a2ed35208310ebfb814aa3ddf9fd47dcdd0768403f60c1', 'HegemonCrypto.NativePrivateSpendQ58CurrentClaimReplay', '2e62857caeeee4d410bcffb103db0263264696395b9ae654138c08efec203ea5', '0d603245fbed6ac35fc61205b7afdf29db872896ebf0bad1fefa109fd5464471'), ('5c2caf26fe5f2d7261e2b98b8b1d41ab206eb254576e7a5dcf2bd733e07262e4', 'HegemonCrypto.NativePrivateSpendQ58CurrentDecsLiteralInclusion', '34994cf5bfc9d6fb55502c659e802eae434eada314acaabffc62c0ee2c7e8709', '33c7b561faae89142a7d8bc13ff23196d6b9cbfd040737fa1f8fcb51deff6038'), ('b5bf780b40cf71c105b670520c026e9b397f9ba46a52b8eaa520395f70a5815b', 'HegemonCrypto.NativePrivateSpendQ58CurrentSourceSelectorTransport', 'f08cbbb33bc9bb8a906fb4c3c754c0bcbf563b3f2e49dbed71eba2501333c432', 'b9ae709f977400d863953a5cdb68639ac51612f9bef4fd112bd7e7b88a872724'), ('949f0fb8bab9410e67e8d3ceb2e424cf843ca8933a23acdd4e8057425a48411a', 'HegemonCrypto.NativePrivateSpendQ58CurrentCanonicalSourceClassifier', 'a2f2098add8c9b28863af401e4d0838abdc5cf08ff7509e0dfc4c0bd159dea62', '2524dee5e7706d335d2457d0a8a83cc72a1c384226f27ec7d5514699d9578f10'), ('bb3379d9aa3e6c0a6bed4e16a0632a10445077be12b1c7673af1c6bd0531864a', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceEndpoint', '855f5b025941ea7e05abc34bf063af445029ef7174065cb200b84457c615724c', 'd8fdebac2d5bc5bbed1c723f300dad2cfc0c7bcd79d77746e4e1e715adf96db8'), ('b9da026538e89b3a07989000030bb605e5ba2a51d70902b83ae9c47ce242715c', 'HegemonCrypto.NativePrivateSpendQ58CurrentRouteTransport', 'c1964ffb0e92797dbcca37d583aeaf0d5117a75b6037d5096e87474ea15cff7b', '73d1c66b7b173f5d9bb5f802c5712d37f49e8a3c5c9aa58a59ebf3c2e6bc0edf'), ('1182e55bdbeb71db8c828e126c58fcc50d89afe9fda33584ae5c048769d152f0', 'HegemonCrypto.NativePrivateSpendQ58CurrentComplementReadback', 'a2ad13586f9e5339b450a20bf56bae7e79cc3dbf11579025c49d174d854b4bea', '8240de331c766d145c25aa63ba51ba1691b79262c614e8e39c25e4afc9145d7e'), ('cd0e11d0b74002420319e2ffef4dfceb2c14e1ead010df6b5baca6c2eacb0472', 'HegemonCrypto.NativePrivateSpendQ58CurrentFixedOpeningReplay', 'f45fa3661c578e7be5340b1f8a7e3c873b955d62253ed79b23f29e2d61d7bbd9', 'd3f7cac42b13e6fca95ab166c91be36f2eb1a2473d8708bdac6717fb21000041'), ('243fa7b9989b77ed715907302a1c69a73c872d56d9b262501ea7f1b2edd96b9d', 'HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceArithmetic', 'fe397a7d1386bdc35a1bf266b57cfa554bbf9af319b7f6ff34419abd312a3567', '4062d0ee68757efdb0878ebc4d26ba43b6bd04c5280bbe850471de6f4e5b695a'), ('427e8f6cacdc02ba07443c234ab9569d9b3749230a61d61ee730bfd19a447ab6', 'HegemonCrypto.NativePrivateSpendQ58CurrentSourceRecordExtraction', 'e9315e2c95c366d2c570ccd3c78e549540979ee6a51b4ab1b2acc98b917feabf', '5d73a677fa1b15d6ff4a8b8d6d5b3e5243c8c52a361957627656d7514d701926'), ('8a2e620528dcdc6b89a76d170aa2a82bee83d62a277fda9bf475bc69fb225a74', 'HegemonCrypto.NativePrivateSpendQ58CurrentDecsSourceJoin', '0f8fc340bd6c48a53c08889ea01b993af301d5b637640e5fd7452952258bcd65', 'e8e9c941809fd3377bf22839688c9d3f526cb37bdc15cf8398cbeb3de681fd14'), ('dc74d69cc214288c71b3ab13397c78ba01449128746606b61d072ed72fff7028', 'HegemonCrypto.NativePrivateSpendQ58CurrentRoleInsertion', '324c88731ceba4b58a16ce95fe0fc8782ebc739a44d35204bffaef18a28e1025', '3dbd5b9f87e20df3d27b5fba8fc8d9cf94d65881296af3c5c846ca7bac8711bb'), ('0b468d776c90443d6931f7cf105a191c2cba151ac4c62a103b53acb55b449859', 'HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel', '16c943fca7c5b7a4b3f993b16464ee941a46fdf94b2f5519b3e37192c66cf92a', '8205615ad76a4343782b1a0b17efeeb6db9d7fe6689aa87379e641c27c528f17'), ('6e40919d064890420d5a691b2755f78bf827e3acd4ce589fedeb8e2123a5794e', 'HegemonCrypto.NativePrivateSpendQ58CurrentFullLogReadback', 'a54515c73bc39a0738762f92576a3278bac88ae5c15493382e6a313a2c91eae0', '130e3bf9c0a089933048da4a17cea4367bbc0f860431cde8c02cbf0794ef01a6')}
# Only these two authenticated naturally completed full-pass ROOT reap formats.
SOURCE_CURRENT_FULL_PASS_REAPS = {'119dad1064135e263316efe1f6c69eb7eb730f1cdfff49cc87063edde8fe2b8a': {'plan': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g3-final-witness-mass-canonical-launch-prep329/PLAN.json', 'bytes': 196671, 'sha256': '30d75cb90a2bca0a1c615419d81393564024651522a99966dc1497159da9e26e'}, 'actual_checks': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g3-final-witness-mass-check329/actual-checks.json', 'bytes': 8634, 'sha256': '6d109ea2012ffac1ca655a49dbe0913fd0c0d4faadbbc9ad427c662fe4b00746'}, 'result': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g3-final-witness-mass-check329/result.json', 'bytes': 1003, 'sha256': 'f866ac9162610bdc0172143107da8a7f6e0406a74dc7404e574c37e3e252283c'}, 'guard': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g3-final-witness-mass-canonical-launch-prep329/GUARD.json', 'bytes': 928, 'sha256': 'c8c6aa6598de6df8e7811b903dd58141ac932e385d9e0c2e96a6cafea6c8364d'}, 'supervisor': {'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g3-final-witness-mass-canonical-launch-prep329/SUPERVISOR.json', 'bytes': 2959, 'sha256': '250a7eb04b77673ba825be29e350ad219408a329abfaf603435ada8784fde298'}}, 'cefea54f0cad7c625f16f6d314ef53e3cd887a71de7442533d2075660ae0380e': {'plan': {'bytes': 218234, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g7-reviewed-source-map-input5/PLAN.json', 'sha256': '444c69f0c9604b4325210b83ccbc0d30aaf832ac2391e1b0ee68609c313915a1'}, 'actual_checks': {'bytes': 70575, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g7-reviewed-source-map-check5/actual-checks.json', 'sha256': '7af0c24ffb681e941fcbea8f7dddec9aa8e326dc70b3629ffc121019332d4cc4'}, 'result': {'bytes': 1459, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/root-g7-reviewed-source-map-check5/result.json', 'sha256': '53126c05da48d223abfc4afbb5fdeffdaedb95cba8bf450cbc61e3e6f228f857'}, 'guard': {'bytes': 963, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g7-root-native-floor20-launch01/GUARD.json', 'sha256': '8ae03eaf92d4874abed58e036a64531c77e33b2a2043c91d16c176ae1b9d43e8'}, 'supervisor': {'bytes': 3027, 'path': '/Users/pldd/Projects/Reflexivity/Hegemon/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/g7-root-native-floor20-launch01/SUPERVISOR.json', 'sha256': '82a6fd755be6a614d713ff7351e6bbbd5b5c90c96cd390d6bd870b29d7aa8954'}}}

# Closed original25 provenance completion; raw native records remain unchanged.
SOURCE_ORIGINAL_SOURCE_COMPONENTS.update({'Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives': 'e6ec2e4aa93b4eb41fa12ef3ef33e0ce0f47850fedfe50fc94ca55975f2b811f',
 'HegemonCrypto.NativeHtlcGraphProducts': '8c48ad424f79c134a5e900591306fa76fdbd7401d1098281e1dccc48e9e53624',
 'HegemonCrypto.NativeLaunchConstraintAdapterBridge': 'ac913ee225e3d8bb0d456c148cbbbf52817c459211b744393d0a4331355645b4',
 'HegemonCrypto.NativeLaunchSparseCoalescing': 'dfbb1931fa39c4d018681f24c5f7421016f63277b5ca917c0916403a4afc9208',
 'HegemonCrypto.NativePrivateSpendArithmeticTopology': 'aaf0908622911470de28f43b74037c3d8a65d26f8176e70d97ed92504f40f06a',
 'HegemonCrypto.NativePrivateSpendCompffPrimitiveGames': '8d2c8cc7aba57a833abb809822bcc32d3d884126955481127deb83c23978bcd8',
 'HegemonCrypto.NativePrivateSpendCsrCertificate': '130dcdc2e587166e37cf24627be412138f7a42ebc25910f354659678ebc57b8c',
 'HegemonCrypto.NativePrivateSpendCurrentRoleGames': '8450625fbae17d19225dc9ac7fa9b84d1dec202c80ca19eb4ea65083cac35d1f',
 'HegemonCrypto.NativePrivateSpendCurrentSourceCallContract': '707300ce537c77475f07ef6e78aef3f55e41a7f482f8460a8ea0a2dba552d37c',
 'HegemonCrypto.NativePrivateSpendG1SourceComposition': '21243a0061df0c3e2530cbe4a31a92071bcb2d1741b7768016c51b0ee36a67cd',
 'HegemonCrypto.NativePrivateSpendHtlcRecipient': '532c2c575c8702e48bdf298fef3691a4cdc76500368c8453a34bd2b89845f821',
 'HegemonCrypto.NativePrivateSpendLocalSemantics': 'b3691995936f9e48151bccad30d8a2c1f0718f281c2762e7a1945ab26d51c70d',
 'HegemonCrypto.NativePrivateSpendMerkleContinuation': 'c2daecf78951cfc0460d585caae543023cbb5d563f908cdc39cc9b5321aae4bd',
 'HegemonCrypto.NativePrivateSpendPackedLowering': 'b7e0008e850eb89047404a57b0c55fe2b6dc37cb7011d50310959dafb0cd2ea2',
 'HegemonCrypto.NativePrivateSpendRoleBridge': '35069b47b6fb8df737a4f1958de8aa4a57eec77e8d162c8a630c7501708bca18',
 'HegemonCrypto.NativePrivateSpendSelectedNullifier': 'd9540bb8f2410cee495610b70c5e8fe68a7b3ac487f7ce03b006e1d383b430f2',
 'HegemonCrypto.NativePrivateSpendSpongeBridge': '92fd6fff9a200fe3ecc4b48fa39b5173ce5cf6105e7e4e59053243454de27176',
 'HegemonCrypto.NativePrivateSpendSymbolicBridge': '6e68a78dce4d79bf17cf1cffe1baed7064eadfeaef2a7d28c5ec18eb65187cfb'})
SOURCE_LEGACY_COMPONENT_REAPS.update({'5eab798f160405ec61a6846a5ad01983bcec06151b4772fe13b6f4ec1e444119': ('HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter',
                                                                      '73c7698084b1c73794526df7fbeb6f23d37fb7c68711defb6fa99139e91415b2',
                                                                      '23de8025039667c66921e9a75b339b7d6033ec9ea330f825c537657a3607346e'),
 '9e67dd990eede922f68b78f3ad503b614b6a8a7e452279a244dcd53deab4de2a': ('HegemonCrypto.NativePrivateSpendQ58CurrentScalarChecks',
                                                                      'a751d18bbe1d6b37a7032036d9449e8fe942ea1655419c72de7631b677ddf44f',
                                                                      '92cf72c00b3194271aa686e77519fd757c82ffc970f4e58c0afe2d181d4f2cbc')})

# Exact original453 individual CLI0 legacy receipt schemas; aggregate states stay unchanged.
SOURCE_LEGACY_COMPONENT_REAPS.update({'320d1849450b4c8fa7ee725162d7810231aaa7f87d08969bb84790cb25f13586': ('HegemonCrypto.NativePrivateSpendQ58CurrentDecodedRelation',
                                                                      'cc077011db457ae0de61c4b1e98b6220a3023202263867c166bcbb9526de7cb5',
                                                                      '11d627f3eca6d7a479d822dda842be21793ce4029961fbe6a6dac9af08ea5cf3'),
 '577cdc14ab1b33ef864eb729128e13bffa7a5ebc894ec94da1a1b10b56a296fd': ('HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier',
                                                                      'df3c8161ee7ad5762f52a71b7a7cb2d6436d042af8936ed5dfdd82d314155443',
                                                                      '2931525ba62707eebb140a9fe431c276fe3e58d6ac6980f1482dd71a0ffe1310'),
 '8ad33227bc77b4b2e67ccd6a656110d891dd46f3c1e5dbdea5ca3732380f7a4d': ('HegemonCrypto.NativePrivateSpendQ58CurrentScalarRowFactorization',
                                                                      '6fa0a3c5b9b8bfd8a7abeb23385054416e534c3c33fcfec5e5748571add46c3b',
                                                                      '5936cf10b845461c04a41e7d96f6299b95b9496a69d10f2dd8caa07bfc149fab'),
 'a90d9ae871a14d0e28b4f90dc83f10aa84d77d9e8652fc3f0d4e3ca4b16636d1': ('HegemonCrypto.NativePrivateSpendQ58CurrentOpeningDensity',
                                                                      '48b47443e8b4cc864800dd88ec6c8aa5861ae920e8823b2fe5053dde1c3f4c61',
                                                                      'e402346f4025a46b113d9e1349080b77d26cfbaff600bda182fb6e47cf1239a7')})

def current_checked_reuse_entry(entry):
    """Authenticate one source-approved object using its original actual receipt."""
    exact_keys(entry, ("module", "source", "object", "import_object_sha256", "producer"), "current object reuse entry")
    module, producer = entry["module"], entry["producer"]
    require(isinstance(module, str) and module, "current reuse module missing")
    source, obj = pin(entry["source"], "current reused source"), pin(entry["object"], "current reused object")
    imports = entry["import_object_sha256"]
    require(isinstance(imports, dict), "current reused imports missing")
    declared = {name for line in source.read_text().splitlines() if line.startswith("import ")
                for name in line[7:].split() if name.startswith(("Hegemon", "Q38", "Mca", "Smza", "SmallWood"))}
    require(set(imports) == declared, "current reuse omits or adds project source imports")
    if producer.get("kind") == "strict8_component":
        exact_keys(producer, ("kind", "check", "completion"), "actual current component")
        check = producer["check"]
        require(check.get("module") == module and check.get("source") == entry["source"] and
                check.get("object") == entry["object"], "component identity changed")
        rows = load(pin(check["provenance"], "original component native receipt list"))
        row = actual_row(rows, module)
        log = strict_native_row(check, row)
        plan = load(pin(check["plan"], "original frozen component plan"))
        require(plan.get("schema") == "hegemon.frozen-lean-delta-check.v1" and
                plan.get("compiler_sha256") == LEAN_SHA256 and plan.get("flags") == list(STRICT_FLAGS),
                "component compiler changed")
        inputs = [item for item in plan.get("files", []) if item.get("module") == module]
        require(len(inputs) == 1 and inputs[0].get("sha256") == entry["source"]["sha256"],
                "component source not in plan")
        relative = module.replace(".", "/")
        require(row.get("cwd") == plan["work"] + "/sources" and
                row["source"] == plan["work"] + "/sources/" + relative + ".lean" and
                row["object"] == plan["work"] + "/objects/" + relative + ".olean" and
                row["argv"][2] == plan["stack_shim"] and
                digest(evidence_file(inputs[0]["path"], entry["source"]["sha256"])) == entry["source"]["sha256"],
                "component scope changed")
        expected = check.get("standard_axiom_roots", {})
        if expected:
            parsed = audit_readouts(log, expected)
            scope = (producer["completion"]["sha256"], module, check["plan"]["sha256"], check["provenance"]["sha256"])
            require((parsed == row.get("standard_axioms") or
                     row.get("standard_axioms") is None and scope in SOURCE_CURRENT_FAILED_COMPONENT_REAPS) and
                    set(expected) == set(inputs[0].get("audit_roots", [])), "component audit roots changed")
        else:
            require(log == "" and not row.get("standard_axioms") and not inputs[0].get("audit_roots"),
                    "component output not empty")
        original_checks = plan["work"] + "/actual-checks.json"
        terminal = pin(producer["completion"], "original terminal reap")
        require(pin(check["provenance"], "original receipts") == evidence_file(original_checks, check["provenance"]["sha256"]) and
                terminal == evidence_file(plan["work"] + "/ROOT-TERMINAL-REAP.json", producer["completion"]["sha256"]),
                "component completion/provenance scope mismatch")
        completion = load(terminal)
        legacy = SOURCE_LEGACY_COMPONENT_REAPS.get(producer["completion"]["sha256"])
        if (producer["completion"]["sha256"], module, check["plan"]["sha256"], check["provenance"]["sha256"]) in SOURCE_CURRENT_FAILED_COMPONENT_REAPS:
            legacy = (module, check["plan"]["sha256"], check["provenance"]["sha256"])
        if legacy is not None:
            require(legacy == (module, check["plan"]["sha256"], check["provenance"]["sha256"]),
                    "historical terminal scope changed")
            # Its exact pinned bytes preserve original schema, keys, types and failure.
        elif producer["completion"]["sha256"] in SOURCE_CURRENT_FULL_PASS_REAPS:
            expected_completion = SOURCE_CURRENT_FULL_PASS_REAPS[producer["completion"]["sha256"]]
            require(completion.get("schema") == "hegemon.root-owned-terminal-reap.v1" and
                    completion.get("fully_reaped") is True and completion.get("natural_completion") is True and
                    completion.get("aggregate_pass") is True and completion.get("diagnostic_only") is False and
                    completion.get("native_active") is False and completion.get("native_running") is False and
                    all(type(completion.get(k)) is int and completion[k] == 0
                        for k in ("terminal_exit_code", "guard_exit_code", "guard_WARN", "owner_signal")),
                    "exact full-pass terminal state changed")
            require(all(completion.get(k) == value for k, value in expected_completion.items()) and
                    completion["plan"] == check["plan"] and completion["actual_checks"] == check["provenance"] and
                    same_evidence_file(pin(completion["result"], "full-pass result"), plan["work"] + "/result.json",
                                       completion["result"]["sha256"]), "exact full-pass descriptor joins changed")
            result = load(pin(completion["result"], "full-pass result"))
            guard = load(pin(completion["guard"], "full-pass guard"))
            supervisor = load(pin(completion["supervisor"], "full-pass supervisor"))
            require(result.get("schema") == "hegemon.frozen-lean-delta-result.v1" and
                    result.get("status") == "SCOPED_KERNEL_PASS" and
                    result.get("plan_sha256") == check["plan"]["sha256"] and
                    result.get("actual_checks_sha256") == check["provenance"]["sha256"] and
                    type(guard.get("exit_code")) is int and guard["exit_code"] == 0 and
                    guard.get("stop_reason") == "none" and guard.get("owner_signal") == 0 and
                    supervisor.get("guard_receipt") == guard and supervisor.get("reason") == "completed" and
                    supervisor.get("guard_exit_code") == 0 and supervisor.get("owner_signal") == 0 and
                    supervisor.get("test_only") is False, "exact full-pass guarded result changed")
        elif completion.get("schema") == "hegemon.root-terminal-reap.v1":
            result_path = plan["work"] + "/result.json"
            require(completion.get("natural_completion") is True and completion.get("native_active") is False and
                    type(completion.get("terminal_exit_code")) is int and completion["terminal_exit_code"] == 0 and
                    completion.get("actual_checks") == original_checks and
                    completion.get("actual_checks_sha256") == check["provenance"]["sha256"] and
                    completion.get("result") == result_path, "terminal completion joins changed")
            hexadecimal(completion.get("result_sha256"), 64, "terminal result hash")
            result_file = evidence_file(result_path, completion["result_sha256"])
            require(digest(result_file) == completion["result_sha256"], "terminal result bytes changed")
            result = load(result_file)
            require(result.get("schema") == "hegemon.frozen-lean-delta-result.v1" and result.get("status") == "SCOPED_KERNEL_PASS" and
                    result.get("plan_sha256") == check["plan"]["sha256"] and
                    result.get("actual_checks_sha256") == check["provenance"]["sha256"], "terminal plan/provenance joins changed")
        else:
            require(completion.get("reaped") is True and type(completion.get("exit_code")) is int and
                    type(completion.get("natural_completion")) is bool, "legacy aggregate not reaped")
        # The selected native CLI0 row is evidence. Never relabel the aggregate.
        available = {item["relative"].removesuffix(".olean").replace("/", "."): item["sha256"]
                     for item in plan.get("retained_objects", [])}
        for earlier in rows:
            if earlier is row:
                break
            require(type(earlier.get("exit_code")) is int and earlier["exit_code"] == 0,
                    "component has a failed earlier producer")
            available[earlier["module"]] = earlier["object_sha256"]
        require(all(available.get(name) == sha for name, sha in imports.items()),
                "component import object changed")
        original_source, original_object = row["source"], row["object"]
    elif (producer.get("kind") == "original_source_component" and
          producer.get("shape") == "original_bound_cli_result"):
        require(SOURCE_ORIGINAL_SOURCE_COMPONENTS.get(module) == canonical_hash(entry),
                "bound historical component is outside the exact reviewed selection")
        exact_keys(producer, ("kind", "shape", "provenance", "row_label", "compiler",
                             "log", "guard", "bound_result", "frozen_plan"),
                   "original bound CLI producer")
        require(producer["row_label"] == module, "bound CLI row label changed")
        rows = load(pin(producer["provenance"], "original raw CLI receipts"))
        row = actual_row(rows, module)
        exact_keys(row, ("module", "argv", "exit_code", "object_sha256", "log_sha256"),
                   "original unmodified CLI row")
        require(type(row["exit_code"]) is int and row["exit_code"] == 0,
                "original bound CLI did not pass")
        frozen = load(pin(producer["frozen_plan"], "original bound frozen plan"))
        bound = load(pin(producer["bound_result"], "original bound result"))
        guard = load(pin(producer["guard"], "original bound guard"))
        compiler = pin(producer["compiler"], "original bound compiler")
        # Exact finite original cohorts: tag, guard exit, result, plan, guard.
        cohorts = {
            "2cb52375182a12f6a62ac6c91896ce3bed13740f82a2cff83f4ec61cee2cf256": (
                "compression02", 1,
                "b1dbfc6400265ff86a717c3e6453b2202d98520c3b874bf765b8fa3e211a3a71",
                "c468599fe985d76441ed366739e07431c03e4d074e99503270ac5ea07bce376d",
                "7c97b226f2d518379c1ce98647be4a67e82a75bb9fe0136543fd2499fbfb6999"),
            "fed345c006f5772f0912d68d2968b9a7bd3ed384c1f3fd7acd66d232528922d3": (
                "compression04", 0,
                "b1dbfc6400265ff86a717c3e6453b2202d98520c3b874bf765b8fa3e211a3a71",
                "7acdc910b1b62fe0a04c8900c070cff3130d920464e52b6f04d32ede1e5ed879",
                "e5cd64a1845f5d7ab6e25face2947a10c8ead21a1eb1e1e82113fcfb48894a0d"),
            "ec3fb8cf9413eec3b24593f8bd45ec0ed2e504c86642920f1d374bc3aca2bc1c": (
                "role01", 0,
                "81c1c639ac72d13b9897360ae24a0fc0be66e4dd00d16c233d23c7c13f789c73",
                "5a0c143c7f6434529355a7e8db0d5d5a31b8cc01c41c3b687068498070821d27",
                "83c1c6ef90808470d4f7b99691c3dca1c6258e1553c2ab2f2881747fbf51d968"),
        }
        cohort = cohorts.get(producer["provenance"]["sha256"])
        require(cohort is not None, "unapproved original bound CLI cohort")
        tag, guard_exit, result_sha, plan_sha, guard_sha = cohort
        require((producer["bound_result"]["sha256"], producer["frozen_plan"]["sha256"],
                 producer["guard"]["sha256"]) == (result_sha, plan_sha, guard_sha),
                "original bound cohort descriptors changed")
        require(type(guard.get("exit_code")) is int and guard["exit_code"] == guard_exit and
                guard.get("stop_reason") == "none" and type(guard.get("owner_signal")) is int and
                guard["owner_signal"] == 0 and guard.get("warn_observations") == 0,
                "original bound guard completion changed")
        flags = ["-j1", "-DElab.async=false", "-DwarningAsError=true",
                 "-DautoImplicit=false", "-DmaxHeartbeats=0"]
        require(frozen.get("compiler") == bound.get("compiler") and
                frozen.get("compiler_sha256") == bound.get("compiler_sha256") ==
                producer["compiler"]["sha256"] == LEAN_SHA256 and
                frozen.get("source_root") == bound.get("source_root") and
                frozen.get("flags") == bound.get("flags") == flags,
                "original bound compiler/flags/source root changed")
        argv = row["argv"]
        require(isinstance(argv, list) and len(argv) == 9 and
                argv == [frozen["compiler"], *flags, "-o", argv[-2], argv[-1]] and
                same_evidence_file(compiler, argv[0], LEAN_SHA256),
                "original bound CLI argv changed")
        original_source, original_object = argv[-1], argv[-2]
        original_work = producer["provenance"]["path"].rsplit("/", 1)[0]
        require(original_source == frozen["source_root"] + "/formal/crypto/" +
                module.replace(".", "/") + ".lean" and
                original_object == original_work + "/objects/" +
                module.replace(".", "/") + ".olean" and
                guard.get("command", [])[-2:] == ["--work", original_work],
                "original bound module/work scope changed")
        require(row["object_sha256"] == entry["object"]["sha256"] and
                row["log_sha256"] == producer["log"]["sha256"] and
                same_evidence_file(obj, original_object, entry["object"]["sha256"]) and
                same_evidence_file(source, original_source, entry["source"]["sha256"]) and
                same_evidence_file(pin(producer["log"], "original bound CLI log"),
                                   original_work + "/" + module + ".log", row["log_sha256"]),
                "original bound source/object/log identity changed")
        require(pin(producer["log"], "original empty bound CLI log").read_text() == "",
                "original bound CLI emitted output")
        require(bound.get("status") == "SCOPED_KERNEL_PASS" and
                bound.get("production_authorized") is False,
                "original bound result status changed")
        if tag == "compression02":
            require(frozen.get("schema") == "hegemon-compff-current-delta-check-v1" and
                    bound.get("schema") == "hegemon-compff-current-delta-check-complete-overlay-v4",
                    "original compression02 result/plan schema changed")
            joined = actual_row(bound.get("previous_actual_passes"), module)
            require(all(joined.get(k) == value for k, value in row.items()) and
                    joined.get("source") == original_source and
                    joined.get("source_sha256") == entry["source"]["sha256"] and
                    joined.get("object") == original_object and
                    joined.get("log") == original_work + "/" + module + ".log",
                    "original retained compression02 row binding changed")
            bound_pins = {p["path"]: p["sha256"] for p in bound.get("pins", [])}
            require(all(bound_pins.get(producer[k]["path"]) == producer[k]["sha256"]
                        for k in ("provenance", "guard", "frozen_plan")),
                    "original compression02 result/input joins changed")
            input_pins = frozen.get("pins", [])
            original_inputs = frozen.get("reused_modules", [])
        elif tag == "compression04":
            require(frozen.get("schema") == bound.get("schema") ==
                    "hegemon-compff-current-delta-check-complete-overlay-v4" and
                    actual_row(bound.get("checks"), module) == row and
                    all(bound.get(k) == value for k, value in frozen.items() if k != "status"),
                    "original compression04 frozen plan/result row changed")
            input_pins = frozen.get("pins", [])
            original_inputs = frozen.get("complete_overlay_links", [])
        else:
            require(frozen.get("schema") == bound.get("schema") ==
                    "hegemon-current-owner-role-one-module-check-v1" and
                    actual_row(bound.get("checks"), module) == row and
                    bound.get("frozen_plan_sha256") == producer["frozen_plan"]["sha256"] and
                    same_evidence_file(pin(producer["frozen_plan"], "original role plan"),
                                       bound.get("frozen_plan_path"),
                                       producer["frozen_plan"]["sha256"]),
                    "original role frozen plan/result row changed")
            # The original skinny role plan's completed result retains the
            # contemporaneous complete input pins and overlay; no reconstruction.
            input_pins = bound.get("pins", [])
            original_inputs = bound.get("complete_overlay_links", [])
        source_pins = [p for p in input_pins if p.get("path") == original_source]
        require(len(source_pins) == 1 and source_pins[0].get("sha256") ==
                entry["source"]["sha256"], "original frozen source pin changed")
        require(isinstance(original_inputs, list), "original import snapshot missing")
        available = {p["module"]: p["object_sha256"] for p in original_inputs}
        for earlier in rows:
            if earlier is row:
                break
            require(type(earlier.get("exit_code")) is int and earlier["exit_code"] == 0,
                    "original bound CLI has a failed earlier producer")
            if "module" in earlier:
                available[earlier["module"]] = earlier["object_sha256"]
        require(all(available.get(name) == value for name, value in imports.items()),
                "original bound CLI import snapshot changed")
        # Only the selected original row passed. Compression02 guard exit1 and
        # its later failed row remain unchanged; no aggregate is promoted.
    elif producer.get("kind") == "original_source_component":
        require(SOURCE_ORIGINAL_SOURCE_COMPONENTS.get(module) == canonical_hash(entry),
                "historical source component is outside the exact reviewed selection")
        exact_keys(producer, ("kind", "shape", "provenance", "row_label", "compiler", "log", "guard"),
                   "original source component producer")
        original = load(pin(producer["provenance"], "original historical native receipts"))
        # The enclosing canonical-entry hash admission and exact seven keys stay mandatory.
        if producer["shape"] == "original_model_compile_guard":
            root = RECORDED_PROJECT_ROOT + "/.agent/launchpad-2026-10-03/resume45/feed-forward/formal-regression"
            expected_module = "Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives"
            original_source = root + "/formal/lean/Hegemon/Transaction/Poseidon2V8LeftFeedForwardPrimitives.lean"
            original_object = root + "/objects/Hegemon/Transaction/Poseidon2V8LeftFeedForwardPrimitives.olean"
            original_compiler = "/Users/pldd/.elan/toolchains/leanprover--lean4---v4.32.2/bin/lean"
            require(module == producer["row_label"] == expected_module and isinstance(original, dict),
                    "original model identity changed")
            require(same_evidence_file(pin(producer["provenance"], "original model generation receipt"),
                                       root + "/audits/generation-receipt.json", producer["provenance"]["sha256"]),
                    "original model receipt path changed")
            model, compiled = original.get("model"), original.get("model_compile_receipt")
            require(isinstance(model, dict) and isinstance(compiled, dict) and
                    model.get("path") == original_source and model.get("source_sha256") == entry["source"]["sha256"] and
                    model.get("object_sha256") == entry["object"]["sha256"] and
                    original.get("compiler_sha256") == producer["compiler"]["sha256"] == LEAN_SHA256 and
                    compiled.get("path") == root + "/audits/model-compile.guard.json" and
                    compiled.get("sha256") == producer["guard"]["sha256"],
                    "original model source/object/compiler/guard join changed")
            compiler = pin(producer["compiler"], "original model compiler")
            guard_file = pin(producer["guard"], "original model compile guard")
            require(same_evidence_file(compiler, original_compiler, LEAN_SHA256) and
                    same_evidence_file(guard_file, compiled["path"], compiled["sha256"]) and
                    same_evidence_file(source, original_source, entry["source"]["sha256"]) and
                    same_evidence_file(obj, original_object, entry["object"]["sha256"]),
                    "original model physical paths changed")
            guard = load(guard_file)
            require(guard.get("schema") == "hegemon.step4.owned-compile.resume45.v1" and
                    guard.get("command") == ["env", "LEAN_PATH=" + root + "/objects",
                        "LEAN_SYSROOT=/Users/pldd/.elan/toolchains/leanprover--lean4---v4.32.2",
                        original_compiler, "-DwarningAsError=true", "-DmaxHeartbeats=0", "-o",
                        original_object, original_source] and
                    type(guard.get("exit_code")) is int and guard["exit_code"] == 0 and
                    guard.get("stop_reason") == "none" and guard.get("no_heap_or_runtime_cap") is True and
                    all(type(guard.get(k)) is int and guard[k] == 0 for k in ("warn_observations", "owner_signal")),
                    "original model command or natural completion changed")
            require(same_evidence_file(pin(producer["log"], "complete original model stdout"),
                                       root + "/audits/model-compile.log", producer["log"]["sha256"]) and
                    pin(producer["log"], "original model stdout").read_bytes() == b"",
                    "original model stdout changed")
            # This is contemporaneous metadata, not fabricated native receipt fields.
            dependency_hash = "b0b4a46c9ca821b0f1a7300237cc8e0ec5fd1f5768e0f60589c4732710c8c72d"
            dependency_file = evidence_file(root + "/audits/dependency-pins.json", dependency_hash)
            require(digest(dependency_file) == dependency_hash, "original model dependency metadata changed")
            dependencies = load(dependency_file)
            require(isinstance(dependencies, list), "original model dependency list missing")
            selected = [row for row in dependencies if row.get("module") == "Hegemon.Transaction.Poseidon2V8SemanticSpecification"]
            require(len(selected) == 1, "original model dependency missing or duplicated")
            dependency = selected[0]
            require(imports == {"Hegemon.Transaction.Poseidon2V8SemanticSpecification":
                                "31192febc55be7008f71c42509adbcaf474704c0a2d6ce57aba92c09e6013a42"} and
                    dependency.get("olean_sha256") == imports[dependency["module"]] and
                    dependency.get("compiler_sha256") == LEAN_SHA256 and
                    dependency.get("private_symlink") == root + "/objects/Hegemon/Transaction/Poseidon2V8SemanticSpecification.olean" and
                    digest(evidence_file(dependency["olean"], dependency["olean_sha256"])) == dependency["olean_sha256"] and
                    digest(evidence_file(dependency["source"], dependency["source_sha256"])) == dependency["source_sha256"],
                    "original model declared import/LEAN_PATH authority changed")
            require(digest(evidence_file(original_source, entry["source"]["sha256"])) == entry["source"]["sha256"] and
                    digest(evidence_file(original_object, entry["object"]["sha256"])) == entry["object"]["sha256"],
                    "original model bytes changed")
            # Historical flags and physical evidence remain historical; no strict8 claim.
            return {"source": original_source, "source_sha256": entry["source"]["sha256"],
                    "object": original_object, "object_sha256": entry["object"]["sha256"],
                    "import_object_sha256": imports}
        if producer["shape"] == "original_native_receipt_list":
            require(producer["guard"] is None, "historical producer shape changed")
            row = actual_row(original, producer["row_label"])
        else:
            require(producer["shape"] == "original_g5_compile" and isinstance(original, dict),
                    "historical compile shape changed")
            row = actual_row(original.get("modules"), producer["row_label"])
            require(row.get("reused") is False, "original G5 producer was not actual")
            guard = load(pin(producer["guard"], "original G5 natural completion"))
            require(type(guard.get("exit_code")) is int and guard["exit_code"] == 0 and
                    guard.get("stop_reason") == "none" and guard.get("owner_signal") == 0,
                    "original G5 compile was stopped")
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0 and
                row.get("module", row.get("label")) == module, "historical producer did not pass")
        argv = row.get("native_argv", row.get("argv", row.get("command")))
        compiler = pin(producer["compiler"], "original historical compiler")
        require(isinstance(argv, list) and len(argv) >= 4 and argv[-3] == "-o" and
                same_evidence_file(compiler, argv[0], producer["compiler"]["sha256"]) and producer["compiler"]["sha256"] == LEAN_SHA256,
                "historical original argv/compiler changed")
        original_source, original_object = argv[-1], argv[-2]
        require(row.get("source_sha256") == entry["source"]["sha256"] and
                row.get("object_sha256", row.get("olean_sha256")) == entry["object"]["sha256"] and
                row.get("log_sha256") == producer["log"]["sha256"] and
                same_evidence_file(pin(producer["log"], "original complete historical output"),
                                   row.get("log", row.get("log_path")), producer["log"]["sha256"]),
                "historical source/object/log identities changed")
        require(pin(producer["log"], "historical producer output").read_text() == "",
                "historical producer output not empty")
        # These import names and selected cache pins are independently reviewed
        # source closure metadata. They are not invented historical native snapshots.
    elif producer.get("kind") == "pr205_package_object":
        exact_keys(producer, ("kind", "reuse"), "original PR205 package producer")
        require(producer["reuse"].get("sha256") == RETAINED_REUSE_SHA256,
                "package predecessor is not source-approved")
        reuse = load(pin(producer["reuse"], "original reviewed package authority"))
        require(reuse.get("schema") == "hegemon.g5-minimal-coherent-dependency-reuse.v1" and
                reuse.get("decision") == "GO" and reuse.get("compiler", {}).get("sha256") == LEAN_SHA256,
                "original package authority changed")
        compiler = pin(reuse["compiler"], "original package compiler")
        package = reuse["unchanged_package_authority"]
        state_file = pin(package["state"], "original package state")
        manifest_file = pin(package["manifest"], "original package source manifest")
        root = RECORDED_PROJECT_ROOT + "/formal/rp05"
        require(same_evidence_file(state_file, root + "/build/state.json", package["state"]["sha256"]) and
                same_evidence_file(manifest_file, root + "/source-manifest.json", package["manifest"]["sha256"]), "original package paths changed")
        state, manifest = load(state_file), load(manifest_file)
        receipt = load(pin(package["actual_final_build"], "actual successful original package build"))
        require(receipt.get("schema") == "hegemon.rp05.accepted-role-labels-affected-package-build.v1" and
                receipt.get("status") == "PASS" and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0 and
                receipt.get("runner_and_sources_stable") is True and
                receipt.get("package_state_post_sha256") == package["state"]["sha256"] and
                receipt.get("input_hashes_post", {}).get(root + "/build/state.json") == package["state"]["sha256"] and
                receipt["input_hashes_post"].get(root + "/source-manifest.json") == package["manifest"]["sha256"],
                "original package result/state/source join changed")
        require(same_evidence_file(pin(package["actual_build_log"], "complete original package build log"),
                                   receipt.get("log"), package["actual_build_log"]["sha256"]) and
                package["actual_build_log"]["sha256"] == receipt.get("log_sha256"), "original package log changed")
        for path, sha in receipt["input_hashes_post"].items():
            require(digest(evidence_file(path, sha)) == sha, "original package producer input changed")
        require(state.get("schema") == "hegemon.rp05.build-state.v1", "package state schema changed")
        records = [v for v in manifest.get("sources", []) if v.get("module") == module]
        require(len(records) == 1, "package module missing or duplicated")
        record, item = records[0], state.get("modules", {}).get(module, {})
        original_source = root + "/" + record["staged"]
        original_object = root + "/build/lib/lean/" + module.replace(".", "/") + ".olean"
        require(same_evidence_file(source, original_source, entry["source"]["sha256"]) and
                same_evidence_file(obj, original_object, entry["object"]["sha256"]) and
                record.get("sha256") == item.get("source_sha256") == entry["source"]["sha256"] and
                item.get("olean_sha256") == entry["object"]["sha256"] and item.get("lean_sha256") == LEAN_SHA256 and
                all(item.get("imports", {}).get(name) == sha for name, sha in imports.items()),
                "original package module/source/object/import identity changed")
        # Retained Lake options/direct argv/package policy remain historical facts.
        # This authentic package-cache reuse is never labelled a fresh strict8 run.
    elif producer.get("kind") == "pr205_direct_cli":
        exact_keys(producer, ("kind", "receipt", "compiler", "log"), "retained original CLI producer")
        row = load(pin(producer["receipt"], "original PR205 direct CLI receipt"))
        require(row.get("module") == module and type(row.get("exit_code")) is int and row["exit_code"] == 0 and
                row.get("lean_sha256") == LEAN_SHA256 and producer["compiler"]["sha256"] == LEAN_SHA256,
                "retained CLI did not pass")
        compiler = pin(producer["compiler"], "retained compiler executable")
        require(same_evidence_file(compiler, row.get("lean"), producer["compiler"]["sha256"]), "retained original compiler path changed")
        argv = row.get("argv")
        require(isinstance(argv, list) and argv and argv[0] == row.get("lean") and
                len(argv) >= 4 and argv[-3] == "-o" and argv[-1] == row.get("source"),
                "retained argv changed")
        original_source, original_object = row["source"], argv[-2]
        hashes = row.get("dependency_hashes_pre_post", {})
        pre, post = hashes.get("pre", {}), hashes.get("post", {})
        require(isinstance(pre, dict) and isinstance(post, dict) and
                pre.get(original_source) == entry["source"]["sha256"] and
                pre.get(row["lean"]) == LEAN_SHA256 and original_object not in pre,
                "retained pre snapshot changed")
        # Original direct-CLI receipts omit the compiler from the post snapshot.
        # Its original path/hash remains independently pinned; no other loss qualifies.
        require(set(post) in (set(pre) | {original_object},
                              (set(pre) - {row["lean"]}) | {original_object}) and
                row.get("source_sha256_pre") == row.get("source_sha256_post") == entry["source"]["sha256"] and
                all(post.get(name) == sha for name, sha in pre.items() if name != row["lean"]) and
                (row["lean"] not in post or post[row["lean"]] == LEAN_SHA256) and
                post.get(original_object) == row.get("output_sha256") == entry["object"]["sha256"],
                "retained snapshots changed")
        require(all(any(path.endswith("/" + name.replace(".", "/") + ".olean") and sha == value
                        for path, value in pre.items()) for name, sha in imports.items()),
                "retained import changed")
        require(digest(pin(producer["log"], "retained original CLI log")) ==
                digest(evidence_file(row["log"], producer["log"]["sha256"])), "retained original CLI log changed")
    else:
        raise Rejected("current object has no accepted original producer class")
    require(digest(evidence_file(original_source, entry["source"]["sha256"])) == entry["source"]["sha256"] and
            digest(evidence_file(original_object, entry["object"]["sha256"])) == entry["object"]["sha256"],
            "current reuse bytes changed")
    return {"source": original_source, "source_sha256": entry["source"]["sha256"],
            "object": original_object, "object_sha256": entry["object"]["sha256"],
            "import_object_sha256": imports}

def authentic_historical_import_variant(value, catalog):
    """Exact unchanged-source evidence reuse; never equate compiled cache bytes."""
    exact_keys(value, ("module", "dependency", "original_import_sha256", "selected_import_sha256",
                       "original_dependency", "source_foundation"), "historical import variant")
    module, dependency = value["module"], value["dependency"]
    original = current_checked_reuse_entry(value["original_dependency"])
    require(value["original_dependency"]["producer"]["kind"] == "pr205_direct_cli" and
            value["original_dependency"]["module"] == dependency and module in catalog and dependency in catalog,
            "historical import scope changed")
    identity = (module, dependency, value["original_import_sha256"], value["selected_import_sha256"],
                original["source_sha256"])
    require(identity in SOURCE_HISTORICAL_IMPORT_VARIANTS and
            catalog[module]["import_object_sha256"].get(dependency) == original["object_sha256"] == value["original_import_sha256"] and
            catalog[dependency]["object_sha256"] == value["selected_import_sha256"] and
            catalog[dependency]["source_sha256"] == original["source_sha256"],
            "historical import/source identity changed")
    require(value["source_foundation"]["sha256"] == SOURCE_HISTORICAL_FOUNDATION_SHA256,
            "unreviewed historical source foundation")
    foundation = json.loads(zlib.decompress(pin(value["source_foundation"], "exact original source foundation").read_bytes()))
    require(foundation.get("schema") == "hegemon.g7.unchanged-pr205-import-source-foundation.v1" and
            foundation.get("compiler_sha256") == LEAN_SHA256 and foundation.get("gaps") == [] and
            foundation.get("historical_object_byte_equivalence_claim") is False and
            foundation["original_reviewed_package_authority"]["sha256"] == RETAINED_REUSE_SHA256,
            "original source foundation authority changed")
    reuse = load(pin(foundation["original_reviewed_package_authority"], "original reviewed foundation"))
    package = reuse["unchanged_package_authority"]
    require(foundation["package_state"] == package["state"] and
            foundation["package_source_manifest"] == package["manifest"], "source foundation package changed")
    state = load(pin(foundation["package_state"], "original source foundation state"))["modules"]
    manifest = {item["module"]: item for item in load(pin(foundation["package_source_manifest"], "original source manifest"))["sources"]}
    graph = foundation.get("graph", {})
    require(dependency in foundation.get("roots", []) and dependency in graph and
            graph[dependency]["source"]["sha256"] == original["source_sha256"], "source foundation root changed")
    for name, item in graph.items():
        source = pin(item["source"], "unchanged original compiler input")
        require(name in state and name in manifest and item["compiler_sha256"] == state[name]["lean_sha256"] == LEAN_SHA256 and
                item["source"]["sha256"] == manifest[name]["sha256"] == state[name]["source_sha256"] and
                same_evidence_file(source, RECORDED_PROJECT_ROOT + "/formal/rp05/" + manifest[name]["staged"], item["source"]["sha256"]) and
                all(dep in graph for dep in item["imports"]), "unchanged original source graph changed")
    return {"original_object_sha256": original["object_sha256"], "selected_object_sha256": value["selected_import_sha256"],
            "source_sha256": original["source_sha256"], "compiler_sha256": LEAN_SHA256}

def approved_current_reuse(record):
    item = record.get("current_reuse")
    if item is None:
        return {}
    require(SOURCE_CURRENT_GATE_REUSE_SHA256 is not None and item.get("sha256") == SOURCE_CURRENT_GATE_REUSE_SHA256,
            "current object catalog is not source-approved")
    value = load(pin(item, "exact source-approved current object reuse catalog"))
    variant_keys = ("historical_import_variants",) if "historical_import_variants" in value else ()
    exact_keys(value, ("schema", "decision", "source_root", "predecessor_reuse_sha256", "g4_checks_sha256", "entries", "independent_review") + variant_keys, "current object catalog")
    require(value["schema"] == "hegemon.private-spend.current-object-reuse.v1" and
            value["decision"] == "GO_EXACT_CHECKED_OBJECT_CATALOG" and value["source_root"] == RECORDED_SOURCE_ROOT and
            value["predecessor_reuse_sha256"] == RETAINED_REUSE_SHA256 and value["g4_checks_sha256"] == RETAINED_G4_CHECKS_SHA256 and
            isinstance(value["entries"], list) and value["entries"], "current catalog changed")
    review = load(pin(value["independent_review"], "current object catalog independent review"))
    review_variant_keys = ("historical_import_variants_sha256",) if variant_keys else ()
    exact_keys(review, ("schema", "decision", "reviewer", "source_root", "entries_sha256", "predecessor_reuse_sha256", "g4_checks_sha256") + review_variant_keys, "current object catalog review")
    require(review["schema"] == "hegemon.private-spend.current-object-reuse-review.v1" and
            review["decision"] == "GO_ORIGINAL_SOURCE_OBJECT_IMPORT_PROVENANCE" and
            isinstance(review["reviewer"], str) and review["reviewer"] and review["source_root"] == RECORDED_SOURCE_ROOT and
            review["entries_sha256"] == canonical_hash(value["entries"]) and
            review["predecessor_reuse_sha256"] == RETAINED_REUSE_SHA256 and review["g4_checks_sha256"] == RETAINED_G4_CHECKS_SHA256,
            "current catalog review mismatch")
    catalog = {}
    for entry in value["entries"]:
        require(entry.get("module") not in catalog, "duplicate current reuse module")
        catalog[entry["module"]] = current_checked_reuse_entry(entry)
    if variant_keys:
        variants = value["historical_import_variants"]
        require(isinstance(variants, list) and len(variants) == len(SOURCE_HISTORICAL_IMPORT_VARIANTS) and
                review["historical_import_variants_sha256"] == canonical_hash(variants),
                "historical variants independent review changed")
        used = set()
        for variant in variants:
            scope = (variant["module"], variant["dependency"])
            require(scope not in used, "duplicate historical import variant")
            used.add(scope)
            result = authentic_historical_import_variant(variant, catalog)
            catalog[scope[0]].setdefault("historical_import_variants", {})[scope[1]] = result
    return catalog

def retained_catalog(record):
    """Only an immutable independently reviewed source/object/import reuse map.

    Actual historical Lake/CLI flags are retained in these receipts. They are
    never upgraded to a fresh strict8 check, and no historical run is repeated.
    """
    require(record["reuse"]["sha256"] == RETAINED_REUSE_SHA256 and
            record["g4_checks"]["sha256"] == RETAINED_G4_CHECKS_SHA256,
            "unreviewed retained source/object authority")
    reuse = load(pin(record["reuse"], "independently reviewed257 retained source/object graph"))
    require(reuse.get("schema") == "hegemon.g5-minimal-coherent-dependency-reuse.v1" and
            reuse.get("decision") == "GO" and reuse.get("compiler", {}).get("sha256") == LEAN_SHA256,
            "retained dependency review identity")
    graph = load(evidence_pin(reuse["g4_223_authority"]["closure"], "accepted G4 dependency closure"))["graph"]
    rows = load(pin(record["g4_checks"], "accepted G4 actual native checks"))
    actual = {row["label"]: row for row in rows}
    catalog = {}
    for module, source_hash, object_hash, authority in reuse["project_pins"]:
        producer = next((row for row in reuse["extra14_pr205_modules"] if row["module"] == module), graph.get(module))
        if module in actual:
            row = actual[module]
            producer = dict(producer, source=row["native_argv"][-1], source_sha256=row["source_sha256"],
                            object=row["native_argv"][-2], object_sha256=row["object_sha256"])
        require(isinstance(producer, dict) and producer.get("source_sha256") == source_hash and
                producer.get("object_sha256", producer.get("sha256")) == object_hash,
                "retained review/source/object provenance mismatch")
        catalog[module] = dict(producer, object_sha256=object_hash, source_sha256=source_hash)
    for row in rows:
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0,
                "retained G4 actual compiler exit changed")
        module, argv = row["label"], row["native_argv"]
        catalog[module] = {"source": argv[-1], "source_sha256": row["source_sha256"],
                           "object": argv[-2], "object_sha256": row["object_sha256"],
                           "imports": graph[module]["imports"],
                           "import_object_sha256": graph[module].get("import_object_sha256", {})}
    current = approved_current_reuse(record)
    require(not(set(current) & set(catalog)), "current catalog replaces predecessor")
    catalog.update(current)
    # These unchanged external objects retain their reviewed original identity.
    for module, sha in reuse["external_pins"]:
        require(module not in catalog or catalog[module]["object_sha256"] == sha,
                "external/current object identity collision")
        catalog.setdefault(module, {"object_sha256": sha, "external": True})
    objects = {module: row["object_sha256"] for module, row in catalog.items()}
    objects.update(dict(reuse["external_pins"]))
    for module, row in catalog.items():
        for dependency, sha in row.get("import_object_sha256", {}).items():
            if objects.get(dependency) != sha:
                variant = row.get("historical_import_variants", {}).get(dependency, {})
                require(variant.get("original_object_sha256") == sha and
                        variant.get("selected_object_sha256") == objects.get(dependency) and
                        variant.get("source_sha256") == catalog.get(dependency, {}).get("source_sha256") and
                        variant.get("compiler_sha256") == LEAN_SHA256,
                        "retained import object/source identity changed")
    return catalog

def canonical_checks(receipt, formal_paths):
    checks, roots, endpoints = (receipt.get(key) for key in ("canonical_checks", "standard_axiom_roots", "endpoint"))
    require(isinstance(endpoints, list) and endpoints and len(set(endpoints)) == len(endpoints) and
            all(isinstance(name, str) and re.fullmatch(r"Hegemon(?:Crypto|Transaction)?(?:\.[A-Za-z_][A-Za-z_0-9]*)+", name) for name in endpoints),
            "qualified theorem endpoints missing")
    require(isinstance(roots, dict) and set(endpoints).issubset(roots) and
            all(isinstance(axioms, list) and set(axioms).issubset(STD_AXIOMS) and len(axioms) == len(set(axioms)) for axioms in roots.values()),
            "exact standard-axiom root map missing")
    require(isinstance(checks, list) and checks, "actual scoped native CLI receipts missing")
    closure = receipt.get("source_closure")
    require(isinstance(closure, list) and closure, "required endpoint source closure missing")
    source_map = {item["path"]: item for item in closure}
    require(len(source_map) == len(closure) and set(source_map).issubset(formal_paths),
            "duplicate or omitted qualified endpoint source")
    for item in closure:
        pin(item, "qualified current endpoint source")
    covered, readouts, modules, imports = set(), {}, {}, {}
    retained = receipt.get("retained_reuse")
    catalog = retained_catalog(retained) if retained is not None else {}
    for check in checks:
        module = check["module"]
        require(check["source"]["path"].endswith("/" + module.replace(".", "/") + ".lean") and
                module not in modules and check["source"]["path"] in source_map and
                check["source"] == source_map[check["source"]["path"]], "duplicate module or different current source pin")
        provenance_file = pin(check["provenance"], "actual scoped compiler receipt list")
        row = actual_row(load(provenance_file), module)
        log = strict_native_row(check, row)
        plan_file = pin(check["plan"], "frozen scoped compiler inputs")
        plan = load(plan_file)
        result = load(pin(check["result"], "natural scoped compiler completion"))
        require(plan.get("schema") == "hegemon.frozen-lean-delta-check.v1" and
                plan.get("compiler_sha256") == LEAN_SHA256 and plan.get("flags") == list(STRICT_FLAGS) and
                result.get("schema") == "hegemon.frozen-lean-delta-result.v1" and result.get("status") == "SCOPED_KERNEL_PASS" and
                result.get("plan_sha256") == check["plan"]["sha256"] and
                result.get("actual_checks_sha256") == check["provenance"]["sha256"],
                "new source/actual completion does not bind frozen scoped inputs")
        source_inputs = [item for item in plan.get("files", []) if item.get("module") == module]
        require(len(source_inputs) == 1 and source_inputs[0].get("sha256") == check["source"]["sha256"], "new source is absent from the frozen compile plan")
        relative = module.replace(".", "/")
        require(row.get("cwd") == plan["work"] + "/sources" and
                row["native_argv"][-1] == plan["work"] + "/sources/" + relative + ".lean" and
                row["native_argv"][-2] == plan["work"] + "/objects/" + relative + ".olean" and
                row["argv"][2] == plan["stack_shim"], "actual producer is outside the frozen work scope")
        require(digest(evidence_file(source_inputs[0]["path"], check["source"]["sha256"])) == check["source"]["sha256"],
                "frozen input source bytes changed")
        expected = check.get("standard_axiom_roots", {})
        if expected:
            found = audit_readouts(log, expected)
            require(row.get("standard_axioms") == found and not(set(found) & set(readouts)), "duplicate or changed actual root provenance")
            require(set(found) == set(source_inputs[0].get("audit_roots", [])), "audit roots differ from frozen plan")
            readouts.update(found)
        else:
            require(log == "" and not row.get("standard_axioms") and not source_inputs[0].get("audit_roots"),
                    "new producer output is not exactly empty")
        modules[module] = check["object"]["sha256"]
        covered.add(check["source"]["path"])
        imports[module] = {item["relative"].removesuffix(".olean").replace("/", "."): item["sha256"] for item in plan.get("retained_objects", [])}
    # The exact new producer plan must reuse the authenticated selected object
    # identities; this reads receipts and never recompiles historical sources.
    for selected in imports.values():
        for module, sha in selected.items():
            require(module in catalog and catalog[module]["object_sha256"] == sha,
                    "new frozen plan imports an object outside authenticated retained reuse")
    if retained is not None:
        selected = retained.get("sources")
        require(isinstance(selected, list), "selected retained endpoint source rows missing")
        for item in selected:
            module = item["module"]
            require(item["source"]["path"].endswith("/" + module.replace(".", "/") + ".lean") and
                    module in catalog and module not in modules and item["source"]["path"] in source_map and
                    item["source"] == source_map[item["source"]["path"]], "retained row omits or duplicates current endpoint source")
            accepted = catalog[module]
            require(item["source"]["sha256"] == accepted["source_sha256"] and
                    item["object"]["sha256"] == accepted["object_sha256"], "retained source/object identity drift")
            pin(item["object"], "retained producer object")
            require(digest(evidence_file(accepted["source"], accepted["source_sha256"])) == accepted["source_sha256"] and
                    digest(evidence_file(accepted["object"], accepted["object_sha256"])) == accepted["object_sha256"],
                    "authenticated retained producer bytes drift")
            modules[module] = item["object"]["sha256"]
            covered.add(item["source"]["path"])
    for module, source_hash in modules.items():
        current_source = next((item for item in closure if item["path"] in covered and
                               (item["path"].removeprefix("formal/crypto/").removeprefix("formal/transaction/").removesuffix(".lean").replace("/", ".") == module)), None)
        if current_source is not None:
            for line in pin(current_source, "required endpoint import source").read_text().splitlines():
                if line.startswith("import "):
                    for dependency in line[7:].split():
                        if dependency.startswith(("HegemonCrypto.", "Hegemon.", "Q38")):
                            require(dependency in modules or dependency in imports.get(module, {}) or dependency in catalog,
                                    "required endpoint import has no producer/retained identity: " + dependency)
    require(covered == set(source_map), "required endpoint source has no actual producer or authenticated retained reuse: " + ",".join(sorted(set(source_map)-covered)))
    require(readouts == roots, "declared endpoint roots do not equal complete unique actual audit readouts")
    # Only required endpoint closure sources need producer/reuse coverage. The
    # unrelated70 retained postimages remain frozen by source_closure().
    return covered

def actual_g5_qualification(value, receipt, formal_paths):
    # Adapt one immutable actual qualification, not a caller's truth wrapper.
    require(value["sha256"] == "04fcfcbf9f61bbff69630294ece88c3800070c105630a3423fc8d06a0c34af9a",
            "G5 is not the accepted actual four-module qualification")
    current_identity(receipt.get("identity"))
    require(receipt.get("qualified") is True and receipt.get("status") == "QUALIFIED_CONDITIONAL" and
            receipt.get("preparation_only") is False and receipt.get("source_root") == RECORDED_SOURCE_ROOT,
            "G5 actual qualification status changed")
    claim = receipt["claim"]
    require(claim["Q_upper_inclusive"] == "3*2^64" and claim["M_upper_inclusive"] == "2^21" and
            "failed and unused" in claim["M_counts"] and "no bound on M is inferred" in claim["M_counts"] and
            "uniform all-context ContinuationQueries" in claim["queries"], "G5 conditional cryptographic class omitted")
    require(receipt["canonical_checks"]["sha256"] == "421f359a7a0c7731e607a982594f025128d7f5fe5139f4e9564baf5d852f6c5a" and
            receipt["independent_review"]["sha256"] == "030ded286349902728fe22b6ee20c16aede8ccab573fa344386b2aebd95f016a" and
            receipt["actual_integration"]["sha256"] == "17d3411910d11285d172d8c58797bbb3cd23eb1581e1d62ad70863f3ddc1c8fe",
            "G5 actual checks/review/application provenance changed")
    checked = load(evidence_pin(receipt["canonical_checks"], "actual G5 four-row cohort"))
    review = load(evidence_pin(receipt["independent_review"], "actual G5 independent readback"))
    applied = load(evidence_pin(receipt["actual_integration"], "actual G5 source integration"))
    require(checked["failed_aggregate_promoted"] is False and
            review["schema"] == "hegemon.g5-independent-actual-readback.v1" and
            review["decision"] == "GO_ACTUAL_SCOPED_KERNEL_READBACK" and
            review["execution_provenance"]["failed_aggregate_runs02_and03_not_promoted"] is True,
            "failed aggregates cannot qualify G5")
    rows = checked["checks"]
    require(len(rows) == 4 and len({row["module"] for row in rows}) == 4, "actual G5 cohort must be exactly four unique modules")
    objects, covered = {}, set()
    for row, accepted in zip(rows, review["cohort"]):
        require(row["module"] == accepted["module"] and
                actual_row(load(evidence_pin(accepted["actual_checks"], "actual individual native receipts")), row["module"]) == row,
                "G5 canonical producer differs from its actual individual native row")
        check = {"exit_code": row["exit_code"], "native_argv": row["native_argv"], "argv": row["argv"],
                 "source": accepted["source"], "object": accepted["object"], "log": accepted["log"],
                 "stack_receipt": accepted["stack"],
                 "compiler": {"path": "release-evidence/compiler/lean4.32.2", "bytes": 49968, "sha256": LEAN_SHA256},
                 "stack_shim": {"path": row["argv"][2], "bytes": evidence_file(row["argv"][2], STACK_SHIM_SHA256).stat().st_size,
                                "sha256": STACK_SHIM_SHA256}}
        # Original artifact pins are translated to the authenticated portable archive.
        for key in ("source", "object", "log", "stack_receipt", "stack_shim"):
            original = check[key]
            name = original["path"]
            require(name.startswith(RECORDED_PROJECT_ROOT + "/"), "G5 producer evidence origin changed")
            check[key] = dict(original, path="release-evidence/retained/" + name[len(RECORDED_PROJECT_ROOT)+1:])
        log = strict_native_row(check, row)
        if row.get("standard_axioms"):
            require(audit_readouts(log, row["standard_axioms"]) == review["final_run"]["standard_axiom_roots"] and
                    set(row["standard_axioms"]) == set(receipt["endpoints"]) and len(row["standard_axioms"]) == 12,
                    "G5 final audit does not consume the exact twelve Std-only roots")
        else:
            require(log == "", "G5 actual individual producer output must be empty")
        entry = next(item for item in applied["entries"] if item.get("module") == row["module"])
        relative = entry["destination"][len(RECORDED_SOURCE_ROOT)+1:]
        require(relative in formal_paths and entry["sha256"] == row["source_sha256"] and
                digest(path(relative)) == row["source_sha256"], "G5 actual checked source is not integrated unchanged")
        covered.add(relative)
        objects[row["module"]] = row["object_sha256"]
    for prerequisite in receipt["evidence"]:
        evidence_pin(prerequisite, "G5 actual execution prerequisite")
    base = RECORDED_PROJECT_ROOT + "/.agent/launchpad-2026-10-03/resume45/feed-forward/shipping-rescope-floor70-20261009/"
    final = load(evidence_file(base + "g5-current-persistent-history-check-04/result.json"))
    plan = load(evidence_file(base + "g5-current-persistent-history-check-prep04/PLAN.json"))
    require(final["status"] == "SCOPED_KERNEL_PASS" and final["plan_sha256"] == review["execution_provenance"]["plan_sha256"] and
            digest(evidence_file(base + "g5-current-persistent-history-check-prep04/PLAN.json")) == final["plan_sha256"] and
            digest(evidence_file(base + "g5-current-persistent-history-check-04/actual-checks.json")) == final["actual_checks_sha256"],
            "G5 final natural audit completion/input closure changed")
    retained = {item["relative"].removesuffix(".olean").replace("/", "."): item["sha256"] for item in plan["retained_objects"]}
    for row in rows[:2]:
        require(retained.get(row["module"]) == objects[row["module"]],
                "final G5 plan did not reuse the individually successful exact producer object")
    reap = load(evidence_file(base + "g5-current-persistent-history-check-04/ROOT-TERMINAL-REAP.json"))
    guard = load(evidence_file(base + "g5-current-persistent-history-check-prep04/guard-receipt.json"))
    require(reap["session_finished"] is True and type(reap["exit_code"]) is int and reap["exit_code"] == 0 and
            reap["natural_guard_exit_code"] == 0 and guard["exit_code"] == 0 and guard["stop_reason"] == "none" and
            reap["guard_receipt_sha256"] == digest(evidence_file(base + "g5-current-persistent-history-check-prep04/guard-receipt.json")) and
            guard["scope_sha256"] == review["execution_provenance"]["scope_sha256"],
            "G5 natural terminal reap/guard postpin validation missing")
    return covered

def actual_g1_qualification(value, receipt, formal_paths):
    """Exact authenticated historical semantic G1; current86 needs its own bridge."""
    require(value.get("sha256") == "d4bdc227625f2685ea02656357b978d4e07295dba8e42b6d795a47a16d4bc3bd" and
            receipt.get("schema") == "hegemon.g1-current-release-qualification.v1" and
            receipt.get("status") == "QUALIFIED_CONDITIONAL_G1_SEMANTIC_RELEASE_GATE" and
            receipt.get("qualified") is True and receipt.get("conditional_G1_qualified") is True and
            receipt.get("source_applied") is True and receipt.get("source_application_pending") is False and
            receipt.get("production_authorized") is False and receipt.get("mainnet_shipped") is False,
            "G1 is not the exact actually applied conditional semantic qualification")
    require(receipt["source_application"]["sha256"] ==
                "8eabfcbf7b8eadcf3595f8b9af1abcb79c0b99360841b8c0dd876e2a8a960196" and
            receipt["independent_final_review"]["sha256"] ==
                "c61ac98ac74650db85e1c90cfef66f3b3be3300a92dd9f15e02e53d63341f861",
            "G1 source application or independent review substituted")
    evidence_pins(receipt)
    application = load(evidence_pin(receipt["source_application"], "G1 actual source application"))
    require(application.get("schema") == "hegemon.g1-checked-sources-applied.v1" and
            application.get("status") == "EXACT17_POSTIMAGES_VERIFIED" and
            application.get("source_files") == 15 and application.get("production_authorized") is False,
            "G1 exact source application differs")
    covered = set()
    for row in application["postimages"]:
        name = row["path"]
        if name.startswith(RECORDED_SOURCE_ROOT + "/formal/"):
            relative = name[len(RECORDED_SOURCE_ROOT) + 1:]
            require(relative in formal_paths, "G1 applied formal source missing from inventory")
            pin(dict(row, path=relative), "G1 actually applied formal source")
            covered.add(relative)
    require(len(covered) == 15, "G1 applied formal source closure changed")
    return covered


def historical_g6_node_reference(gate_value, identity, *, allow_reference=False):
    """Authenticate one explicitly unavailable historical executable reference.

    This never establishes retained node bytes or fresh execution. Every other
    historical artifact and every final binary/lifecycle check still applies.
    """
    require(allow_reference is True and isinstance(identity, dict) and
            identity.get("schema") == ONGOING_IDENTITY_SCHEMA and
            _ONGOING_POLICY_SOURCE_APPROVED and
            SOURCE_HISTORICAL_G6_NODE_REFERENCE_SHA256 is not None,
            "historical G6 node reference is not source-approved for this ongoing call")
    identity_check(identity)
    expected_gate = dict(HISTORICAL_G6_RECEIPT, path="release-evidence/retained/" +
                         HISTORICAL_G6_RECEIPT["path"][len(RECORDED_PROJECT_ROOT) + 1:])
    require(gate_value == expected_gate and gate_value["sha256"] == G6_SHA256,
            "historical G6 node reference requires the exact original G6 receipt")
    file = path(SOURCE_HISTORICAL_G6_NODE_REFERENCE)
    require(digest(file) == SOURCE_HISTORICAL_G6_NODE_REFERENCE_SHA256,
            "historical G6 node provenance bytes changed")
    provenance = load(file)
    exact_keys(provenance, ("schema", "status", "g6_receipt", "historical_node",
        "frozen_g7_inputs", "recovery_report", "current_artifact_bytes_required",
        "fresh_final_lifecycle_required", "all_other_historical_bytes_required",
        "production_authorized", "limitation", "g2_qualification", "g2_binding",
        "g2_node_context"), "historical G6 node provenance")
    require(provenance["schema"] == "hegemon.historical-g6-node-reference.v2" and
            provenance["status"] == "NOT_RETAINED_HISTORICAL_EXECUTABLE_REFERENCE" and
            provenance["g6_receipt"] == HISTORICAL_G6_RECEIPT and
            provenance["historical_node"] == HISTORICAL_G6_NODE and
            provenance["g2_qualification"] == HISTORICAL_G2_QUALIFICATION and
            provenance["g2_binding"] == HISTORICAL_G2_BINDING and
            provenance["g2_node_context"] == HISTORICAL_G2_NODE_CONTEXT and
            provenance["frozen_g7_inputs"] == HISTORICAL_G6_FROZEN_INPUTS and
            provenance["recovery_report"] == HISTORICAL_G6_RECOVERY and
            provenance["current_artifact_bytes_required"] is True and
            provenance["fresh_final_lifecycle_required"] is True and
            provenance["all_other_historical_bytes_required"] is True and
            provenance["production_authorized"] is False,
            "historical G6 node provenance scope changed")
    receipt = load(evidence_pin(provenance["g6_receipt"], "original historical G6 receipt"))
    frozen = load(evidence_pin(provenance["frozen_g7_inputs"], "frozen historical G7 node identity"))
    recovery = load(evidence_pin(provenance["recovery_report"], "bounded historical node recovery"))
    require(receipt.get("binaries", {}).get("hegemon-node") ==
                {key: HISTORICAL_G6_NODE[key] for key in ("path", "sha256")} and
            frozen.get("gates", {}).get("G6", {}).get("retained_binaries", {}).get("hegemon-node") == HISTORICAL_G6_NODE and
            recovery.get("historical_descriptors", {}).get("hegemon-node") == HISTORICAL_G6_NODE and
            recovery.get("findings", {}).get("hegemon-node", {}).get("status") == "NOT_RECOVERED_IN_BOUNDED_SEARCH" and
            recovery["findings"]["hegemon-node"].get("matching_hash_candidates") == [],
            "historical node identity or bounded nonretention evidence changed")
    g2 = load(evidence_pin(provenance["g2_qualification"], "original G2 qualification"))
    g2_binding = load(evidence_pin(provenance["g2_binding"], "original G2 binding"))
    require(g2.get("binding") == HISTORICAL_G2_BINDING and
            isinstance(g2_binding.get("g6", {}).get("binaries"), list) and
            g2_binding["g6"]["binaries"] and
            g2_binding["g6"]["binaries"][0] == HISTORICAL_G2_NODE_CONTEXT["descriptor"],
            "original G2 historical node context changed")
    return HISTORICAL_G6_NODE


def g2_evidence_pins(gate_value, receipt, binding, identity=None, *, allow_historical_node_reference=False):
    require(type(allow_historical_node_reference) is bool, "historical G2 reference flag must be Boolean")
    if not allow_historical_node_reference:
        evidence_pins(receipt)
        evidence_pins(binding)
        return
    expected_gate = dict(HISTORICAL_G2_QUALIFICATION, path="release-evidence/retained/" +
                        HISTORICAL_G2_QUALIFICATION["path"][len(RECORDED_PROJECT_ROOT) + 1:])
    require(gate_value == expected_gate and receipt.get("binding") == HISTORICAL_G2_BINDING and
            receipt["binding"]["sha256"] == G2_BINDING_SHA256,
            "historical node reference requires the exact original G2 binding")
    g6_gate = dict(HISTORICAL_G6_RECEIPT, path="release-evidence/retained/" +
                   HISTORICAL_G6_RECEIPT["path"][len(RECORDED_PROJECT_ROOT) + 1:])
    historical_g6_node_reference(g6_gate, identity, allow_reference=True)
    require(isinstance(binding.get("g6", {}).get("binaries"), list) and
            binding["g6"]["binaries"] and
            binding["g6"]["binaries"][0] == HISTORICAL_G2_NODE_CONTEXT["descriptor"],
            "historical G2 node reference location changed")
    evidence_pins(receipt)
    # Only /g6/binaries/0 in this immutable G2 binding is metadata-only.
    # Identical descriptors anywhere else still require physical bytes.
    for key, value in binding.items():
        if key == "g6":
            for field, child in value.items():
                evidence_pins(child[1:] if field == "binaries" else child)
        else:
            evidence_pins(value)


def g6_evidence_pins(gate_value, receipt, identity=None, *, allow_historical_node_reference=False):
    require(type(allow_historical_node_reference) is bool, "historical G6 reference flag must be Boolean")
    if not allow_historical_node_reference:
        evidence_pins(receipt)
        return
    node = historical_g6_node_reference(gate_value, identity, allow_reference=True)
    require(receipt.get("binaries", {}).get("hegemon-node") ==
            {key: node[key] for key in ("path", "sha256")},
            "historical G6 receipt node reference changed")
    # Skip exactly this one root location; any duplicate reference elsewhere is
    # still a physical prerequisite. Do not apply a hash/path-wide exemption.
    for key, value in receipt.items():
        if key == "binaries":
            for name, binary in value.items():
                if name != "hegemon-node":
                    evidence_pins(binary)
        else:
            evidence_pins(value)


def retained_g6_binaries(binding, receipt, identity, *, allow_historical_node_reference=False):
    require(type(allow_historical_node_reference) is bool, "historical G6 reference flag must be Boolean")
    exact_keys(binding["retained_binaries"], ("hegemon-node", "private-spend", "treasury-v8"),
               "retained G6 binary identities")
    for name, binary in binding["retained_binaries"].items():
        require(binary["sha256"] == receipt["binaries"][name]["sha256"], "retained G6 binary substituted")
        if name == "hegemon-node" and allow_historical_node_reference:
            historical_g6_node_reference(binding["gates"]["G6"], identity, allow_reference=True)
            require(binary == HISTORICAL_G6_NODE_PACKAGED, "historical G6 binding node metadata changed")
        else:
            pin(binary, "retained G6 binary")


def qualification(gate, value, formal_paths, *, identity=None, allow_historical_node_reference=False):
    file = pin(value, gate + " qualification")
    receipt = load(file)
    if gate == "G1" and receipt.get("schema") == "hegemon.g1-current-release-qualification.v1":
        return actual_g1_qualification(value, receipt, formal_paths)
    if gate == "G5" and value.get("sha256") == "04fcfcbf9f61bbff69630294ece88c3800070c105630a3423fc8d06a0c34af9a":
        return actual_g5_qualification(value, receipt, formal_paths)
    if gate in ("G1", "G3", "G5"):
        require(receipt.get("schema") == "hegemon.current-release-gate-qualification.v1" and receipt.get("gate") == gate and
                receipt.get("status") == "QUALIFIED_CONDITIONAL" and receipt.get("qualified") is True and
                receipt.get("preparation_only") is False and receipt.get("source_root") == RECORDED_SOURCE_ROOT,
                gate + " is missing actual current conditional qualification")
        current_identity(receipt.get("identity"))
        if gate == "G5":
            require(receipt.get("cryptographic_class") == CRYPTOGRAPHIC_CLASS,
                    "G5 qualified claim omits the actual all-attempt/continuation class")
        require(receipt.get("assumptions") == list(ASSUMPTIONS), gate + " inherited boundary mismatch")
        prerequisites = receipt.get("evidence_prerequisites")
        require(isinstance(prerequisites, dict) and prerequisites, gate + " actual prerequisites missing")
        for prerequisite in prerequisites.values():
            pin(prerequisite, gate + " actual prerequisite")
        covered = canonical_checks(receipt, formal_paths)
        review = load(pin(receipt["independent_review"], gate + " actual independent review"))
        require(review.get("schema") == "hegemon.current-release-gate-independent-review.v1" and
                review.get("decision") == "GO_QUALIFIED_CONDITIONAL" and review.get("gate") == gate and
                review.get("identity") == receipt["identity"] and review.get("endpoint") == receipt["endpoint"] and
                review.get("source_closure_sha256") == canonical_hash(receipt["source_closure"]) and
                review.get("evidence_prerequisites_sha256") == canonical_hash(prerequisites) and
                review.get("assumptions") == list(ASSUMPTIONS), gate + " independent review does not bind actual current endpoint/inputs")
        if gate == "G5":
            require(review.get("cryptographic_class") == CRYPTOGRAPHIC_CLASS,
                    "G5 independent review omits the actual conditional experiment class")
        return covered
    if gate == "G2":
        require(receipt.get("schema") == "hegemon.current-g2-qualified-f1-binding.v1" and receipt.get("gate") == gate and
                receipt.get("status") == "QUALIFIED_CONDITIONAL" and receipt.get("qualified") is True and
                receipt.get("preparation_only") is False and receipt.get("source_root") == RECORDED_SOURCE_ROOT, "G2 is not the actual qualified F1 binding")
        current_identity(receipt.get("identity"))
        require(receipt["binding"]["sha256"] == G2_BINDING_SHA256 and receipt["independent_review"]["sha256"] == G2_REVIEW_SHA256, "G2 candidate or unrelated review substituted")
        binding = load(evidence_pin(receipt["binding"], "actual G2 binding"))
        require(binding.get("schema") == "hegemon.current-g2-finite-f1-binding.v1" and binding.get("relation", {}).get("computed_sha512") == CURRENT_RELATION, "wrong G2 current packet")
        require(all(binding["exact_profile"].get(k) == v for k, v in PROFILE.items()), "G2 geometry/profile mismatch")
        review = load(evidence_pin(receipt["independent_review"], "actual G2 independent review"))
        require(review.get("decision") == "GO_FINITE_G2_CONDITIONAL_F1" and review.get("packet", {}).get("sha256") == G2_BINDING_SHA256, "G2 not independently accepted")
        g2_evidence_pins(value, receipt, binding, identity,
                         allow_historical_node_reference=allow_historical_node_reference)
        return set()
    if gate == "G4":
        require(value["sha256"] == G4_SHA256 and receipt.get("gate") == gate and receipt.get("status") == "QUALIFIED_CONDITIONAL" and
                receipt.get("qualified") is True and receipt.get("preparation_only") is False, "G4 is not the unchanged accepted current full-public endpoint")
        require(receipt.get("endpoint") and receipt.get("evidence_prerequisites") and receipt.get("combined_exact_cohort", {}).get("canonical_checks"), "G4 actual full cohort missing")
        for check in receipt["combined_exact_cohort"]["canonical_checks"]:
            require(check.get("exit_code") == 0 and "-DwarningAsError=true" in check.get("argv", []), "G4 canonical native checks not accepted")
        evidence_pins(receipt)
        return set()
    require(gate == "G6" and value["sha256"] == G6_SHA256 and receipt.get("schema") == "hegemon.private-spend.actualnode.compff01.v1" and
            receipt.get("status") == "PASS_DEV_ONLY" and receipt.get("production_authorized") is False and
            receipt.get("runtime_inventory_sha256") == BASE_RUNTIME_SHA256, "G6 is not the unchanged actual local predecessor lifecycle")
    lifecycle_checks(receipt)
    require(receipt["parameters"].get("relation_id") == CURRENT_RELATION_ID and receipt["parameters"].get("relation_digest") == CURRENT_RELATION and
            receipt["parameters"].get("public_words") == 77 and receipt["manifest"].get("profile") == "development", "old G6 tuple reinterpreted as mainnet")
    g6_evidence_pins(value, receipt, identity, allow_historical_node_reference=allow_historical_node_reference)
    return set()

def lifecycle_checks(receipt):
    require(set(receipt.get("gates", {})) == LIFECYCLE_GATES and all(value is True for value in receipt["gates"].values()), "actual 35-gate lifecycle incomplete")
    require(receipt.get("all_owned_exit0") is True and receipt.get("all_owned_reaped") is True and receipt.get("rpc_closed") is True,
            "actual lifecycle runner not cleanly completed")
    require({proof.get("case") for proof in receipt.get("proofs", {}).values()} == set(CASES), "actual lifecycle omits a common relation branch")
    require(len(receipt.get("canonical_bodies", [])) >= 55, "actual same-byte block lifecycle evidence missing")

def proof_check(case, record, *, predecessor=False):
    exact_keys(record, ("proof", "carrier", "public_binding", "result", "source_config", "migration_negative", "native_stage", "native_stage_outer"), "retained proof case")
    files = {name: pin(row, case + " " + name) for name, row in record.items()}
    proof, carrier, binding = (files[name].read_bytes() for name in ("proof", "carrier", "public_binding"))
    require(len(proof) == 1926125 and proof[:4] == b"SMZD" and len(carrier) == 1931869 and
            carrier[:24] == b"HGPSLC01" + bytes.fromhex("01000b00070001000f000800020c0100") and
            carrier[24:72] == bytes.fromhex(CURRENT_RUNTIME_RELATION)[:48] and carrier[5744:] == proof, "wrong complete current proof/carrier")
    words = [word[0] for word in struct.iter_unpack("<I", carrier[72:136])]
    words += [word[0] for word in struct.iter_unpack("<Q", carrier[136:432])]
    words += [word[0] for word in struct.iter_unpack("<I", carrier[432:528])]
    require(len(binding) == 616 and len(words) == 77 and struct.pack("<77Q", *words) == binding and all(word < FIELD_P for word in words), "wrong canonical common77")
    cursor = 104
    shapes = ((5, 69), (5, 126), (12, 58), (58, 128), (6, 10), (58, 5), (5, 13115), (6, 26220))
    for index, shape in enumerate(shapes):
        if index == 5:
            require(struct.unpack_from("<H", proof, cursor)[0] == 58, "wrong DECS path count")
            cursor += 2
            depths = proof[cursor:cursor + 58]
            require(len(depths) == 58 and max(depths) <= 23, "wrong canonical DECS paths")
            cursor += 58 + sum(depths) * 64 + 58 * 64
        if index == 7:
            require(proof[cursor] == 1, "opened witness absent")
            cursor += 1
        require(struct.unpack_from("<HH", proof, cursor) == shape, "wrong current proof matrix geometry")
        cursor += 4
        stop = cursor + 8 * shape[0] * shape[1]
        require(stop <= len(proof) and all(word[0] < FIELD_P for word in struct.iter_unpack("<Q", proof[cursor:stop])), "noncanonical proof field")
        cursor = stop
    require(struct.unpack_from("<II", proof, cursor) == (0, 0) and not any(proof[cursor + 8:]), "noncanonical proof suffix")
    result, config, negative, stage, outer = (load(files[name]) for name in ("result", "source_config", "migration_negative", "native_stage", "native_stage_outer"))
    require(result.get("status") == "candidate_proof_verified" and result.get("error") is None and
            result.get("proof_sha512") == hashlib.sha512(proof).hexdigest() and result.get("carrier_sha512") == hashlib.sha512(carrier).hexdigest(), "actual native generated/verified proof mismatch")
    require(config.get("qualification_branch") == case and config.get("relation_id") == CURRENT_RELATION_ID and config.get("relation_digest_sha512") == CURRENT_RUNTIME_RELATION and
            config.get("public_words") == words and config.get("geometry", {}).get("matrix_dimensions") == [list(shape) for shape in shapes], "proof source relation/geometry mismatch")
    require(negative.get("schema") == "hegemon.private-spend.compff01.old-proof-negative.v1" and
            negative.get("new_relation") == CURRENT_RUNTIME_RELATION and
            negative.get("old_relation") == CURRENT_RELATION and negative.get("no_relabel_or_reencoding") is True and
            negative.get("current_expected_context_rejected_old_carrier") == "Context" and
            negative.get("current_relation_rejected_unmodified_old_proof") == "constraint system violated: smallwood piop transcript hash mismatch", "current migration negatives absent")
    current_proof_provenance(case, record, stage, outer, predecessor=predecessor)

class Rejected(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Rejected(message)

def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " keys mismatch")

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result

def load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def hexadecimal(value, width, label, nonzero=False):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(width) + "}", value), label + " invalid hex")
    require(not nonzero or int(value, 16) != 0, label + " is zero")

def path(relative):
    require(isinstance(relative, str) and relative, "empty evidence path")
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and parts.as_posix() == relative and
            all(part not in (".", "..") for part in parts.parts), "noncanonical relative evidence path")
    candidate = ROOT
    for part in parts.parts:
        candidate = candidate / part
        require(not candidate.is_symlink(), "symlink evidence path")
    require(candidate.is_file(), "missing evidence: " + relative)
    return candidate

def pin(value, label):
    exact_keys(value, ("path", "bytes", "sha256"), label)
    hexadecimal(value["sha256"], 64, label + " hash")
    require(type(value["bytes"]) is int and value["bytes"] >= 0, label + " invalid length")
    name = value["path"]
    if PurePosixPath(name).is_absolute():
        alias = retained_path_aliases().get(name)
        if alias is not None:
            require(alias["bytes"] == value["bytes"] and alias["sha256"] == value["sha256"],
                    label + " original alias identity changed")
            file = path(alias["path"])
        else:
            require(name.startswith(RECORDED_SOURCE_ROOT + "/") or
                    name.startswith(RECORDED_PROJECT_ROOT + "/"),
                    label + " unapproved original absolute path")
            # Translate only the two literal historical origins into this checkout.
            # evidence_file never reads an original host path; path rejects escape.
            file = evidence_file(name, value["sha256"])
    else:
        file = path(name)
    require(file.stat().st_size == value["bytes"] and digest(file) == value["sha256"], label + " bytes changed")
    return file

def native_capability(identity):
    identity_check(identity)
    source = path("protocol/versioning/src/launch_candidate.rs").read_text()
    match = re.search(r"const\s+AUTHORIZED_LAUNCH_PROOF_CAPABILITIES\s*:\s*&\[LaunchProofCapability\]\s*=\s*(.*?);", source, re.S)
    require(match is not None, "native capability registry not found")
    array = lambda values: "[" + ",".join(str(v) for v in values) + "]"
    byte_array = lambda value: array(bytes.fromhex(value))
    optional_u64 = lambda value: "None" if value is None else f"Some({value})"
    fields = {
        "kind": "LaunchProofKind::PrivateSpend", "chain_id": byte_array(identity["chain_id"]),
        "genesis_hash": byte_array(identity["genesis_hash"]), "manifest_digest": byte_array(identity["manifest_digest"]),
        "relation_digest": byte_array(identity["relation_digest"]),
        "activation_height": str(identity["activation_height"]),
        "deactivation_height_exclusive": optional_u64(identity["deactivation_height_exclusive"]),
        "max_proof_bytes": str(identity["max_proof_bytes"]),
        "stablecoin_genesis_root": array(identity["stablecoin_genesis_root"]),
        "note_genesis_root": array(identity["note_genesis_root"]),
        "max_proof_actions_per_block": str(identity["max_proof_actions_per_block"]),
        "max_total_proofs": optional_u64(identity["max_total_proofs"]),
    }
    expected = "&[LaunchProofCapability{" + ",".join(k + ":" + v for k, v in fields.items()) + ",}]"
    # Exact generated literals only: no calls, macros, expressions or extra rows.
    normalize = lambda text: re.sub(r",(?=[\]}])", "", re.sub(r"\s+", "", text))
    require(normalize(match.group(1)) == normalize(expected), "native capability does not equal the one reviewed literal tuple")

def identity_network_profile(identity):
    require(isinstance(identity, dict), "identity must be an object")
    if "schema" not in identity:
        return "mainnet"  # Immutable historical bounded identity format.
    require(identity["schema"] == ONGOING_IDENTITY_SCHEMA, "unknown native identity schema")
    require(identity.get("network_profile") in ("pre-mainnet", "mainnet"),
            "ongoing identity requires explicit pre-mainnet or mainnet profile")
    return identity["network_profile"]


def identity_check(identity):
    identity_network_profile(identity)
    ongoing = identity.get("schema") == ONGOING_IDENTITY_SCHEMA
    keys = set(FIXED) | {"chain_id", "genesis_hash", "manifest_digest", "relation_digest",
        "activation_height", "deactivation_height_exclusive", "max_proof_bytes",
        "stablecoin_genesis_root", "note_genesis_root", "max_proof_actions_per_block", "max_total_proofs", "cryptographic_class"}
    if ongoing:
        keys |= {"schema", "network_profile", "relation_id", "public_words"}
    exact_keys(identity, keys, "identity")
    fixed = ONGOING_FIXED if ongoing else FIXED
    require(all(identity[k] == v for k, v in fixed.items()), "wrong proof/compression/emission identity")
    for name, width in (("chain_id", 64), ("genesis_hash", 64), ("manifest_digest", 128), ("relation_digest", 128)):
        hexadecimal(identity[name], width, name, True)
    require(identity["relation_digest"] == (ONGOING_POLICY_RELATION if ongoing else CURRENT_RUNTIME_RELATION),
            "release relation is not the exact selected reviewed relation")
    if ongoing:
        require(identity["relation_id"] == ONGOING_POLICY_PROFILE["relation_id"] and
                identity["public_words"] == 86, "ongoing native relation/public binding differs from actual current policy")
    for name in ("activation_height", "max_proof_bytes", "max_proof_actions_per_block"):
        require(type(identity[name]) is int and identity[name] > 0, name + " must be a positive integer")
    require(identity["activation_height"] < 1 << 63, "activation outside relation scalar range")
    require(identity["max_proof_actions_per_block"] <= 512 and
            identity["max_proof_bytes"] <= (ONGOING_POLICY_PROFILE["max_carrier_bytes"] if ongoing else 2102896),
            "capability per-block or per-proof resource budget exceeds the source limits")
    if ongoing:
        require(identity["deactivation_height_exclusive"] is None and identity["max_total_proofs"] is None,
                "ongoing identity requires explicit null expiry and accepted-proof quota")
        expected_class = ONGOING_CRYPTOGRAPHIC_CLASS
    else:
        for name in ("deactivation_height_exclusive", "max_total_proofs"):
            require(type(identity[name]) is int and identity[name] > 0, name + " must be a positive integer")
        require(identity["activation_height"] < identity["deactivation_height_exclusive"] < (1 << 64) - 1,
                "invalid finite activation interval")
        require(identity["max_total_proofs"] <= 1 << 21, "bounded historical accepted-proof budget exceeds its conditional class")
        expected_class = CRYPTOGRAPHIC_CLASS
    require(identity["cryptographic_class"] == expected_class,
            "release cryptographic class differs from the selected identity schema")
    for name in ("stablecoin_genesis_root", "note_genesis_root"):
        root = identity[name]
        require(isinstance(root, list) and len(root) == 7 and all(type(v) is int and 0 <= v < FIELD_P for v in root), "noncanonical genesis root")
    require(identity["stablecoin_genesis_root"] == [0] * 7, "fresh stablecoin genesis must be empty")


def release_binding_layout(identity):
    identity_check(identity)
    if identity.get("schema") == ONGOING_IDENTITY_SCHEMA:
        return ("hegemon.private-spend.release-binding.v4", "network_manifest", "native_identity_receipt")
    return ("hegemon.private-spend.release-binding.v3", "mainnet_manifest", "mainnet_identity_receipt")


def release_binding_check(binding, identity):
    schema, manifest_key, receipt_key = release_binding_layout(identity)
    keys = {"schema", "identity", "assumptions", "gates", "pr205_contract", "runtime_predecessor",
            "formal_predecessor", "reviewed_runtime_delta", "runtime_delta_review", "runtime_inventory",
            "formal_inventory", "retained_binaries", "retained_proofs", manifest_key, receipt_key,
            "identity_native_binary", "authority_sources"}
    if schema.endswith(".v4"):
        keys |= {"ongoing_security_qualification", "ongoing_policy_qualification"}
    exact_keys(binding, keys, "binding")
    require(binding["schema"] == schema and binding["identity"] == identity, "binding identity/schema mismatch")
    return manifest_key, receipt_key


def network_manifest_check(manifest, identity):
    identity_check(identity)
    manifest_keys = ("schema", "profile", "genesis_timestamp_ms", "pow_bits", "rules_hash", "launch_reference_rules_hash", "funding_address", "funding_subsidy_numerator", "funding_subsidy_denominator")
    exact_keys(manifest, manifest_keys, "native network manifest")
    require(manifest["schema"] == "hegemon.native.network-manifest.v1" and
            manifest["profile"] == identity_network_profile(identity),
            "native manifest profile differs from the exact approved identity")
    require(type(manifest["funding_subsidy_numerator"]) is int and
            type(manifest["funding_subsidy_denominator"]) is int and
            (manifest["funding_subsidy_numerator"], manifest["funding_subsidy_denominator"]) == (1, 5), "wrong subsidy allocation")
    require(isinstance(manifest["funding_address"], str) and manifest["funding_address"], "network funding recipient absent")
    require(type(manifest["genesis_timestamp_ms"]) is int and manifest["genesis_timestamp_ms"] > 0 and type(manifest["pow_bits"]) is int and 0 < manifest["pow_bits"] < 1 << 32, "invalid genesis timestamp/PoW")
    for field in ("rules_hash", "launch_reference_rules_hash"):
        if identity.get("schema") == ONGOING_IDENTITY_SCHEMA:
            require(isinstance(manifest[field], str) and manifest[field].startswith("0x"),
                    field + " must retain the native canonical 0x prefix")
            hexadecimal(manifest[field][2:], 64, field)
        else:
            hexadecimal(manifest[field], 64, field)
    canonical = json.dumps({k: manifest[k] for k in manifest_keys}, separators=(",", ":"), ensure_ascii=False).encode()
    manifest_digest = hashlib.sha512(b"hegemon.native.network-manifest.sha512.v1\0" + canonical).hexdigest()
    require(manifest_digest == identity["manifest_digest"], "canonical manifest digest differs from source capability")


def native_network_identity_check(binding, identity):
    manifest_key, receipt_key = release_binding_check(binding, identity)
    manifest = load(pin(binding[manifest_key], "native network manifest"))
    network_manifest_check(manifest, identity)
    derived = load(pin(binding[receipt_key], "reviewed actual native identity derivation"))
    keys = {"schema", "identity", "manifest_sha256", "native_command", "native_executable_sha256", "actual_output"}
    ongoing = identity.get("schema") == ONGOING_IDENTITY_SCHEMA
    if ongoing:
        keys.add("network_profile")
    exact_keys(derived, keys, "native identity receipt")
    schema = "hegemon.private-spend.native-identity.v2" if ongoing else "hegemon.private-spend.mainnet-identity.v1"
    require(derived["schema"] == schema and derived["identity"] == identity and
            derived["manifest_sha256"] == binding[manifest_key]["sha256"], "native identity receipt does not bind this network")
    if ongoing:
        require(derived["network_profile"] == identity_network_profile(identity), "native receipt profile differs from approved identity")
    hexadecimal(derived["native_executable_sha256"], 64, "identity producer executable")
    pin(binding["identity_native_binary"], "actual final native identity binary")
    require(derived["native_executable_sha256"] == binding["identity_native_binary"]["sha256"], "identity producer is not the reviewed final native binary")
    require(isinstance(derived["native_command"], list) and derived["native_command"] and all(isinstance(arg, str) for arg in derived["native_command"]), "native derivation command absent")
    output_file = pin(derived["actual_output"], "native network identity output")
    if ongoing:
        output = load(output_file)
        require(output.get("genesis_hash") == "0x" + identity["genesis_hash"] and
                output.get("node_config", {}).get("networkManifest") == manifest and
                output["node_config"].get("networkProfile") == identity["network_profile"] and
                output["node_config"].get("chainId") == "0x" + identity["chain_id"] and
                output["node_config"].get("networkManifestDigest") == "0x" + identity["manifest_digest"],
                "actual native H0 output does not match exact network identity")
        ongoing_native_parameters_check(output.get("private_spend_parameters"))
    return manifest


def ongoing_native_parameters_check(parameters):
    require(isinstance(parameters, dict) and all(parameters.get(key) == ONGOING_POLICY_PROFILE[key]
            for key in ("relation_id", "relation_digest", "public_words", "max_proof_bytes", "max_carrier_bytes")),
            "actual ongoing native parameters differ from current bounded-policy relation86/caps")


# Exact ordered compact source closure; this list grants no qualification.
COMPACT_RELATION_SOURCE_PATHS = (
    'circuits/transaction/src/private_spend.rs',
    'circuits/transaction/src/private_spend/types.rs',
    'circuits/transaction/src/private_spend/circuit.rs',
    'circuits/transaction/src/private_spend/helpers.rs',
    'circuits/transaction/src/private_spend/proof.rs',
    'circuits/transaction/src/smallwood_htlc/circuit.rs',
    'circuits/transaction/src/smallwood_htlc/sha256.rs',
    'circuits/transaction/src/smallwood_htlc.rs',
    'circuits/transaction/src/smallwood_engine.rs',
    'circuits/transaction/src/smallwood_semantics.rs',
    'circuits/transaction/src/smallwood_hx512_transcript.rs',
    'circuits/transaction/src/smallwood_v6_transcript.rs',
    'circuits/transaction/src/smallwood_poseidon2_v8_rng_refinement.rs',
    'circuits/transaction/src/smallwood_poseidon2_v8_hash_schedule.rs',
    'circuits/transaction/src/smallwood_poseidon2_v8_types.rs',
    'circuits/transaction-core/src/constants.rs',
    'circuits/transaction-core/src/poseidon2_width16.rs',
    'circuits/transaction-core/src/poseidon2.rs',
    'circuits/transaction-core/src/hashing_pq.rs',
    'circuits/hegemon-field/src/lib.rs',
    'crypto/src/private_note_encryption.rs',
    'crypto/src/private_note_payload.rs',
    'crypto/src/ml_kem.rs',
    'crypto/src/deterministic.rs',
    'crypto/src/traits.rs',
    'crypto/hash384/src/lib.rs',
    'protocol/shielded-pool/src/private_spend_transport.rs',
    'protocol/versioning/src/launch_candidate_identity.rs',
    'circuits/transaction-core/src/bounded_policy.rs',
    'circuits/transaction/src/lib.rs',
    'circuits/transaction/src/smallwood_htlc/affine.rs',
    'circuits/transaction/src/smallwood_htlc/boolean_guards.rs',
    'circuits/transaction/src/smallwood_htlc/source_cse.rs',
    'circuits/transaction/src/smallwood_htlc/sha_lowering.rs',
    'circuits/transaction/src/smallwood_htlc/compact_sha256.rs',
    'circuits/transaction/src/smallwood_htlc/compact_sha_certificate.rs',
    'circuits/transaction/src/smallwood_htlc/compact_sha_lowering.rs',
    'circuits/transaction/src/smallwood_htlc/packed_poseidon_lowering.rs',
    'circuits/transaction/src/private_spend_packed_poseidon.rs',
    'circuits/transaction/src/smallwood_poseidon2_v8_hash_constraints.rs',
    'Cargo.lock',
)


def ongoing_policy_qualification(value):
    global _ONGOING_POLICY_SOURCE_APPROVED
    _ONGOING_POLICY_SOURCE_APPROVED = False
    require(isinstance(value, dict) and SOURCE_ONGOING_POLICY_QUALIFICATION_SHA256 is not None and
            value.get("sha256") == SOURCE_ONGOING_POLICY_QUALIFICATION_SHA256,
            "current bounded-policy relation lacks a source-owned security qualification")
    receipt = load(pin(value, "current bounded-policy relation qualification"))
    exact_keys(receipt, ("schema", "status", "qualified", "preparation_only", "production_authorized",
        "relation_profile", "source_inputs", "qualified_obligations", "retained_gate_sha256",
        "retained_predecessor_proofs", "assumptions", "cryptographic_class",
        "ongoing_security_qualification_sha256", "actual_checks", "independent_review"),
        "current bounded-policy qualification")
    require(receipt["schema"] == "hegemon.private-spend.ongoing-policy-relation-qualification.v1" and
            receipt["status"] == "QUALIFIED_CONDITIONAL" and receipt["qualified"] is True and
            receipt["preparation_only"] is False and receipt["production_authorized"] is False and
            receipt["relation_profile"] == ONGOING_POLICY_PROFILE and receipt["assumptions"] == list(ASSUMPTIONS) and
            receipt["cryptographic_class"] == ONGOING_CRYPTOGRAPHIC_CLASS and
            receipt["ongoing_security_qualification_sha256"] == SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256,
            "current policy relation is not actually conditionally qualified")
    sources = receipt["source_inputs"]
    expected_paths = list(COMPACT_RELATION_SOURCE_PATHS)
    require(isinstance(sources, list) and len(sources) == 41 and
            all(isinstance(row, dict) and isinstance(row.get("path"), str) for row in sources) and
            [row["path"] for row in sources] == expected_paths,
            "current policy qualification omits or reorders the exact41-source compact relation closure")
    relation_hash = hashlib.sha512(b"Hegemon.PrivateSpend.SourceManifest.v1" +
                                  ONGOING_POLICY_PROFILE["relation_id"].encode())
    for descriptor in sources:
        data = pin(descriptor, "current policy relation source").read_bytes()
        name = posixpath.relpath(descriptor["path"], "circuits/transaction/src").encode()
        relation_hash.update(struct.pack("<Q", len(name)))
        relation_hash.update(name)
        relation_hash.update(struct.pack("<Q", len(data)))
        relation_hash.update(data)
    require(relation_hash.hexdigest() == ONGOING_POLICY_RELATION,
            "qualified current policy source bytes do not reproduce actual native relation")
    obligations = receipt["qualified_obligations"]
    exact_keys(obligations, ("G1_current_relation", "G2_current_implementation_binding", "G3_current_relation",
        "G4_current_public_statement", "G5_current_history", "current_policy_privacy"), "current policy qualified obligations")
    for name, obligation in obligations.items():
        require(obligation.get("status") == "QUALIFIED_CONDITIONAL" and
                obligation.get("relation_profile") == ONGOING_POLICY_PROFILE and
                isinstance(obligation.get("endpoints"), list) and obligation["endpoints"] and
                all(isinstance(endpoint, str) and endpoint for endpoint in obligation["endpoints"]),
                name + " omits actual current-policy endpoint coverage")
        pinned_map(obligation.get("evidence"), name)
    exact_keys(receipt["retained_gate_sha256"], GATES, "policy historical gate bridge")
    for sha in receipt["retained_gate_sha256"].values():
        hexadecimal(sha, 64, "policy historical gate")
    exact_keys(receipt["retained_predecessor_proofs"], CASES, "policy historical proof bridge")
    pinned_map(receipt["actual_checks"], "policy actual qualification checks")
    review = load(pin(receipt["independent_review"], "current policy independent security review"))
    require(review.get("schema") == "hegemon.private-spend.ongoing-policy-independent-review.v1" and
            review.get("decision") == "GO_QUALIFIED_CURRENT_POLICY_RELATION" and
            isinstance(review.get("reviewer"), str) and review["reviewer"] and
            review.get("relation_profile") == ONGOING_POLICY_PROFILE and
            review.get("source_inputs_sha256") == canonical_hash(sources) and
            review.get("qualified_obligations_sha256") == canonical_hash(obligations) and
            review.get("actual_checks_sha256") == canonical_hash(receipt["actual_checks"]) and
            review.get("retained_gate_sha256") == receipt["retained_gate_sha256"] and
            review.get("retained_predecessor_proofs_sha256") == canonical_hash(receipt["retained_predecessor_proofs"]) and
            review.get("cryptographic_class") == ONGOING_CRYPTOGRAPHIC_CLASS and
            review.get("ongoing_security_qualification_sha256") == SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256 and
            review.get("assumptions") == list(ASSUMPTIONS) and review.get("production_authorized") is False,
            "current policy review does not bind exact new relation/statement/privacy and inherited evidence")
    _ONGOING_POLICY_SOURCE_APPROVED = True
    return receipt


def ongoing_security_qualification(value):
    require(isinstance(value, dict) and SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256 is not None and
            value.get("sha256") == SOURCE_ONGOING_SECURITY_QUALIFICATION_SHA256,
            "ongoing security class lacks an independently reviewed source-owned qualification pin")
    receipt = load(pin(value, "ongoing security class qualification"))
    require(receipt.get("schema") == "hegemon.private-spend.ongoing-security-qualification.v1" and
            receipt.get("status") == "QUALIFIED_CONDITIONAL" and receipt.get("qualified") is True and
            receipt.get("preparation_only") is False and receipt.get("production_authorized") is False,
            "ongoing security class is not actually conditionally qualified")
    require(receipt.get("cryptographic_class") == ONGOING_CRYPTOGRAPHIC_CLASS and
            receipt.get("gate_coverage") == ["G3", "G4", "G5"] and
            receipt.get("assumptions") == list(ASSUMPTIONS),
            "ongoing security qualification does not cover the exact all-attempt class and endpoints")
    pin(receipt["actual_checks"], "ongoing security actual checks")
    pin(receipt["independent_review"], "ongoing security independent review")


def release_lifecycle_identity_check(lifecycle, identity, artifacts, manifest):
    network_manifest_check(manifest, identity)
    require(lifecycle.get("schema") == "hegemon.private-spend.actualnode.compff01.v1" and
            lifecycle.get("status") == "PASS_LOCAL_RELEASE_TUPLE" and lifecycle.get("release_identity") == identity and
            lifecycle.get("artifact_sha256") == artifacts and lifecycle.get("manifest") == manifest and
            lifecycle.get("genesis") == "0x" + identity["genesis_hash"],
            "final approved network tuple/produced binaries were not actually lifecycle-validated")


COMPOSITE_SCHEMA = "hegemon.hgn-single-key.composite-lifecycle.v1"
COMPOSITE_COMPONENTS = ("external_lifecycle", "treasury_public_output", "custody_restore",
                        "disposable_treasury_spend", "semantic_bridge", "policy_regressions")
CURRENT_ACTION_CASES = {"fee_fund_1": "ordinary", "fee_fund_2": "ordinary", "claim_lock": "lock",
                        "claim": "claim", "refund_lock": "lock", "refund": "refund"}
DEFERRED_GATES = {name + suffix for name in ("approval1", "approval2", "final")
                  for suffix in ("", "_reorg_rollback", "_unchanged_resubmission")}
EXTERNAL_GATES = LIFECYCLE_GATES - DEFERRED_GATES - {"treasury_payout"}
BRIDGE_ROLES = set("reward_allocation public_opening_recovery recipient_authorization_seven_limbs key_derivation note_commitment_nullifier_codec maturity_membership witness_input_selection ordinary_relation_backend_transcript encryption_codec wallet_journal verifier_state_transition source_admission".split())
DISPOSABLE_OBLIGATIONS = set("immature_reject mature_membership ordinary_proof_generation both_nodes_identical_action first_eligible_inclusion nullifier_replay_reject reorg_rollback unchanged_resubmission restart_reverification".split())
POLICY_OBLIGATIONS = set("exact_identity_rejection no_source_rejection invalid_proof_rejection ongoing_past_old_sunset ongoing_past_old_accepted_quota finite_historical_expiry_and_quota partial_missing_limits_rejection source_per_block_cap_including_reward proof_byte_cap canonical_reference_freshness_and_height_codec nullifier_replay_rejection maturity_boundary_120 audit_counter_u64_overflow audit_counter_restart_reorg_replay no_source_empty_block finite_wallet_storage_compatibility".split())
COMPOSITE_OBLIGATIONS = EXTERNAL_GATES | DISPOSABLE_OBLIGATIONS | POLICY_OBLIGATIONS | {
    "treasury_public_output", "exact_custody_restore", "treasury_shared_wallet_readback",
    "treasury_shared_fresh_node_sync", "same_semantics_key_substitution"}


def pinned_map(value, label):
    require(isinstance(value, dict) and value, label + " evidence pins missing")
    for name, descriptor in value.items():
        require(isinstance(name, str) and name, label + " evidence name missing")
        pin(descriptor, label + " " + name)


def structured_obligations(rows, required, label, modes):
    require(isinstance(rows, list) and len(rows) == len(required) and
            {row.get("id") for row in rows} == required, label + " missing/duplicate/unknown obligations")
    for row in rows:
        exact_keys(row, ("id", "mode", "passed", "evidence"), label + " obligation")
        require(row["mode"] in modes and row["passed"] is True and
                isinstance(row["evidence"], list) and row["evidence"], label + " unsupported obligation")
        for assertion in row["evidence"]:
            exact_keys(assertion, ("receipt", "pointer", "expected"), label + " observed assertion")
            observed = load(pin(assertion["receipt"], label + " observed receipt"))
            pointer = assertion["pointer"]
            require(isinstance(pointer, list) and pointer, label + " concrete receipt field missing")
            for part in pointer:
                require((isinstance(observed, dict) and isinstance(part, str) and part in observed) or
                        (isinstance(observed, list) and type(part) is int and 0 <= part < len(observed)),
                        label + " observed receipt field absent")
                observed = observed[part]
            require(observed is not None and observed == assertion["expected"], label + " observed assertion differs")


def current_action_carrier(raw):
    """Read the exact independent PendingActionWire public_args, without rebuilding it."""
    def compact_len(pos):
        require(pos < len(raw), "truncated current action SCALE length")
        mode = raw[pos] & 3
        size = (1, 2, 4)[mode] if mode < 3 else (raw[pos] >> 2) + 5
        require((mode != 3 or size == 5) and pos + size <= len(raw), "invalid current action SCALE length")
        value = (int.from_bytes(raw[pos:pos + size], "little") >> 2 if mode < 3 else
                 int.from_bytes(raw[pos + 1:pos + size], "little"))
        require(mode == 0 or value >= (64, 16384, 1 << 30)[mode - 1], "noncanonical current action SCALE length")
        return value, pos + size
    require(len(raw) >= 104 and raw[52:56] == b"\x01\x00\x0f\x00", "wrong current private action route")
    cursor = 104
    for width in (48, 48, 48, 4):
        count, cursor = compact_len(cursor)
        require(count <= (len(raw) - cursor) // width, "truncated current action vector")
        cursor += count * width
    length, cursor = compact_len(cursor)
    end = cursor + length
    require(end + 9 == len(raw) and raw[end + 8] == 0, "current action framing/candidate artifact differs")
    carrier = raw[cursor:end]
    require(len(carrier) >= 208 and raw[end:end + 8] == carrier[200:208], "current action outer/inner fee differs")
    return carrier


def current_policy_proof_files(proofs, descriptors, actions, identity):
    exact_keys(proofs, CURRENT_ACTION_CASES, "six fresh action proof observations")
    exact_keys(descriptors, CURRENT_ACTION_CASES, "six fresh action proof file sets")
    for name, case in CURRENT_ACTION_CASES.items():
        record = proofs[name]
        exact_keys(descriptors[name], ("action", "carrier", "proof"), "fresh current proof files")
        files = {kind: pin(item, name + " current " + kind) for kind, item in descriptors[name].items()}
        proof, carrier, action = (files[kind].read_bytes() for kind in ("proof", "carrier", "action"))
        require(record.get("case") == case and record.get("wallet_local_proof_verify") is True and
                type(record.get("proof_bytes")) is int and record["proof_bytes"] == len(proof) and
                type(record.get("carrier_bytes")) is int and record["carrier_bytes"] == len(carrier) and
                4 <= len(proof) <= ONGOING_POLICY_PROFILE["max_proof_bytes"] and
                len(carrier) == len(proof) + ONGOING_POLICY_PROFILE["carrier_fixed_bytes"] and
                len(carrier) <= identity["max_proof_bytes"], "fresh proof/carrier measurements differ from actual files or current caps")
        require(proof[:4] == b"SMZL" and carrier[5784:] == proof and
                carrier[:24] == b"HGPSLC02" + bytes.fromhex("01000c00070001000f000800020c0100") and
                carrier[24:72] == bytes.fromhex(ONGOING_POLICY_RELATION)[:48] and
                carrier[72:104] == bytes.fromhex(identity["chain_id"]), "fresh carrier is not actual current policy transport/context")
        require(hashlib.sha512(proof).hexdigest() == record.get("proof_sha512") and
                hashlib.sha512(carrier).hexdigest() == record.get("carrier_sha512") and
                hashlib.sha256(action).hexdigest() == actions.get(name, {}).get("action_sha256") and
                current_action_carrier(action) == carrier, "fresh proof/carrier/action bytes do not join actual lifecycle")
        reference = int.from_bytes(carrier[136:144], "little")
        require(reference < 1 << 48 and reference == record.get("reference_parent_height") and
                "0x" + carrier[104:136].hex() == record.get("reference_parent_hash"), "fresh proof reference differs")
        words = [word[0] for word in struct.iter_unpack("<I", carrier[72:136])]
        words += [word[0] for word in struct.iter_unpack("<Q", carrier[136:432])]
        words += [word[0] for word in struct.iter_unpack("<I", carrier[432:528])]
        words += [int.from_bytes(carrier[528:536], "little")]
        words += [word[0] for word in struct.iter_unpack("<I", carrier[536:568])]
        require(len(words) == 86 and all(word < FIELD_P for word in words) and words[77] in (0, 1) and
                (words[77] == 1 or words[78:] == [0] * 8), "fresh current public86/release encoding is noncanonical")


def canonical_prefix_snapshot_files(rows):
    require(isinstance(rows, list) and rows, "canonical prefix snapshot list missing")
    names = []
    for row in rows:
        exact_keys(row, ("path", "sha256", "bytes"), "canonical prefix snapshot row")
        name = row["path"]
        require(isinstance(name, str) and name and not PurePosixPath(name).is_absolute() and
                PurePosixPath(name).parts and PurePosixPath(name).as_posix() == name and
                all(part not in (".", "..") for part in PurePosixPath(name).parts),
                "canonical prefix snapshot path escapes database")
        hexadecimal(row["sha256"], 64, "canonical prefix snapshot hash")
        require(type(row["bytes"]) is int and row["bytes"] >= 0, "canonical prefix snapshot length invalid")
        names.append(name)
    require(names == sorted(set(names)) and sum(row["bytes"] for row in rows) <= 32 * 2**20,
            "canonical prefix snapshot duplicate, unordered or oversized")


def canonical_prefix_continuation_shape(continuation):
    exact_keys(continuation, ("schema", "input", "parent_receipt", "parent_contract", "parent_binding",
        "current_contract", "initial_height", "initial_block_hash", "snapshot_files", "restored_node",
        "fresh_import_node", "peer_identity_reused", "wallet_state_reused", "prefix_remined", "parent_status",
        "fresh_native_import_verified", "readback", "verified_block_count"), "canonical prefix continuation")


def canonical_prefix_continuation_check(external, identity, artifacts, manifest, runtime_inventory):
    if "canonical_prefix_continuation" not in external:
        return
    continuation = external["canonical_prefix_continuation"]
    canonical_prefix_continuation_shape(continuation)
    require(continuation["schema"] == "hegemon.private-spend.canonical-prefix-continuation.v1" and
            continuation["restored_node"] == "node-a" and continuation["fresh_import_node"] == "node-b" and
            continuation["parent_status"] == "NON_PASS" and
            all(continuation[key] is False for key in ("peer_identity_reused", "wallet_state_reused", "prefix_remined")) and
            continuation["fresh_native_import_verified"] is True,
            "canonical prefix continuation origin/import boundary differs")
    def public(descriptor, label):
        exact_keys(descriptor, ("path", "sha256"), label)
        require(isinstance(descriptor["path"], str) and PurePosixPath(descriptor["path"]).is_absolute(),
                label + " requires original absolute public path")
        return load(evidence_pin(descriptor, label))
    checkpoint = public(continuation["input"], "canonical prefix input")
    exact_keys(checkpoint, ("schema", "parent_receipt", "parent_contract", "parent_binding", "database", "files",
                           "height", "block_hash"), "canonical prefix input")
    require(checkpoint["schema"] == "hegemon.private-spend.canonical-prefix-input.v1" and
            type(checkpoint["height"]) is int and 0 < checkpoint["height"] < 120 and
            re.fullmatch(r"0x[0-9a-f]{64}", checkpoint["block_hash"] or ""), "canonical prefix height/tip invalid")
    for key in ("parent_receipt", "parent_contract", "parent_binding"):
        require(continuation[key] == checkpoint[key], "canonical prefix parent descriptor differs")
    canonical_prefix_snapshot_files(checkpoint["files"])
    require(continuation["snapshot_files"] == checkpoint["files"] and
            type(continuation["initial_height"]) is int and continuation["initial_height"] == checkpoint["height"] and
            continuation["initial_block_hash"] == checkpoint["block_hash"] and
            type(continuation["verified_block_count"]) is int and
            continuation["verified_block_count"] == checkpoint["height"], "canonical prefix snapshot/count/tip differs")
    parent = public(continuation["parent_receipt"], "canonical prefix failed parent")
    old = public(continuation["parent_contract"], "canonical prefix parent contract")
    binding = public(continuation["parent_binding"], "canonical prefix parent binding")
    current = public(continuation["current_contract"], "canonical prefix current contract")
    keys = {"schema", "release_binding_sha256", "identity", "network_manifest", "runtime_inventory", "binaries",
            "artifact_sha256", "parameters", "cases", "transport", "compression_mode_id", "emission_schedule_id",
            "harness_sha256", "io_sha256", "watchdog_sha256"}
    exact_keys(old, keys, "canonical prefix old contract")
    exact_keys(current, keys, "canonical prefix current contract")
    changed = {"release_binding_sha256", "harness_sha256", "watchdog_sha256"}
    require(old["schema"] == "hegemon.private-spend.local-release-lifecycle-input.v2" and
            all(old[key] == current[key] for key in keys - changed) and current["identity"] == identity and
            current["artifact_sha256"] == artifacts and current["binaries"] == external.get("binaries") and
            current["runtime_inventory"]["sha256"] == runtime_inventory["sha256"] and
            current["parameters"] == external.get("parameters") and
            continuation["current_contract"]["sha256"] == external.get("contract_sha256") and
            current["harness_sha256"] == external.get("harness_sha256") and
            current["io_sha256"] == external.get("recovered_helper_sha256") and
            current["watchdog_sha256"] == external.get("progress_watchdog_sha256"),
            "canonical prefix changed runtime/proof contract or current producer")
    require(old["release_binding_sha256"] == continuation["parent_binding"]["sha256"] and
            binding.get("identity") == identity and
            binding.get("runtime_inventory", {}).get("sha256") == runtime_inventory["sha256"] and
            binding.get("network_manifest", {}).get("sha256") == old["network_manifest"]["sha256"] and
            load(evidence_pin(current["network_manifest"], "canonical prefix network manifest")) == manifest,
            "canonical prefix parent binding/network differs")
    require(parent.get("schema") == "hegemon.private-spend.actualnode.compff01.v1" and
            parent.get("status") == "NON_PASS" and parent.get("failure") == "no canonical mining height progress for600s" and
            parent.get("contract_sha256") == continuation["parent_contract"]["sha256"] and
            parent.get("harness_sha256") == old["harness_sha256"] and
            parent.get("recovered_helper_sha256") == old["io_sha256"] and
            parent.get("progress_watchdog_sha256") == old["watchdog_sha256"] and
            parent.get("release_identity") == identity and parent.get("artifact_sha256") == artifacts and
            parent.get("binaries") == current["binaries"] and
            parent.get("runtime_inventory_sha256") == runtime_inventory["sha256"] and
            parent.get("manifest") == manifest and parent.get("genesis") == "0x" + identity["genesis_hash"] and
            parent.get("miner") == external.get("miner") and parent.get("custody") == "external-single-key" and
            external.get("custody") == "external-single-key", "canonical prefix failed parent tuple differs")
    require(parent.get("gates") == {} and parent.get("fresh_proof_cases") == [] and
            not any(parent.get(key) for key in ("actions", "canonical_bodies", "pending", "canonical_prefix_continuation")),
            "canonical prefix inherits proof/action gates")
    require(all(parent.get(key) is True for key in ("all_owned_exit0", "all_owned_reaped", "rpc_closed")) and
            isinstance(parent.get("owned_processes"), list) and parent["owned_processes"] and
            all(isinstance(row, dict) and type(row.get("pid")) is int and row["pid"] > 1 and
                type(row.get("exit_code")) is int and row["exit_code"] == 0 and row.get("reaped") is True
                for row in parent["owned_processes"]), "canonical prefix parent cleanup incomplete")
    parent_path = PurePosixPath(checkpoint["parent_receipt"]["path"])
    require(parent_path.name == "receipt.json" and
            checkpoint["database"] == str(parent_path.parent / "node-a" / "native-chain.sled"),
            "canonical prefix database origin differs")
    readback = public(continuation["readback"], "canonical prefix actual readback")
    exact_keys(readback, ("schema", "genesis", "records", "nodes"), "canonical prefix actual readback")
    require(readback["schema"] == "hegemon.private-spend.canonical-prefix-readback.v1" and
            readback["genesis"] == parent["genesis"] and readback["nodes"] == ["node-a", "node-b"] and
            isinstance(readback["records"], list) and len(readback["records"]) == checkpoint["height"],
            "canonical prefix readback identity/count differs")
    previous = parent["genesis"]
    for number, record in enumerate(readback["records"], 1):
        exact_keys(record, ("height", "block_hash", "header", "body_metadata", "canonical_body_sha256",
                            "reward_action_sha256"), "canonical prefix block readback")
        require(type(record["height"]) is int and record["height"] == number and
                isinstance(record["header"], dict) and isinstance(record["body_metadata"], dict),
                "canonical prefix record height/header differs")
        header, meta = record["header"], record["body_metadata"]
        raw_number = header.get("number")
        require(type(raw_number) is int or (isinstance(raw_number, str) and re.fullmatch(r"0x[0-9a-fA-F]+", raw_number)),
                "canonical prefix header number invalid")
        observed_number = int(raw_number, 16) if isinstance(raw_number, str) else raw_number
        require(observed_number == number and header.get("parentHash") == previous and
                meta.get("parent_hash") == previous and type(meta.get("height")) is int and meta["height"] == number and
                type(meta.get("tx_count")) is int and meta["tx_count"] == 1 and
                meta.get("extrinsics_root") == header.get("extrinsicsRoot"), "canonical prefix header/body link differs")
        require(isinstance(record["block_hash"], str) and re.fullmatch(r"0x[0-9a-f]{64}", record["block_hash"]),
                "canonical prefix block hash invalid")
        for key in ("canonical_body_sha256", "reward_action_sha256"):
            hexadecimal(record[key], 64, "canonical prefix block " + key)
        previous = record["block_hash"]
    require(previous == checkpoint["block_hash"], "canonical prefix final tip differs")


def composite_lifecycle_checks(receipt, identity, artifacts, manifest, target, runtime_inventory):
    require(receipt.get("schema") == COMPOSITE_SCHEMA and
            receipt.get("status") == "PASS_LOCAL_HGN_SINGLE_KEY_COMPOSITE" and
            receipt.get("final_identity") == identity and receipt.get("artifact_sha256") == artifacts and
            receipt.get("target_triple") == target and receipt.get("manifest") == manifest and
            receipt.get("runtime_inventory") == runtime_inventory and
            receipt.get("production_authorized") is False and receipt.get("real_treasury_spend_exercised") is False and
            receipt.get("deferred_scope") == ["fresh_two_of_three_approval_final"],
            "composite lifecycle tuple, scope or nonproduction boundary differs")
    network_manifest_check(manifest, identity)
    pin(runtime_inventory, "composite runtime inventory")
    components = {name: load(pin(receipt[name], "composite " + name)) for name in COMPOSITE_COMPONENTS}
    for name in ("treasury_public_output", "semantic_bridge", "policy_regressions"):
        component = components[name]
        require(component.get("final_identity") == identity and component.get("target_triple") == target and
                component.get("artifact_sha256") == artifacts and component.get("runtime_inventory") == runtime_inventory,
                name + " does not bind exact final source/binaries/tuple")
    for name in COMPOSITE_COMPONENTS[1:]:
        pinned_map(components[name].get("evidence"), name)
    external = components["external_lifecycle"]
    require(external.get("schema") == "hegemon.private-spend.actualnode.compff01.v1" and
            external.get("status") == "PASS_LOCAL_EXTERNAL_TREASURY_NETWORK_LIFECYCLE" and
            external.get("release_identity") == identity and external.get("artifact_sha256") == artifacts and
            external.get("manifest") == manifest and external.get("genesis") == "0x" + identity["genesis_hash"] and
            external.get("treasury_spend_exercised") is False and
            external.get("treasury_custody_status") == "operator_custody_rehearsed_not_spent",
            "external lifecycle is not actual final external-custody execution")
    require(external.get("all_owned_exit0") is True and external.get("all_owned_reaped") is True and
            external.get("rpc_closed") is True, "external lifecycle has not cleanly completed")
    canonical_prefix_continuation_check(external, identity, artifacts, manifest, runtime_inventory)
    proofs = external.get("proofs", {})
    current_policy_proof_files(proofs, receipt.get("current_proofs"), external.get("actions", {}), identity)
    gates = external.get("gates", {})
    require(set(gates) == EXTERNAL_GATES | {"reward_maturity_wait"} and
            all(value is True for value in gates.values()),
            "external lifecycle omits required native/HTLC/public reward gates")
    require({"treasury_payout", "treasury_single_key_payout", "treasury_single_key_payout_reorg_rollback",
             "treasury_single_key_payout_unchanged_resubmission"}.issubset(external.get("unexercised_release_checks", [])),
            "external receipt hides unexecuted real treasury spend")
    require(external.get("binaries", {}).get("hegemon-node", {}).get("sha256") == artifacts["hegemon-node"],
            "external receipt ran a different native verifier")
    ongoing_native_parameters_check(external.get("parameters"))
    for name in ("private-spend", "treasury-v8"):
        pin(external["binaries"][name], "actual final production wallet tool")
    evidence_pins(external)
    public = components["treasury_public_output"]
    require(public.get("schema") == "hegemon.hgn-single-key.treasury-public-output.v1" and
            public.get("status") == "PASS_PUBLIC_OUTPUT" and public.get("funding_address") == manifest["funding_address"] and
            public.get("reward_height") == 1 and public.get("maturity_blocks") == 120 and
            public.get("first_spend_height") == 121, "real public treasury identity/maturity differs")
    for key in ("subsidy_atoms", "treasury_atoms", "miner_atoms", "fees_atoms", "output_position"):
        require(type(public.get(key)) is int and public[key] >= 0, "noncanonical public reward amount/position")
    require(public["treasury_atoms"] == public["subsidy_atoms"] // 5 and
            public["miner_atoms"] == public["subsidy_atoms"] - public["treasury_atoms"] + public["fees_atoms"] and
            public.get("opening", {}).get("asset_id") == 0 and
            public["opening"].get("value") == public["treasury_atoms"], "public reward allocation/opening differs")
    for key in ("authorization_limbs", "recipient_key", "commitment"):
        limbs = public.get(key)
        require(isinstance(limbs, list) and len(limbs) == (4 if key == "recipient_key" else 7) and
                all(type(limb) is int and 0 <= limb < FIELD_P for limb in limbs), "noncanonical public reward " + key)
    for key in ("block_hash", "action_sha256", "canonical_body_sha256"):
        hexadecimal(public.get(key), 64, "public reward " + key)
    readback = load(pin(public["native_readback"], "actual public reward native readback"))
    require(readback.get("status") == "PASS_PUBLIC_OUTPUT_NATIVE_READBACK" and
            readback.get("final_identity") == identity and readback.get("runtime_inventory") == runtime_inventory and
            readback.get("observed") == {key: public[key] for key in (
                "funding_address", "reward_height", "block_hash", "action_sha256", "canonical_body_sha256",
                "output_position", "opening", "recipient_key", "authorization_limbs", "commitment")} and
            readback.get("commitment_recomputed") is True and readback.get("restart_fresh_node_match") is True,
            "public output lacks actual decoding/commitment/canonical readback")
    pin(readback["producer"], "public readback native producer")
    custody = components["custody_restore"]
    require(custody.get("schema") == "hegemon.hgn-single-key.custody-restore.v1" and
            custody.get("status") == "PASS_EXACT_KEY_RESTORE" and custody.get("funding_address") == manifest["funding_address"] and
            custody.get("original_public_identity") == custody.get("restored_public_identity") == {
                "funding_address": manifest["funding_address"], "recipient_key": public["recipient_key"],
                "authorization_limbs": public["authorization_limbs"]}, "custody public identity/restore differs")
    hexadecimal(custody.get("backup_artifact_sha256"), 64, "backup provenance only")
    restore = load(pin(custody["restore_receipt"], "actual nonsecret custody restore receipt"))
    require(restore.get("status") == "PASS_EXACT_KEY_RESTORE" and
            restore.get("original_public_identity") == custody["original_public_identity"] and
            restore.get("restored_public_identity") == custody["restored_public_identity"] and
            restore.get("backup_artifact_sha256") == custody["backup_artifact_sha256"], "actual restore provenance differs")
    pin(custody["producer"], "reviewed custody restore producer")
    disposable = components["disposable_treasury_spend"]
    require(disposable.get("schema") == "hegemon.hgn-single-key.disposable-treasury-spend.v1" and
            disposable.get("status") == "PASS_RETAINED_OBLIGATIONS" and
            {"wallet_readback", "fresh_node_sync"}.issubset(disposable.get("unexercised", [])),
            "retained disposable evidence hides its missing execution")
    for key in ("source_inventory", "generation_receipt", "continuation_receipt", "action", "proof_carrier", "reward_evidence"):
        pin(disposable[key], "retained disposable " + key)
    pinned_map(disposable.get("producer_binaries"), "retained disposable binary")
    load(pin(disposable["generation_receipt"], "retained generation receipt"))
    continuation = load(pin(disposable["continuation_receipt"], "retained continuation receipt"))
    require(continuation.get("original_action_sha256") == disposable["action"]["sha256"],
            "retained treasury action does not join continuation")
    structured_obligations(disposable.get("obligations"), DISPOSABLE_OBLIGATIONS, "disposable", {"retained"})
    bridge = components["semantic_bridge"]
    require(bridge.get("schema") == "hegemon.hgn-single-key.treasury-semantic-bridge.v1" and
            bridge.get("status") == "PASS_SCOPED_SOURCE_BRIDGE" and bridge.get("limitations") and
            bridge.get("deferred_scope") == receipt["deferred_scope"] and
            all(bridge.get(name) == receipt[name] for name in ("disposable_treasury_spend", "treasury_public_output", "custody_restore")),
            "semantic bridge component inputs/scope differ")
    source_rows = bridge.get("source_rows")
    require(isinstance(source_rows, list) and len(source_rows) == len(BRIDGE_ROLES) and
            {row.get("role") for row in source_rows} == BRIDGE_ROLES, "semantic bridge source roles missing/duplicated")
    for row in source_rows:
        before = pin(row["before"], "bridge original source")
        after = pin(row["after"], "bridge current source")
        pin(row["review"], "bridge independent source review")
        require(row.get("comparison") in ("identical", "reviewed_delta") and row.get("affected_obligation_ids") and
                set(row["affected_obligation_ids"]).issubset(COMPOSITE_OBLIGATIONS), "bridge source obligation mapping missing")
        if row["comparison"] == "identical":
            require(digest(before) == digest(after), "claimed identical bridge source differs")
        else:
            pinned_map(row.get("fresh_affected_evidence"), "changed bridge source actual evidence")
    pin(bridge["independent_review"], "independent finite semantic bridge review")
    structured_obligations(bridge.get("obligation_map"), COMPOSITE_OBLIGATIONS, "composite bridge", {"fresh", "retained", "composed"})
    regressions = components["policy_regressions"]
    require(regressions.get("schema") == "hegemon.hgn-single-key.policy-regressions.v1" and
            regressions.get("status") == "PASS_AFFECTED_POLICY_REGRESSIONS" and
            isinstance(regressions.get("runs"), list) and regressions["runs"] and regressions.get("limitations"),
            "affected ongoing policy actual regressions missing")
    for run in regressions["runs"]:
        require(type(run.get("exit_code")) is int and run["exit_code"] == 0 and run.get("argv") and
                run.get("source_inventory") == runtime_inventory and run.get("test_names") and
                type(run.get("passed_tests")) is int and run["passed_tests"] > 0 and
                run.get("natural_exit") is True and run.get("reaped") is True,
                "affected policy run is absent, zero-test or incomplete")
        hexadecimal(run.get("binary_sha256"), 64, "policy test executable")
        pin(run["stdout"], "policy actual stdout"); pin(run["stderr"], "policy actual stderr")
    structured_obligations(regressions.get("obligation_map"), POLICY_OBLIGATIONS, "policy", {"fresh", "retained", "composed"})
    expected_mapping = {gate: ("deferred" if gate in DEFERRED_GATES else
        "composed" if gate in {"treasury_payout", "treasury_canonical_value"} else "fresh") for gate in LIFECYCLE_GATES}
    require(receipt.get("legacy_gate_map") == expected_mapping, "legacy gate mapping hides deferred or composed obligations")
    return {name: receipt[name]["sha256"] for name in COMPOSITE_COMPONENTS}


def check(record):
    exact_keys(record, ("binding", "independent_review", "workflow_sha256", "identity", "authority_sources"), "source release record")
    identity = record["identity"]
    identity_check(identity)
    hexadecimal(record["workflow_sha256"], 64, "workflow hash")
    require(digest(path(".github/workflows/release.yml")) == record["workflow_sha256"], "first release workflow changed")
    authority = record["authority_sources"]
    require(isinstance(authority, list) and len(authority) == 7 and
            {row["path"] for row in authority} == {CONTRACT, "scripts/check_private_spend_launch_authorization.py", "scripts/check_ci_release_gate_policy.py", "scripts/release_artifact_manifest.py", "scripts/release_private_spend_lifecycle.py", "scripts/release_private_spend_lifecycle_io.py", "scripts/release_private_spend_progress_watchdog.py"},
            "reviewed authority/checker source closure missing")
    for row in authority:
        pin(row, "reviewed authority source")
    binding_file = pin(record["binding"], "source-reviewed binding")
    binding = load(binding_file)
    release_binding_check(binding, identity)
    require(binding["authority_sources"] == authority, "binding authority mismatch")
    if identity.get("schema") == ONGOING_IDENTITY_SCHEMA:
        ongoing_security_qualification(binding["ongoing_security_qualification"])
        policy_qualification = ongoing_policy_qualification(binding["ongoing_policy_qualification"])
        require(policy_qualification["retained_gate_sha256"] == {
                    gate: binding["gates"][gate]["sha256"] for gate in GATES} and
                policy_qualification["retained_predecessor_proofs"] == binding["retained_proofs"],
                "current policy qualification does not bind these exact historical gates/proofs as predecessors")
    require(binding["assumptions"] == list(ASSUMPTIONS), "disclosed inherited assumptions changed")
    exact_keys(binding["gates"], GATES, "six gate receipts")
    require(len({binding["gates"][gate]["path"] for gate in GATES}) == 6 and
            len({binding["gates"][gate]["sha256"] for gate in GATES}) == 6, "aliased gate receipts")
    require(binding["pr205_contract"]["sha256"] == "a2386a76dadcb843c4e661327ee03c03ef357e14070c64384e6f340a9bda8952", "unchanged PR205 F1/F4 contract substituted")
    pin(binding["pr205_contract"], "unchanged PR205 boundary")
    formal_paths = source_closure(binding, identity)
    covered_formal = set()
    allow_historical_node_reference = (identity.get("schema") == ONGOING_IDENTITY_SCHEMA and
        _ONGOING_POLICY_SOURCE_APPROVED and SOURCE_HISTORICAL_G6_NODE_REFERENCE_SHA256 is not None)
    for gate in GATES:
        covered_formal.update(qualification(gate, binding["gates"][gate], formal_paths, identity=identity,
            allow_historical_node_reference=allow_historical_node_reference if gate in ("G2", "G6") else False))
    base_formal = load(pin(binding["formal_predecessor"], "formal predecessor final"))
    base_names = {name[len(RECORDED_SOURCE_ROOT) + 1:] for name in base_formal["retained_postimages_after"]}
    require(formal_paths == base_names | covered_formal, "formal inventory adds unreviewed or omits qualified endpoint sources")
    g6 = load(pin(binding["gates"]["G6"], "actual retained G6 binaries"))
    retained_g6_binaries(binding, g6, identity,
                        allow_historical_node_reference=allow_historical_node_reference)
    exact_keys(binding["retained_proofs"], CASES, "six retained proof cases")
    for case, proof in binding["retained_proofs"].items():
        proof_check(case, proof, predecessor=identity.get("schema") == ONGOING_IDENTITY_SCHEMA)
    native_network_identity_check(binding, identity)
    review = load(pin(record["independent_review"], "source-trusted independent G7 review"))
    exact_keys(review, ("schema", "decision", "reviewer", "binding_sha256", "gate_sha256", "identity", "assumptions", "authority_sources_sha256", "runtime_delta_sha256"), "independent review")
    require(review["schema"] == "hegemon.private-spend.independent-release-review.v2" and review["decision"] == "GO_QUALIFIED_SOURCE_TUPLE" and
            isinstance(review["reviewer"], str) and review["reviewer"], "actual independent review missing")
    require(review["binding_sha256"] == record["binding"]["sha256"] and review["identity"] == identity and
            review["assumptions"] == list(ASSUMPTIONS) and
            review["gate_sha256"] == {gate: binding["gates"][gate]["sha256"] for gate in GATES} and
            review["authority_sources_sha256"] == canonical_hash(authority) and
            review["runtime_delta_sha256"] == canonical_hash(binding["reviewed_runtime_delta"]), "G7 review is not of this exact complete package")
    native_capability(identity)
    # Rehash final inputs to detect changes during validation.
    for gate in GATES:
        pin(binding["gates"][gate], gate)
    source_closure(binding, identity)
    if identity.get("schema") == ONGOING_IDENTITY_SCHEMA:
        ongoing_security_qualification(binding["ongoing_security_qualification"])
        ongoing_policy_qualification(binding["ongoing_policy_qualification"])
    pin(record["binding"], "binding final")
    pin(record["independent_review"], "review final")
    return {"schema": "hegemon.private-spend.release-authorization.v2", "authorization_kind": "qualified_source_tuple",
            "binding_sha256": record["binding"]["sha256"], "g7_review_sha256": record["independent_review"]["sha256"],
            "identity": identity, "assumptions": list(ASSUMPTIONS), "deployment_verified": False}

def final_artifact_phase(rows, artifact_manifest, record, receipt):
    target = artifact_manifest.get("target_triple")
    matching = [row for row in rows if row.get("target_triple") == target]
    require(len(matching) == 1, "one source-owned final artifact/lifecycle authorization required for this target")
    row = matching[0]
    exact_keys(row, ("target_triple", "identity", "artifact_sha256", "lifecycle", "independent_review"), "source-owned final artifact record")
    require(row["identity"] == record["identity"], "final artifact identity differs from reviewed capability")
    artifacts = artifact_manifest.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 3 and
            tuple((item.get("package"), item.get("binary")) for item in artifacts) == (("hegemon-node", "hegemon-node"), ("wallet", "wallet"), ("walletd", "walletd")), "wrong final artifact identities")
    actual = {item["binary"]: item["sha256"] for item in artifacts}
    require(actual == row["artifact_sha256"], "final artifact digest is not source-authorized")
    final_binding = load(pin(record["binding"], "final native identity binding"))
    require(actual["hegemon-node"] == final_binding["identity_native_binary"]["sha256"], "final node differs from actual native identity producer")
    manifest_key, _ = release_binding_check(final_binding, record["identity"])
    manifest = load(pin(final_binding[manifest_key], "final approved network manifest"))
    lifecycle = load(pin(row["lifecycle"], "actual affected release lifecycle"))
    composite = lifecycle.get("schema") == COMPOSITE_SCHEMA
    require(record["identity"].get("schema") != ONGOING_IDENTITY_SCHEMA or composite,
            "ongoing HGN current-policy release requires its distinct composite lifecycle; historical77 receipts cannot qualify it")
    if composite:
        require(record["identity"].get("schema") == ONGOING_IDENTITY_SCHEMA,
                "composite successor requires the explicit ongoing HGN identity")
        component_hashes = composite_lifecycle_checks(lifecycle, record["identity"], actual, manifest,
                                                     target, final_binding["runtime_inventory"])
    else:
        release_lifecycle_identity_check(lifecycle, record["identity"], actual, manifest)
        require(lifecycle.get("binaries", {}).get("hegemon-node", {}).get("sha256") == actual["hegemon-node"] and
                lifecycle.get("parameters", {}).get("relation_digest") == CURRENT_RUNTIME_RELATION and
                lifecycle.get("parameters", {}).get("public_words") == 77, "affected lifecycle did not run the produced native verifier")
        lifecycle_checks(lifecycle)
        evidence_pins(lifecycle)
    review = load(pin(row["independent_review"], "actual final artifact independent review"))
    if composite:
        require(review.get("schema") == "hegemon.hgn-single-key.final-independent-review.v1" and
                review.get("decision") == "GO_LOCAL_HGN_SINGLE_KEY_COMPOSITE" and
                review.get("component_sha256") == component_hashes and
                review.get("runtime_inventory") == final_binding["runtime_inventory"] and
                review.get("checker_sha256") == digest(path("scripts/check_private_spend_launch_authorization.py")) and
                review.get("contract_sha256") == digest(path(CONTRACT)) and
                review.get("limitations") == load(pin(lifecycle["semantic_bridge"], "final bridge"))["limitations"] and
                review.get("production_authorized") is False and review.get("real_treasury_spend_exercised") is False,
                "composite final review omits exact checker/contract/components/limitations")
    else:
        require(review.get("schema") == "hegemon.private-spend.final-independent-review.v1" and
                review.get("decision") == "GO_ACTUAL_RELEASE_ARTIFACTS_AND_LIFECYCLE",
                "legacy final lifecycle review schema/decision differs")
    require(
            review.get("identity") == record["identity"] and review.get("target_triple") == target and
            review.get("artifact_sha256") == actual and review.get("lifecycle_sha256") == row["lifecycle"]["sha256"] and
            review.get("binding_sha256") == record["binding"]["sha256"] and review.get("assumptions") == list(ASSUMPTIONS), "final G7 review misses actual artifacts/lifecycle/current package")
    receipt["production_artifacts_verified"] = True
    receipt["affected_lifecycle_verified"] = True
    receipt["final_lifecycle_sha256"] = row["lifecycle"]["sha256"]
    receipt["final_review_sha256"] = row["independent_review"]["sha256"]
    if composite:
        receipt["lifecycle_scope"] = "hgn_single_key_composite"
        receipt["fresh_proof_cases"] = ["ordinary", "lock", "claim", "refund"]
        receipt["fresh_two_of_three_execution"] = False
        receipt["real_treasury_spend_exercised"] = False

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-authorized", action="store_true", help="explicit workflow intent; missing authority always rejects")
    parser.add_argument("--artifact-manifest", type=str, help="after the reviewed capability build, also verify the final existing release artifact manifest")
    args = parser.parse_args()
    try:
        registry = load(path(REGISTRY))
        exact_keys(registry, ("schema", "release", "final_artifacts"), "source registry")
        require(registry["schema"] == "hegemon.private-spend.source-authorized-registry.v2", "registry schema mismatch")
        require(isinstance(registry["final_artifacts"], list), "final source-owned artifact registry missing")
        require(registry["release"] is not None, "common PrivateSpend release is unqualified: G1-G3/G5/G7/exact native network tuple and source capability required")
        receipt = check(registry["release"])
        receipt["production_artifacts_verified"] = False
        if args.artifact_manifest:
            manifest_file = path(args.artifact_manifest)
            artifact_manifest = load(manifest_file)
            artifacts = artifact_manifest.get("artifacts")
            require(isinstance(artifacts, list) and len(artifacts) == 3, "final artifact manifest must name node/wallet/walletd")
            expected = (("hegemon-node", "hegemon-node"), ("wallet", "wallet"), ("walletd", "walletd"))
            require(tuple((item.get("package"), item.get("binary")) for item in artifacts) == expected, "wrong final artifact identities")
            command = [sys.executable, "-I", "-B", str(path("scripts/release_artifact_manifest.py")), "verify", "--manifest", str(manifest_file)]
            for item in artifacts:
                path(item["path"])
                command.extend(("--expect", item["package"] + ":" + item["binary"] + ":" + item["path"]))
            subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
            final_artifact_phase(registry["final_artifacts"], artifact_manifest, registry["release"], receipt)
            receipt["artifact_manifest_sha256"] = digest(manifest_file)
            # Repeat source, tuple and G1-G7 bindings immediately before packaging.
            check(registry["release"])
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, TypeError, KeyError, IndexError, struct.error, subprocess.CalledProcessError) as error:
        print("Common PrivateSpend release unauthorized: " + str(error), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
