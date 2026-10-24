//! Compile-time qualification evidence only; no runtime opt-in or proof cache.
//! Populate only from reviewed real prove+verify artifacts and their receipts.
//! A digest here records that review, not a proof that Rust or the OS is correct.
//! Scope: Development geometry eligibility. Complete native carrier alignment,
//! lifecycle acceptance, security qualification and production remain separate.
use super::DevelopmentRecoveryV1;
use anyhow::{anyhow, ensure, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use transaction_circuit::{asset_recovery_capsule_v1 as capsule, asset_recovery_wire_v1 as wire};

// Reviewed actual source-shape prove/verify evidence; Development geometry only.
// Neither manifest JSON nor command-line input can supply these measurements.
// Native lifecycle, security qualification and production remain separate gates.
const QUALIFIED_CATALOG_JSON: &str = r#"{
  "capsule_bundle": {
    "geometry_receipt": {
      "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule-bundle.geometry.json",
      "sha256": "e3bd5d3af5ec0261b808541618a06479d3f35b36daf5e181ee769ab5ab2b25cc"
    },
    "proof": {
      "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/proof.smrc",
      "sha256": "78f23d98fa6c99be8881353107400c9663193fde5fb33ea1f198547d60a43d12"
    },
    "resource_guard_receipt": {
      "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-capsule-v1.json",
      "sha256": "7eec38601ef9b2df7ee0d8850cc902aa8e7fb3cba759f081f7b9ee01abdc3d21"
    },
    "verification_receipt": {
      "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/report.json",
      "sha256": "4e75e16b71519aaaaa0fc7f966a8a4f93d14d98f055599487cc9ada7973f4ab5"
    },
    "wire_receipt": {
      "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule-bundle.wire.json",
      "sha256": "177c675ff4c1b0464b179e97c4df3160d2d888734bafb2bb27bf53488298f381"
    }
  },
  "cases": [
    {
      "proof": {
        "actual_inner_bytes": 1110901,
        "actual_outer_bytes": 1110981,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 7132,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 14254,
          "unstacked_cols": 14264,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/holder.geometry.json",
            "sha256": "98fd81771090683712d37994a9ec29ba09affc42806e8265dfe1ecc4fe49b47a"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/holder/proof.smzr",
            "sha256": "8e8c5d09c42d81e6a3045fc1cfc2860125b5e48885dc9b22b5c37f61b59bbb46"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/holder/report.json",
            "sha256": "41c0ed50ea289579f39007343e34a624fa12d3a0faae7dd145540cfd0c4e2305"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/holder.wire.json",
            "sha256": "1d386f768d2575eaff0119fabfd27d68dfe6d4b3c8ad0e0306f52e9041d947d7"
          }
        },
        "projected_inner_bytes": 1112437,
        "projected_outer_bytes": 1112517,
        "public_words": 182,
        "relation_digest": "c188d06745a115f37881db6cc6bc7850995a9f22ed2cc3afc0eaa7ce8c1a48f1a0f1e73df7ca81e1d92c00e6075b0df489a3b586ee2474738961df9dbfb82ade",
        "role": "spend"
      },
      "role": "transfer-holder"
    },
    {
      "proof": {
        "actual_inner_bytes": 1111541,
        "actual_outer_bytes": 1111621,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 7132,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 14254,
          "unstacked_cols": 14264,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/delegate.geometry.json",
            "sha256": "98fd81771090683712d37994a9ec29ba09affc42806e8265dfe1ecc4fe49b47a"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/delegate/proof.smzr",
            "sha256": "2f495767e5f7ba583f03ae05976a585c9ec31019b703cc0cf07b1d4c6a610e94"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/delegate/report.json",
            "sha256": "c5b56787b51e68422d2d471e445cc8f33f68843133b54a80f68efaec6dd1a5b0"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/delegate.wire.json",
            "sha256": "f9d8edf6e073eb2dedd4999b369cfaa7947b845c4384aa608a359be686694e4d"
          }
        },
        "projected_inner_bytes": 1112437,
        "projected_outer_bytes": 1112517,
        "public_words": 182,
        "relation_digest": "c188d06745a115f37881db6cc6bc7850995a9f22ed2cc3afc0eaa7ce8c1a48f1a0f1e73df7ca81e1d92c00e6075b0df489a3b586ee2474738961df9dbfb82ade",
        "role": "spend"
      },
      "role": "transfer-delegate"
    },
    {
      "proof": {
        "actual_inner_bytes": 1111093,
        "actual_outer_bytes": 1111173,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 7132,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 14254,
          "unstacked_cols": 14264,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/mint.geometry.json",
            "sha256": "98fd81771090683712d37994a9ec29ba09affc42806e8265dfe1ecc4fe49b47a"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/mint/proof.smzr",
            "sha256": "bf8e63806a444526d854110ca028421417c5af9b910bf391e22006d105020927"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/mint/report.json",
            "sha256": "4b00fed0fab40c7a2f4b880c59a514c46bcafeabfd585f65714660c26acf0a8c"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/mint.wire.json",
            "sha256": "e53e093b070c705c6289c23c0379d7f875b67ca1762481061b19790b2d68f449"
          }
        },
        "projected_inner_bytes": 1112437,
        "projected_outer_bytes": 1112517,
        "public_words": 182,
        "relation_digest": "c188d06745a115f37881db6cc6bc7850995a9f22ed2cc3afc0eaa7ce8c1a48f1a0f1e73df7ca81e1d92c00e6075b0df489a3b586ee2474738961df9dbfb82ade",
        "role": "spend"
      },
      "role": "mint"
    },
    {
      "proof": {
        "actual_inner_bytes": 1110837,
        "actual_outer_bytes": 1110917,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 7132,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 14254,
          "unstacked_cols": 14264,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/burn.geometry.json",
            "sha256": "98fd81771090683712d37994a9ec29ba09affc42806e8265dfe1ecc4fe49b47a"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/burn/proof.smzr",
            "sha256": "6c6528128fd3328ec0fbf133febc157bb19833de6070f13437be4f03d5d0e58b"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/burn/report.json",
            "sha256": "1e6a979bfa1180d75fd113469306976ff06bcc415ddba94ffae0825217c6be4f"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/burn.wire.json",
            "sha256": "c1492205d89de6c40afcecb140ec636f8cdc1daac066382301c1f202035a3177"
          }
        },
        "projected_inner_bytes": 1112437,
        "projected_outer_bytes": 1112517,
        "public_words": 182,
        "relation_digest": "c188d06745a115f37881db6cc6bc7850995a9f22ed2cc3afc0eaa7ce8c1a48f1a0f1e73df7ca81e1d92c00e6075b0df489a3b586ee2474738961df9dbfb82ade",
        "role": "spend"
      },
      "role": "burn"
    },
    {
      "proof": {
        "actual_inner_bytes": 216125,
        "actual_outer_bytes": 216205,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 549,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 1088,
          "unstacked_cols": 1098,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/admin_rotation.geometry.json",
            "sha256": "dadd3a03393579e319c696b093e14863f079999400d70993a6f01a588d4b75cc"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/admin_rotation/proof.smzr",
            "sha256": "1e745ec2dae5c5479609e44945a66522aeeb8a70c1afb4e9c5e361a9f723bafb"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/admin_rotation/report.json",
            "sha256": "546ada8c970485548de454a2162b62d26793652c957408592acbc59051a25a7f"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/admin_rotation.wire.json",
            "sha256": "325580adee2bbe454e25078c1106f303a6af5fa33f63857a92a993e9c2dfc03f"
          }
        },
        "projected_inner_bytes": 217149,
        "projected_outer_bytes": 217229,
        "public_words": 128,
        "relation_digest": "70fed2c976de2194bd0cc55ceb16a2932b5beb7c0441f40caa23172b4ed227f6e46c8cdc4499ea42d79d161b06d2079f64e4ef2e0c652fab0d5efc0fa3ae7310",
        "role": "admin"
      },
      "role": "admin-none"
    },
    {
      "proof": {
        "actual_inner_bytes": 598509,
        "actual_outer_bytes": 598589,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 3363,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 6716,
          "unstacked_cols": 6726,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/admin_note_freeze.geometry.json",
            "sha256": "db6a9d69759615be0343d5afa0f9a5c84d3ca620dc955094db927d34f859f66d"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/admin_note_freeze/proof.smzr",
            "sha256": "d6d6b7024157ade2fee3e0c4cd8f07cc1bf91f48ea0351d45d902fa248cde05c"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-primary-shapes-v1.json",
            "sha256": "a903c6c25d94eb35825dea306a72e77d06b2a8fa3c9dad8e0fc536c0f61e636d"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/admin_note_freeze/report.json",
            "sha256": "96fad68c9490614255055976b987b37e1d60b934a739c95bd8b770bba943acb2"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/admin_note_freeze.wire.json",
            "sha256": "5035c36d4f9652ccecfd6ef0d8639c34fb965d71417ac24ea209b00e0a27ccb7"
          }
        },
        "projected_inner_bytes": 599853,
        "projected_outer_bytes": 599933,
        "public_words": 128,
        "relation_digest": "70fed2c976de2194bd0cc55ceb16a2932b5beb7c0441f40caa23172b4ed227f6e46c8cdc4499ea42d79d161b06d2079f64e4ef2e0c652fab0d5efc0fa3ae7310",
        "role": "admin"
      },
      "role": "admin-some"
    },
    {
      "proof": {
        "actual_inner_bytes": 1940893,
        "actual_outer_bytes": 1940973,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 13233,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 26456,
          "unstacked_cols": 26466,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule0.geometry.json",
            "sha256": "2a54a0a316c634a18a9b33599e3176beb5a2514e59a68a699a340be8cdf793ec"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/component-0.smzr",
            "sha256": "a2a7832352ec38f9e00f9604b1b7b6e7cceb8fa0baac0e960ac5ee4cb356eb6d"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-capsule-v1.json",
            "sha256": "7eec38601ef9b2df7ee0d8850cc902aa8e7fb3cba759f081f7b9ee01abdc3d21"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/report.json",
            "sha256": "4e75e16b71519aaaaa0fc7f966a8a4f93d14d98f055599487cc9ada7973f4ab5"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule0.wire.json",
            "sha256": "881adb03b1ffdb1f01c85053c813b27d2578c45cfc011abaac49919558999646"
          }
        },
        "projected_inner_bytes": 1942173,
        "projected_outer_bytes": 1942253,
        "public_words": 82,
        "relation_digest": "44896d9bf3ed82272a8aef3dcce000a2dd48e4f730ddc6c42ef146425d8bb9a84fa7a29e2071fb9eb41e06ec0f2de2265baf8f92898a553e32f05ad819e72dc5",
        "role": "capsule.segment0"
      },
      "role": "capsule-segment0"
    },
    {
      "proof": {
        "actual_inner_bytes": 1633117,
        "actual_outer_bytes": 1633197,
        "dimensions": {
          "constraint_degree": 2,
          "lvcs_cols": 10967,
          "lvcs_opened": 12,
          "lvcs_rows": 140,
          "mlin_degree": 132,
          "mpol_degree": 74,
          "packing": 64,
          "polys": 21923,
          "unstacked_cols": 21933,
          "unstacked_rows": 70,
          "witness_polynomial_degree": 69
        },
        "evidence": {
          "geometry_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule1.geometry.json",
            "sha256": "0c069d949119c4e2982ac42d0fd9469f0dc191d82c7de7d91bf21c2ba5beaf9c"
          },
          "proof": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/component-1.smzr",
            "sha256": "04035650fa8cd9bfd8ed71b360e1654f7d07244f5c78228200c514c931ac39f8"
          },
          "resource_guard_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/guard-floor40-v1/runs/actual-capsule-v1.json",
            "sha256": "7eec38601ef9b2df7ee0d8850cc902aa8e7fb3cba759f081f7b9ee01abdc3d21"
          },
          "verification_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/actual-proofs-v1/capsule/report.json",
            "sha256": "4e75e16b71519aaaaa0fc7f966a8a4f93d14d98f055599487cc9ada7973f4ab5"
          },
          "wire_receipt": {
            "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/capsule1.wire.json",
            "sha256": "ec70d6e344068d0a0823f10b5ef611bcbd0eb709120c8ae1482f2376f32a8cd6"
          }
        },
        "projected_inner_bytes": 1633949,
        "projected_outer_bytes": 1634029,
        "public_words": 82,
        "relation_digest": "bf6b775aba12dd804fd19a7f45a3b955230a98d8fb7951fa9b4383768bb587b37a8c31550d9e98b20ad183bcc3617fbef5436b7f5a2b7834dbce4e6e8ea3ca76",
        "role": "capsule.segment1"
      },
      "role": "capsule-segment1"
    }
  ],
  "credential_depth": 4,
  "independent_review_receipt": {
    "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/independent-review-v1.json",
    "sha256": "7524c85e448113edd194bf6c6d92d5abb70b1cfb4ba9f505c8c3ba92dfeff8dd"
  },
  "max_actions_per_block": 1,
  "max_admin_action_bytes": 2098260,
  "max_capsule_bundle_bytes": 4194320,
  "max_component_bytes": 2097152,
  "max_spend_action_bytes": 10496540,
  "measured_capsule_bundle_bytes": 3574186,
  "negative_checks_receipt": {
    "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/negative-checks.json",
    "sha256": "2f6b68412382f8bb53e4d2143f5718fad67ca9160a5657e7926127f20ac5a12d"
  },
  "profile": {
    "beta": 2,
    "decs_eta": 5,
    "decs_nb_evals": 8388608,
    "decs_nb_opened_evals": 58,
    "decs_pow_bits": 0,
    "nb_opened_evals": 6,
    "opening_pow_bits": 0,
    "rho": 5
  },
  "proof_units": 5,
  "qualification_binary": {
    "path": "target-stablecoin/retained-proof/deps/transaction_circuit-e5e94c168046e97d",
    "sha256": "7117f6294a8a6c03a255a95b54ef5c28176f7e66ab421c5d1598c5d685145306"
  },
  "qualification_receipt": {
    "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/qualification-readback.json",
    "sha256": "fbc38d1043b314e5130ffc712fa146979b42bf405be368be3334f40104136e98"
  },
  "qualification_tool": {
    "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/generate.py",
    "sha256": "6a7b2cdaab833406f1624a04c4f5ef51f74e6877fdb33a2861340edab1d3cf9c"
  },
  "schema": "hegemon.native.recovery-geometry-catalog.v1",
  "source_manifest": {
    "path": ".agent/stablecoin-network-controls-v1/qualification/catalog/proposed-independent-review-v1/source-manifest.json",
    "sha256": "30d8c5e4ec8709e2f268797477a2f3f426ecd76a1469ce98f731bdcb859490d4"
  },
  "sources": {
    "admin": "70fed2c976de2194bd0cc55ceb16a2932b5beb7c0441f40caa23172b4ed227f6e46c8cdc4499ea42d79d161b06d2079f64e4ef2e0c652fab0d5efc0fa3ae7310",
    "capsule": "23c8011bf40ab50d034cd92ea1956217b295132a4bac00b1f03d409ff7230f24737e6ec8f0e12e9614b27f27063241e6d57eb08c554ea305c673128aa3e4cce9",
    "files": [
      {
        "path": "circuits/transaction/src/asset_recovery_spend_v1.rs",
        "sha256": "2ce69a01c93e7fcba564ced4c09e5f04036921f7b00eec04c2d8b99ba7f9437b"
      },
      {
        "path": "circuits/transaction/src/asset_recovery_admin_v1.rs",
        "sha256": "9da5ed49ae4aba77986d090251c0af803a194d0786334ed41d525eb072caad13"
      },
      {
        "path": "circuits/transaction/src/asset_recovery_capsule_v1.rs",
        "sha256": "381bc9dfd52fd84d83a83c264d8a711000fb6e3efec5f71fc36923f413eaebeb"
      },
      {
        "path": "circuits/transaction/src/asset_recovery_chacha_v1.rs",
        "sha256": "523246cbd6a5440eddb5d62a09877bee29adac45fd7f01f8e996cfa9b386c284"
      },
      {
        "path": "circuits/transaction/src/asset_recovery_backend_v1.rs",
        "sha256": "916619fdb91aff4e5582d4c7e4a1ec8da4fdc3de69a2a705f32ec0fc5a4d1825"
      },
      {
        "path": "circuits/transaction/src/asset_recovery_wire_v1.rs",
        "sha256": "d910a6fc82063ae155c80ca545005f1d7f76887a7f47e4985539ee03451b66d0"
      },
      {
        "path": "circuits/transaction-core/src/asset_recovery_v1.rs",
        "sha256": "cecc97d5e0e99f5f45986667ce1abdb8c4d8c1cb1d1879cccb5d6a6827bb708f"
      },
      {
        "path": "circuits/transaction/src/smallwood_engine.rs",
        "sha256": "fd0f379f2785cfc0ff07fa9d1bf2858dbcfbaceb69cf43349af5579fa33f1938"
      },
      {
        "path": "circuits/transaction/src/smallwood_semantics.rs",
        "sha256": "e9230ee4e62490800052627a014521e4a7c9403875d1504864183cd105e61e51"
      },
      {
        "path": "circuits/transaction/src/smallwood_htlc.rs",
        "sha256": "e5926e5bee015a4cdc5c09c316e4fc0640a45fd0a7d6fee94abcd0d6869b901f"
      }
    ],
    "segments": [
      "44896d9bf3ed82272a8aef3dcce000a2dd48e4f730ddc6c42ef146425d8bb9a84fa7a29e2071fb9eb41e06ec0f2de2265baf8f92898a553e32f05ad819e72dc5",
      "bf6b775aba12dd804fd19a7f45a3b955230a98d8fb7951fa9b4383768bb587b37a8c31550d9e98b20ad183bcc3617fbef5436b7f5a2b7834dbce4e6e8ea3ca76"
    ],
    "spend": "c188d06745a115f37881db6cc6bc7850995a9f22ed2cc3afc0eaa7ce8c1a48f1a0f1e73df7ca81e1d92c00e6075b0df489a3b586ee2474738961df9dbfb82ade"
  },
  "wire_version": 2
}
"#;
const SCHEMA: &str = "hegemon.native.recovery-geometry-catalog.v1";
// These are the six primary source shapes and the two components of the
// standalone capsule collection. Full native carrier acceptance is a later
// lifecycle gate: requiring it here would prevent constructing that node.
const CASES: [&str; 8] = [
    "transfer-holder",
    "transfer-delegate",
    "mint",
    "burn",
    "admin-none",
    "admin-some",
    "capsule-segment0",
    "capsule-segment1",
];

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePin {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    spend: String,
    admin: String,
    capsule: String,
    segments: [String; 2],
    files: Vec<FilePin>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    // Relative artifact paths and exact SHA256s are all public. No witness,
    // secret material, argv, or private test state belongs in the catalog.
    proof: FilePin,
    geometry_receipt: FilePin,
    wire_receipt: FilePin,
    verification_receipt: FilePin,
    resource_guard_receipt: FilePin,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dimensions {
    packing: usize,
    constraint_degree: usize,
    witness_polynomial_degree: usize,
    mpol_degree: usize,
    mlin_degree: usize,
    polys: usize,
    lvcs_rows: usize,
    lvcs_opened: usize,
    lvcs_cols: usize,
    unstacked_cols: usize,
    unstacked_rows: usize,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofMeasurement {
    role: String,
    relation_digest: String,
    public_words: usize,
    dimensions: Dimensions,
    projected_inner_bytes: usize,
    projected_outer_bytes: usize,
    actual_inner_bytes: usize,
    actual_outer_bytes: usize,
    evidence: Evidence,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseMeasurement {
    role: String,
    proof: ProofMeasurement,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema: String,
    sources: Sources,
    profile: transaction_circuit::SmallwoodNoGrindingProfileV1,
    credential_depth: u8,
    wire_version: u16,
    proof_units: usize,
    max_component_bytes: usize,
    max_capsule_bundle_bytes: usize,
    max_spend_action_bytes: usize,
    max_admin_action_bytes: usize,
    max_actions_per_block: usize,
    measured_capsule_bundle_bytes: usize,
    capsule_bundle: Evidence,
    source_manifest: FilePin,
    qualification_binary: FilePin,
    qualification_tool: FilePin,
    negative_checks_receipt: FilePin,
    qualification_receipt: FilePin,
    independent_review_receipt: FilePin,
    cases: Vec<CaseMeasurement>,
}

fn compiled_sources() -> Result<Sources> {
    let capsule_digest = capsule::relation_digest();
    let files: &[(&str, &[u8])] = &[
        (
            "circuits/transaction/src/asset_recovery_spend_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_spend_v1.rs"),
        ),
        (
            "circuits/transaction/src/asset_recovery_admin_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_admin_v1.rs"),
        ),
        (
            "circuits/transaction/src/asset_recovery_capsule_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_capsule_v1.rs"),
        ),
        (
            "circuits/transaction/src/asset_recovery_chacha_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_chacha_v1.rs"),
        ),
        (
            "circuits/transaction/src/asset_recovery_backend_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_backend_v1.rs"),
        ),
        (
            "circuits/transaction/src/asset_recovery_wire_v1.rs",
            include_bytes!("../../../../circuits/transaction/src/asset_recovery_wire_v1.rs"),
        ),
        (
            "circuits/transaction-core/src/asset_recovery_v1.rs",
            include_bytes!("../../../../circuits/transaction-core/src/asset_recovery_v1.rs"),
        ),
        (
            "circuits/transaction/src/smallwood_engine.rs",
            include_bytes!("../../../../circuits/transaction/src/smallwood_engine.rs"),
        ),
        (
            "circuits/transaction/src/smallwood_semantics.rs",
            include_bytes!("../../../../circuits/transaction/src/smallwood_semantics.rs"),
        ),
        (
            "circuits/transaction/src/smallwood_htlc.rs",
            include_bytes!("../../../../circuits/transaction/src/smallwood_htlc.rs"),
        ),
    ];
    Ok(Sources {
        spend: hex::encode(transaction_circuit::asset_recovery_spend_v1::relation_digest()),
        admin: hex::encode(transaction_circuit::asset_recovery_admin_v1::relation_digest()),
        capsule: hex::encode(capsule_digest),
        segments: [
            hex::encode(
                capsule::segment_relation_digest(capsule_digest, 0)
                    .map_err(|e| anyhow!("segment identity: {e}"))?,
            ),
            hex::encode(
                capsule::segment_relation_digest(capsule_digest, 1)
                    .map_err(|e| anyhow!("segment identity: {e}"))?,
            ),
        ],
        files: files
            .iter()
            .map(|(path, bytes)| FilePin {
                path: (*path).into(),
                sha256: hex::encode(Sha256::digest(bytes)),
            })
            .collect(),
    })
}
fn file_pin(pin: &FilePin) -> Result<()> {
    ensure!(
        !pin.path.is_empty()
            && !pin.path.starts_with('/')
            && !pin.path.contains('\\')
            && !pin
                .path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "recovery geometry evidence must use an exact relative artifact path"
    );
    ensure!(
        pin.sha256.len() == 64
            && pin
                .sha256
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && pin.sha256 != "0".repeat(64),
        "recovery geometry evidence requires a nonzero lowercase SHA256"
    );
    Ok(())
}
fn validate_catalog(value: &Catalog, selected: &DevelopmentRecoveryV1) -> Result<()> {
    selected.validate()?;
    let expected_profile = transaction_circuit::SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 6,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1 << 23,
        decs_nb_opened_evals: 58,
        decs_eta: 5,
        decs_pow_bits: 0,
    };
    let compiled_profile = transaction_circuit::smallwood_no_grinding_profile_for_arithmetization(
        transaction_circuit::SmallwoodArithmetization::DirectPacked64AssetSpendSha512Smze,
    );
    ensure!(
        value.schema == SCHEMA
            && value.sources == compiled_sources()?
            && value.profile == expected_profile
            && value.profile == compiled_profile,
        "recovery geometry catalog differs from compiled sources or unchanged SMZE profile"
    );
    ensure!(
        value.credential_depth == 4
            && value.credential_depth == selected.credential_depth
            && value.wire_version == wire::VERSION
            && value.wire_version == selected.wire_version
            && value.proof_units == 5
            && value.proof_units == wire::PROOF_UNITS
            && value.max_component_bytes == 2 * 1024 * 1024
            && value.max_component_bytes == wire::MAX_PROOF_BYTES
            && value.max_capsule_bundle_bytes == capsule::MAX_CAPSULE_BUNDLE_BYTES
            && value.max_spend_action_bytes == wire::MAX_SPEND_ACTION_BYTES
            && value.max_spend_action_bytes == selected.max_action_bytes
            && value.max_admin_action_bytes == wire::MAX_ADMIN_ACTION_BYTES
            && value.max_actions_per_block == 1
            && value.max_actions_per_block == selected.max_actions_per_block,
        "recovery geometry catalog changes finite wire, credential or proof limits"
    );
    for pin in [
        &value.source_manifest,
        &value.qualification_binary,
        &value.qualification_tool,
        &value.negative_checks_receipt,
        &value.qualification_receipt,
        &value.independent_review_receipt,
        &value.capsule_bundle.proof,
        &value.capsule_bundle.geometry_receipt,
        &value.capsule_bundle.wire_receipt,
        &value.capsule_bundle.verification_receipt,
        &value.capsule_bundle.resource_guard_receipt,
    ] {
        file_pin(pin)?;
    }
    ensure!(
        value.cases.len() == CASES.len(),
        "recovery geometry requires every accepted role"
    );
    for (case, expected_role) in value.cases.iter().zip(CASES) {
        ensure!(
            case.role == expected_role,
            "recovery geometry roles are missing, duplicated or reordered"
        );
        let proof = &case.proof;
        let (role, source, words) = if expected_role.starts_with("admin-") {
            (
                "admin",
                &value.sources.admin,
                transaction_circuit::asset_recovery_admin_v1::PUBLIC_WORDS,
            )
        } else if expected_role.starts_with("capsule-") {
            let segment = usize::from(expected_role.ends_with('1'));
            (
                if segment == 0 {
                    "capsule.segment0"
                } else {
                    "capsule.segment1"
                },
                &value.sources.segments[segment],
                capsule::PUBLIC_WORDS,
            )
        } else {
            (
                "spend",
                &value.sources.spend,
                transaction_circuit::asset_recovery_spend_v1::PUBLIC_WORDS,
            )
        };
        ensure!(
            proof.role == role,
            "recovery geometry component role mismatch"
        );
        ensure!(
            &proof.relation_digest == source && proof.public_words == words,
            "recovery geometry component source/public framing mismatch"
        );
        let d = &proof.dimensions;
        ensure!(
            d.packing > 0
                && d.constraint_degree > 0
                && d.witness_polynomial_degree > 0
                && d.mpol_degree > 0
                && d.mlin_degree > 0
                && d.polys > 0
                && d.lvcs_rows > 0
                && d.lvcs_opened > 0
                && d.lvcs_cols > 0
                && d.unstacked_cols > 0
                && d.unstacked_rows > 0,
            "recovery geometry dimensions must be measured and nonzero"
        );
        ensure!(
            proof.actual_inner_bytes > 0
                && proof.projected_inner_bytes > 0
                && proof.actual_inner_bytes.checked_add(80) == Some(proof.actual_outer_bytes)
                && proof.projected_inner_bytes.checked_add(80) == Some(proof.projected_outer_bytes)
                && proof.actual_outer_bytes <= value.max_component_bytes
                && proof.projected_outer_bytes <= value.max_component_bytes,
            "recovery geometry component exceeds exact SMZR/2MiB framing"
        );
        for pin in [
            &proof.evidence.proof,
            &proof.evidence.geometry_receipt,
            &proof.evidence.wire_receipt,
            &proof.evidence.verification_receipt,
            &proof.evidence.resource_guard_receipt,
        ] {
            file_pin(pin)?;
        }
    }
    let capsule0 = &value.cases[6].proof;
    let capsule1 = &value.cases[7].proof;
    ensure!(
        capsule::BUNDLE_HEADER_BYTES + capsule0.actual_outer_bytes + capsule1.actual_outer_bytes
            == value.measured_capsule_bundle_bytes
            && value.measured_capsule_bundle_bytes <= value.max_capsule_bundle_bytes,
        "recovery geometry measured capsule collection byte mismatch"
    );
    // Derive the finite carrier ceiling from actual component grammar. This
    // does not assert that any complete five-proof native carrier was accepted.
    ensure!(
        wire::SPEND_FIXED_BYTES + value.max_component_bytes + 2 * value.max_capsule_bundle_bytes
            == value.max_spend_action_bytes
            && wire::ADMIN_FIXED_BYTES + value.max_component_bytes == value.max_admin_action_bytes
            && capsule::BUNDLE_HEADER_BYTES + 2 * value.max_component_bytes
                == value.max_capsule_bundle_bytes,
        "recovery geometry derived action/bundle ceiling mismatch"
    );

    Ok(())
}

pub(super) fn require(selected: &DevelopmentRecoveryV1) -> Result<()> {
    let catalog: Option<Catalog> = serde_json::from_str(QUALIFIED_CATALOG_JSON)
        .map_err(|error| anyhow!("compiled recovery geometry catalog rejected: {error}"))?;
    let catalog = catalog
        .ok_or_else(|| anyhow!("recovery source-bound geometry qualification is pending"))?;
    validate_catalog(&catalog, selected)
}

#[cfg(test)]
pub(super) fn retained_catalog_matches_current_sources_for_test() -> bool {
    let catalog: Catalog = serde_json::from_str(QUALIFIED_CATALOG_JSON).unwrap();
    catalog.sources == compiled_sources().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selected() -> DevelopmentRecoveryV1 {
        DevelopmentRecoveryV1::compiled(vec![super::super::RecoveryGenesisConfigV1 {
            asset_id: 1001,
            stable_policy_id: [7; 7],
            policy_admin_commitment: [2; 7],
            archive_key_commitment: [8; 7],
            maximum_powers_bits: 3,
            initial_delegate_commitment: [9; 7],
            initial_revoked: false,
            initial_powers_bits: 3,
        }])
        .unwrap()
    }
    fn measured_catalog() -> Catalog {
        serde_json::from_str::<Option<Catalog>>(QUALIFIED_CATALOG_JSON)
            .unwrap()
            .expect("reviewed actual geometry catalog")
    }
    #[test]
    fn reviewed_catalog_qualifies_exact_development_geometry_only() {
        let value = measured_catalog();
        if retained_catalog_matches_current_sources_for_test() {
            validate_catalog(&value, &selected()).unwrap();
            require(&selected()).unwrap();
        } else {
            assert_ne!(value.sources, compiled_sources().unwrap());
            assert_eq!(
                validate_catalog(&value, &selected())
                    .unwrap_err()
                    .to_string(),
                "recovery geometry catalog differs from compiled sources or unchanged SMZE profile"
            );
            assert_eq!(
                require(&selected()).unwrap_err().to_string(),
                "recovery geometry catalog differs from compiled sources or unchanged SMZE profile"
            );
            eprintln!("inactive recovery source: retained reviewed catalog rejects current source closure; retained artifact pins only");
        }
        assert_eq!(value.cases.len(), 8);
        assert_eq!(value.measured_capsule_bundle_bytes, 3_574_186);
        assert_eq!(value.independent_review_receipt.path,
            ".agent/stablecoin-network-controls-v1/qualification/catalog/independent-review-v1.json");
        assert_eq!(
            value.independent_review_receipt.sha256,
            "7524c85e448113edd194bf6c6d92d5abb70b1cfb4ba9f505c8c3ba92dfeff8dd"
        );
    }
    #[test]
    fn qualified_catalog_rejects_source_role_profile_and_budget_mutants() {
        let selected = selected();
        let changes: &[fn(&mut Catalog)] = &[
            |v| v.sources.spend = "00".repeat(64),
            |v| v.sources.segments.swap(0, 1),
            |v| v.sources.files[0].sha256 = "00".repeat(32),
            |v| v.profile.decs_nb_opened_evals = 57,
            |v| v.credential_depth = 8,
            |v| v.wire_version += 1,
            |v| v.proof_units = 3,
            |v| v.max_component_bytes += 1,
            |v| v.max_actions_per_block = 2,
            |v| v.max_spend_action_bytes += 1,
            |v| v.cases.swap(0, 1),
            |v| v.cases[0].proof.dimensions.lvcs_cols = 0,
            |v| v.cases[0].proof.actual_outer_bytes = 2 * 1024 * 1024 + 1,
            |v| v.independent_review_receipt.sha256 = "0".repeat(64),
            |v| v.measured_capsule_bundle_bytes += 1,
        ];
        for change in changes {
            let mut bad = measured_catalog();
            change(&mut bad);
            assert!(validate_catalog(&bad, &selected).is_err());
        }
    }
    #[test]
    fn catalog_requires_review_and_cannot_add_production_authority_field() {
        let mut value: serde_json::Value = serde_json::from_str(QUALIFIED_CATALOG_JSON).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("independent_review_receipt");
        assert!(serde_json::from_value::<Catalog>(value).is_err());
        let mut value: serde_json::Value = serde_json::from_str(QUALIFIED_CATALOG_JSON).unwrap();
        value["production_authorized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Catalog>(value).is_err());
    }
    #[test]
    fn qualification_evidence_requires_exact_public_artifact_pins() {
        for (path, sha256) in [
            ("", "a".repeat(64)),
            ("../proof", "a".repeat(64)),
            ("proof", "0".repeat(64)),
            ("proof", "A".repeat(64)),
        ] {
            assert!(file_pin(&FilePin {
                path: path.into(),
                sha256
            })
            .is_err());
        }
        assert!(file_pin(&FilePin {
            path: "qualification/actual-proof.bin".into(),
            sha256: "a".repeat(64)
        })
        .is_ok());
    }
}
