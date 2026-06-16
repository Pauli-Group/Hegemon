import Hegemon.Transaction.SmallWoodSpendAuthorization

namespace Hegemon
namespace Transaction
namespace SmallWoodSpendAuthorization

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def surfacePreviousLimbs (surface : ActiveAuthLinkSurface) : List Nat :=
  [
    surface.previousAuth0,
    surface.previousAuth1,
    surface.previousAuth2,
    surface.previousAuth3
  ]

def surfaceDerivedLimbs (surface : ActiveAuthLinkSurface) : List Nat :=
  [
    surface.derivedAuth0,
    surface.derivedAuth1,
    surface.derivedAuth2,
    surface.derivedAuth3
  ]

def surfaceCommitmentLimbs (surface : ActiveAuthLinkSurface) : List Nat :=
  [
    surface.commitmentAuth0,
    surface.commitmentAuth1,
    surface.commitmentAuth2,
    surface.commitmentAuth3
  ]

def caseJson (name : String) (surface : ActiveAuthLinkSurface) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"active\": " ++ boolJson surface.active ++ ",\n"
    ++ "      \"previous_commitment_state_limbs\": "
    ++ natListJson (surfacePreviousLimbs surface) ++ ",\n"
    ++ "      \"spend_derived_auth_limbs\": "
    ++ natListJson (surfaceDerivedLimbs surface) ++ ",\n"
    ++ "      \"commitment_auth_limbs\": "
    ++ natListJson (surfaceCommitmentLimbs surface) ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (activeAuthLinkAccepted surface) ++ "\n"
    ++ "    }"

def spendBoundaryCaseJson
    (name : String)
    (surface : ActiveInputSpendBoundarySurface) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"active_flag\": " ++ toString surface.activeFlag ++ ",\n"
    ++ "      \"note_opening_commitment\": "
    ++ toString surface.noteOpeningCommitment ++ ",\n"
    ++ "      \"commitment_row_commitment\": "
    ++ toString surface.commitmentRowCommitment ++ ",\n"
    ++ "      \"public_nullifier\": "
    ++ toString surface.publicNullifier ++ ",\n"
    ++ "      \"nullifier_row\": "
    ++ toString surface.nullifierRow ++ ",\n"
    ++ "      \"public_merkle_root\": "
    ++ toString surface.publicMerkleRoot ++ ",\n"
    ++ "      \"merkle_root_row\": "
    ++ toString surface.merkleRootRow ++ ",\n"
    ++ "      \"nullifier_position\": "
    ++ toString surface.nullifierPosition ++ ",\n"
    ++ "      \"merkle_position\": "
    ++ toString surface.merklePosition ++ ",\n"
    ++ "      \"merkle_path_accepted\": "
    ++ boolJson surface.merklePathAccepted ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (activeInputSpendBoundaryAccepted surface) ++ "\n"
    ++ "    }"

def validNoWrap : ActiveAuthLinkSurface :=
  { active := true,
    previousAuth0 := 1,
    previousAuth1 := 2,
    previousAuth2 := 3,
    previousAuth3 := 4,
    derivedAuth0 := 10,
    derivedAuth1 := 20,
    derivedAuth2 := 30,
    derivedAuth3 := 40,
    commitmentAuth0 := 11,
    commitmentAuth1 := 22,
    commitmentAuth2 := 33,
    commitmentAuth3 := 44 }

def validWrap : ActiveAuthLinkSurface :=
  { active := true,
    previousAuth0 := goldilocksModulus - 1,
    previousAuth1 := goldilocksModulus - 2,
    previousAuth2 := 7,
    previousAuth3 := 11,
    derivedAuth0 := 1,
    derivedAuth1 := 7,
    derivedAuth2 := goldilocksModulus - 7,
    derivedAuth3 := 13,
    commitmentAuth0 := 0,
    commitmentAuth1 := 5,
    commitmentAuth2 := 0,
    commitmentAuth3 := 24 }

def mismatchLimb0 : ActiveAuthLinkSurface :=
  { validNoWrap with commitmentAuth0 := 12 }

def mismatchLimb1 : ActiveAuthLinkSurface :=
  { validNoWrap with commitmentAuth1 := 23 }

def mismatchLimb2 : ActiveAuthLinkSurface :=
  { validNoWrap with commitmentAuth2 := 34 }

def mismatchLimb3 : ActiveAuthLinkSurface :=
  { validNoWrap with commitmentAuth3 := 45 }

def inactiveMismatched : ActiveAuthLinkSurface :=
  { validNoWrap with
    active := false,
    commitmentAuth0 := 99,
    commitmentAuth1 := 98,
    commitmentAuth2 := 97,
    commitmentAuth3 := 96 }

def activeBoundaryValid : ActiveInputSpendBoundarySurface :=
  sampleActiveSpendBoundarySurface

def activeBoundaryCommitmentMismatch : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with commitmentRowCommitment := 56 }

def activeBoundaryNullifierMismatch : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with nullifierRow := 78 }

def activeBoundaryMerkleRootMismatch : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with merkleRootRow := 100 }

def activeBoundaryPositionMismatch : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with merklePosition := 4 }

def activeBoundaryMerklePathRejected : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with merklePathAccepted := false }

def inactiveBoundaryValid : ActiveInputSpendBoundarySurface :=
  sampleInactiveSpendBoundarySurface

def inactiveBoundaryPublicNullifierNonzero : ActiveInputSpendBoundarySurface :=
  { inactiveBoundaryValid with publicNullifier := 1 }

def inactiveBoundaryNullifierRowNonzero : ActiveInputSpendBoundarySurface :=
  { inactiveBoundaryValid with nullifierRow := 1 }

def boundaryMalformedFlag : ActiveInputSpendBoundarySurface :=
  { activeBoundaryValid with activeFlag := 2 }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"field_modulus\": " ++ toString goldilocksModulus ++ ",\n"
    ++ "  \"smallwood_spend_authorization_cases\": [\n"
    ++ caseJson "active-valid-no-wrap" validNoWrap ++ ",\n"
    ++ caseJson "active-valid-goldilocks-wrap" validWrap ++ ",\n"
    ++ caseJson "active-mismatched-limb-0-rejected" mismatchLimb0 ++ ",\n"
    ++ caseJson "active-mismatched-limb-1-rejected" mismatchLimb1 ++ ",\n"
    ++ caseJson "active-mismatched-limb-2-rejected" mismatchLimb2 ++ ",\n"
    ++ caseJson "active-mismatched-limb-3-rejected" mismatchLimb3 ++ ",\n"
    ++ caseJson "inactive-mismatched-limbs-accepted" inactiveMismatched ++ "\n"
    ++ "  ],\n"
    ++ "  \"smallwood_spend_boundary_cases\": [\n"
    ++ spendBoundaryCaseJson "active-boundary-valid" activeBoundaryValid ++ ",\n"
    ++ spendBoundaryCaseJson
      "active-boundary-commitment-mismatch-rejected"
      activeBoundaryCommitmentMismatch ++ ",\n"
    ++ spendBoundaryCaseJson
      "active-boundary-nullifier-mismatch-rejected"
      activeBoundaryNullifierMismatch ++ ",\n"
    ++ spendBoundaryCaseJson
      "active-boundary-merkle-root-mismatch-rejected"
      activeBoundaryMerkleRootMismatch ++ ",\n"
    ++ spendBoundaryCaseJson
      "active-boundary-position-mismatch-rejected"
      activeBoundaryPositionMismatch ++ ",\n"
    ++ spendBoundaryCaseJson
      "active-boundary-merkle-path-rejected"
      activeBoundaryMerklePathRejected ++ ",\n"
    ++ spendBoundaryCaseJson
      "inactive-boundary-zero-nullifier-valid"
      inactiveBoundaryValid ++ ",\n"
    ++ spendBoundaryCaseJson
      "inactive-boundary-public-nullifier-nonzero-rejected"
      inactiveBoundaryPublicNullifierNonzero ++ ",\n"
    ++ spendBoundaryCaseJson
      "inactive-boundary-nullifier-row-nonzero-rejected"
      inactiveBoundaryNullifierRowNonzero ++ ",\n"
    ++ spendBoundaryCaseJson
      "boundary-malformed-active-flag-rejected"
      boundaryMalformedFlag ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

end SmallWoodSpendAuthorization
end Transaction
end Hegemon

def main : IO Unit :=
  Hegemon.Transaction.SmallWoodSpendAuthorization.main
