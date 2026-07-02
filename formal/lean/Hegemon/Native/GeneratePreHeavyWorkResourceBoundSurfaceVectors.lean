import Hegemon.Native.PreHeavyWorkResourceBoundSurface

namespace Hegemon
namespace Native
namespace PreHeavyWorkResourceBoundSurface

open Hegemon.Native.ResourceBudgetAdmission
open Hegemon.Native.SidecarUploadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def stageJson : Option String -> String
  | none => "null"
  | some stage => "\"" ++ stage ++ "\""

def sidecarRejectJson : SidecarUploadReject -> String
  | SidecarUploadReject.tooManyCiphertexts => "too_many_ciphertexts"
  | SidecarUploadReject.tooManyProofs => "too_many_proofs"
  | SidecarUploadReject.stagedCiphertextCapacityReached =>
      "staged_ciphertext_capacity_reached"
  | SidecarUploadReject.stagedProofCapacityReached =>
      "staged_proof_capacity_reached"
  | SidecarUploadReject.proofBindingHashMissing =>
      "proof_binding_hash_missing"
  | SidecarUploadReject.invalidBindingHash => "invalid_binding_hash"
  | SidecarUploadReject.proofMissing => "proof_missing"
  | SidecarUploadReject.proofEmpty => "proof_empty"
  | SidecarUploadReject.proofTooLarge => "proof_too_large"
  | SidecarUploadReject.proofBindingHashMismatch =>
      "proof_binding_hash_mismatch"

def budgetRejectJson : BudgetReject -> String
  | BudgetReject.mempoolByteBudgetExceeded =>
      "mempool_byte_budget_exceeded"
  | BudgetReject.stagedProofByteBudgetExceeded =>
      "staged_proof_byte_budget_exceeded"

def preHeavyRejectJson :
    Except StagedProofUploadPreHeavyReject Unit -> Option (String × String)
  | Except.ok _ => none
  | Except.error reject =>
      match reject with
      | StagedProofUploadPreHeavyReject.metadata sidecarReject =>
          some ("metadata", sidecarRejectJson sidecarReject)
      | StagedProofUploadPreHeavyReject.stagedProofBudget budgetReject =>
          some ("staged_proof_budget", budgetRejectJson budgetReject)
      | StagedProofUploadPreHeavyReject.decoded sidecarReject =>
          some ("decoded", sidecarRejectJson sidecarReject)

def rejectionStage
    (result : Except StagedProofUploadPreHeavyReject Unit) : Option String :=
  match preHeavyRejectJson result with
  | none => none
  | some pair => some pair.fst

def rejectionLabel
    (result : Except StagedProofUploadPreHeavyReject Unit) : Option String :=
  match preHeavyRejectJson result with
  | none => none
  | some pair => some pair.snd

def preHeavyAccepts
    (result : Except StagedProofUploadPreHeavyReject Unit) : Bool :=
  match result with
  | Except.ok _ => true
  | Except.error _ => false

def stagedProofUploadPreHeavyCaseJson
    (name : String)
    (input : StagedProofUploadPreHeavyInput) : String :=
  let result := evaluateStagedProofUploadPreHeavy input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"binding_hash_present\": "
      ++ boolJson input.proofMetadata.bindingHashPresent ++ ",\n"
    ++ "      \"binding_hash_valid\": "
      ++ boolJson input.proofMetadata.bindingHashValid ++ ",\n"
    ++ "      \"proof_present\": "
      ++ boolJson input.proofMetadata.proofPresent ++ ",\n"
    ++ "      \"staged_bytes\": "
      ++ toString input.stagedProofBudget.stagedBytes ++ ",\n"
    ++ "      \"existing_bytes\": "
      ++ toString input.stagedProofBudget.existingBytes ++ ",\n"
    ++ "      \"proof_bytes\": "
      ++ toString input.stagedProofBudget.proofBytes ++ ",\n"
    ++ "      \"max_bytes\": "
      ++ toString input.stagedProofBudget.maxBytes ++ ",\n"
    ++ "      \"expected_total_bytes\": "
      ++ toString (stagedProofBudgetTotal input.stagedProofBudget) ++ ",\n"
    ++ "      \"decoded_proof_bytes\": "
      ++ toString input.proofDecoded.proofBytes ++ ",\n"
    ++ "      \"decoded_max_proof_bytes\": "
      ++ toString input.proofDecoded.maxProofBytes ++ ",\n"
    ++ "      \"proof_binding_hash_matches_key\": "
      ++ boolJson input.proofDecoded.proofBindingHashMatchesKey ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (preHeavyAccepts result) ++ ",\n"
    ++ "      \"expected_rejection_stage\": "
      ++ stageJson (rejectionStage result) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ stageJson (rejectionLabel result) ++ "\n"
    ++ "    }"

def metadataPrecedesBudgetInput : StagedProofUploadPreHeavyInput :=
  {
    stagedProofBudgetPrecedesBindingMismatchInput with
    proofMetadata := {
      validProofMetadata with
      bindingHashPresent := false
    }
  }

def decodedBindingMismatchAfterBudgetAcceptInput :
    StagedProofUploadPreHeavyInput :=
  {
    validStagedProofUploadPreHeavyInput with
    proofDecoded := {
      validProofDecoded with
      proofBindingHashMatchesKey := false
    }
  }

def decodedOversizeAfterBudgetAcceptInput :
    StagedProofUploadPreHeavyInput :=
  {
    validStagedProofUploadPreHeavyInput with
    proofDecoded := {
      validProofDecoded with
      proofBytes := validProofDecoded.maxProofBytes + 1
    }
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"staged_proof_upload_preheavy_cases\": [\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "valid-staged-proof-upload-preheavy"
      validStagedProofUploadPreHeavyInput ++ ",\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "metadata-precedes-staged-proof-budget"
      metadataPrecedesBudgetInput ++ ",\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "staged-proof-budget-precedes-binding-mismatch"
      stagedProofBudgetPrecedesBindingMismatchInput ++ ",\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "staged-proof-budget-precedes-decoded-oversize"
      stagedProofBudgetPrecedesDecodedOversizeInput ++ ",\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "decoded-binding-mismatch-after-budget-accept"
      decodedBindingMismatchAfterBudgetAcceptInput ++ ",\n"
    ++ stagedProofUploadPreHeavyCaseJson
      "decoded-oversize-after-budget-accept"
      decodedOversizeAfterBudgetAcceptInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

end PreHeavyWorkResourceBoundSurface
end Native
end Hegemon

def main : IO Unit :=
  Hegemon.Native.PreHeavyWorkResourceBoundSurface.main
