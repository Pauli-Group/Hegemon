import Hegemon.Native.ResourceBudgetAdmission

open Hegemon.Native.ResourceBudgetAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natJson (value : Nat) : String :=
  toString value

def rejectionJson : Option BudgetReject -> String
  | none => "null"
  | some BudgetReject.mempoolByteBudgetExceeded => "\"mempool_byte_budget_exceeded\""
  | some BudgetReject.stagedProofByteBudgetExceeded =>
      "\"staged_proof_byte_budget_exceeded\""

def mempoolCaseJson (name : String) (input : MempoolBudgetInput) : String :=
  let result := evaluateMempoolBudgetRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"pending_bytes\": " ++ natJson input.pendingBytes ++ ",\n"
    ++ "      \"candidate_bytes\": " ++ natJson input.candidateBytes ++ ",\n"
    ++ "      \"max_bytes\": " ++ natJson input.maxBytes ++ ",\n"
    ++ "      \"expected_total_bytes\": " ++ natJson (mempoolBudgetTotal input) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def stagedProofCaseJson (name : String) (input : StagedProofBudgetInput) : String :=
  let result := evaluateStagedProofBudgetRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"staged_bytes\": " ++ natJson input.stagedBytes ++ ",\n"
    ++ "      \"existing_bytes\": " ++ natJson input.existingBytes ++ ",\n"
    ++ "      \"proof_bytes\": " ++ natJson input.proofBytes ++ ",\n"
    ++ "      \"max_bytes\": " ++ natJson input.maxBytes ++ ",\n"
    ++ "      \"expected_total_bytes\": " ++ natJson (stagedProofBudgetTotal input) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def mempoolEmptyInput : MempoolBudgetInput :=
  {
    pendingBytes := 0,
    candidateBytes := 4,
    maxBytes := 4
  }

def mempoolSaturatedExactInput : MempoolBudgetInput :=
  {
    pendingBytes := usizeMax,
    candidateBytes := 1,
    maxBytes := usizeMax
  }

def stagedProofNoExistingInput : StagedProofBudgetInput :=
  {
    stagedBytes := 3,
    existingBytes := 0,
    proofBytes := 2,
    maxBytes := 5
  }

def stagedProofReplacementOverLimitInput : StagedProofBudgetInput :=
  {
    stagedBytes := 6,
    existingBytes := 4,
    proofBytes := 4,
    maxBytes := 5
  }

def stagedProofSaturatedExactInput : StagedProofBudgetInput :=
  {
    stagedBytes := usizeMax,
    existingBytes := 0,
    proofBytes := 1,
    maxBytes := usizeMax
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"mempool_budget_cases\": [\n"
    ++ mempoolCaseJson "mempool-empty-exact-limit" mempoolEmptyInput ++ ",\n"
    ++ mempoolCaseJson "mempool-exact-limit" mempoolExactLimitInput ++ ",\n"
    ++ mempoolCaseJson "mempool-over-limit-rejected" mempoolOverLimitInput ++ ",\n"
    ++ mempoolCaseJson "mempool-saturated-overflow-rejected"
      mempoolSaturatedOverflowInput ++ ",\n"
    ++ mempoolCaseJson "mempool-saturated-exact-cap-accepted"
      mempoolSaturatedExactInput ++ "\n"
    ++ "  ],\n"
    ++ "  \"staged_proof_budget_cases\": [\n"
    ++ stagedProofCaseJson "staged-proof-no-existing-exact-limit"
      stagedProofNoExistingInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-over-limit-rejected"
      stagedProofOverLimitInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-replacement-subtracts-existing"
      stagedProofReplacementInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-replacement-over-limit-rejected"
      stagedProofReplacementOverLimitInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-existing-overcount-saturates"
      stagedProofExistingOvercountInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-saturated-overflow-rejected"
      stagedProofSaturatedOverflowInput ++ ",\n"
    ++ stagedProofCaseJson "staged-proof-saturated-exact-cap-accepted"
      stagedProofSaturatedExactInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
