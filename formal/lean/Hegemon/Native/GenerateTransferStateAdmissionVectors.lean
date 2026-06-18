import Hegemon.Native.TransferStateAdmission

open Hegemon.Native.TransferStateAdmission
open Hegemon
open Hegemon.Shielded

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullifierStateJson : TransferNullifierState -> String
  | TransferNullifierState.valid => "\"valid\""
  | TransferNullifierState.zero => "\"zero\""
  | TransferNullifierState.alreadySpent => "\"already_spent\""
  | TransferNullifierState.duplicate => "\"duplicate\""
  | TransferNullifierState.alreadyPending => "\"already_pending\""

def rejectionJson : Option TransferStateReject -> String
  | none => "null"
  | some TransferStateReject.unknownAnchor => "\"unknown_anchor\""
  | some TransferStateReject.nullifierZero => "\"nullifier_zero\""
  | some TransferStateReject.nullifierAlreadySpent =>
      "\"nullifier_already_spent\""
  | some TransferStateReject.duplicateNullifier => "\"duplicate_nullifier\""
  | some TransferStateReject.nullifierAlreadyPending =>
      "\"nullifier_already_pending\""
  | some TransferStateReject.commitmentZero => "\"commitment_zero\""
  | some TransferStateReject.stablecoinPolicyUnauthorized =>
      "\"stablecoin_policy_unauthorized\""
  | some TransferStateReject.sidecarCiphertextMissing =>
      "\"sidecar_ciphertext_missing\""
  | some TransferStateReject.sidecarCiphertextSizeMissing =>
      "\"sidecar_ciphertext_size_missing\""
  | some TransferStateReject.sidecarCiphertextSizeMismatch =>
      "\"sidecar_ciphertext_size_mismatch\""

def commaJoin : List String -> String
  | [] => ""
  | [value] => value
  | value :: rest => value ++ ", " ++ commaJoin rest

def quotedHexListJson (values : List Nullifier) : String :=
  commaJoin (values.map fun value => "\"" ++ hexBytes value ++ "\"")

def transferStateCaseJson (name : String) (input : TransferStateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"anchor_known\": " ++ boolJson input.anchorKnown ++ ",\n"
    ++ "      \"nullifier_state\": "
      ++ nullifierStateJson input.nullifierState ++ ",\n"
    ++ "      \"commitments_nonzero\": " ++ boolJson input.commitmentsNonzero ++ ",\n"
    ++ "      \"stablecoin_policy_authorized\": "
      ++ boolJson input.stablecoinPolicyAuthorized ++ ",\n"
    ++ "      \"sidecar_route\": " ++ boolJson input.sidecarRoute ++ ",\n"
    ++ "      \"sidecar_ciphertexts_available\": "
      ++ boolJson input.sidecarCiphertextsAvailable ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson input.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson input.sidecarCiphertextSizesMatch ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (transferStateAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (transferStateRejection input) ++ "\n"
    ++ "    }"

def transferNullifierRowsCaseJson
    (name : String)
    (input : TransferNullifierRowsInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"spent_nullifiers\": ["
      ++ quotedHexListJson input.spent ++ "],\n"
    ++ "      \"pending_nullifiers\": ["
      ++ quotedHexListJson input.pending ++ "],\n"
    ++ "      \"action_nullifiers\": ["
      ++ quotedHexListJson input.action ++ "],\n"
    ++ "      \"expected_mempool_nullifier_state\": "
      ++ nullifierStateJson (deriveMempoolNullifierState input) ++ ",\n"
    ++ "      \"expected_block_nullifier_state\": "
      ++ nullifierStateJson (deriveBlockNullifierState input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"transfer_state_admission_cases\": [\n"
    ++ transferStateCaseJson "valid-sidecar-transfer-state"
      validTransferState ++ ",\n"
    ++ transferStateCaseJson "valid-inline-transfer-state"
      { validTransferState with sidecarRoute := false } ++ ",\n"
    ++ transferStateCaseJson "unknown-anchor-rejected"
      { validTransferState with anchorKnown := false } ++ ",\n"
    ++ transferStateCaseJson "zero-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.zero } ++ ",\n"
    ++ transferStateCaseJson "already-spent-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.alreadySpent } ++ ",\n"
    ++ transferStateCaseJson "duplicate-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.duplicate } ++ ",\n"
    ++ transferStateCaseJson "already-pending-nullifier-rejected"
      { validTransferState with
        nullifierState := TransferNullifierState.alreadyPending } ++ ",\n"
    ++ transferStateCaseJson "zero-commitment-rejected"
      { validTransferState with commitmentsNonzero := false } ++ ",\n"
    ++ transferStateCaseJson "unauthorized-stablecoin-policy-rejected"
      { validTransferState with stablecoinPolicyAuthorized := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-missing-rejected"
      { validTransferState with sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-size-missing-rejected"
      { validTransferState with sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ transferStateCaseJson "sidecar-ciphertext-size-mismatch-rejected"
      { validTransferState with sidecarCiphertextSizesMatch := false } ++ ",\n"
    ++ transferStateCaseJson "unknown-anchor-precedes-nullifier"
      { validTransferState with
        anchorKnown := false,
        nullifierState := TransferNullifierState.zero } ++ ",\n"
    ++ transferStateCaseJson "nullifier-precedes-zero-commitment"
      { validTransferState with
        nullifierState := TransferNullifierState.duplicate,
        commitmentsNonzero := false } ++ ",\n"
    ++ transferStateCaseJson "commitment-precedes-stablecoin-policy"
      { validTransferState with
        commitmentsNonzero := false,
        stablecoinPolicyAuthorized := false } ++ ",\n"
    ++ transferStateCaseJson "stablecoin-policy-precedes-sidecar"
      { validTransferState with
        stablecoinPolicyAuthorized := false,
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false,
        sidecarCiphertextSizesMatch := false } ++ ",\n"
    ++ transferStateCaseJson "inline-ignores-sidecar-availability"
      { validTransferState with
        sidecarRoute := false,
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false,
        sidecarCiphertextSizesMatch := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"transfer_nullifier_row_cases\": [\n"
    ++ transferNullifierRowsCaseJson "fresh-single-nullifier-valid"
      { spent := [],
        pending := [],
        action := [sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "zero-nullifier-precedes-spent-pending"
      { spent := [sampleNullifierA],
        pending := [sampleNullifierB],
        action := [zeroNullifier, sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "prior-spent-mempool-spent-block-duplicate"
      { spent := [sampleNullifierA],
        pending := [],
        action := [sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "prior-pending-mempool-pending-block-valid"
      { spent := [],
        pending := [sampleNullifierA],
        action := [sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "same-action-duplicate-nullifier"
      { spent := [],
        pending := [],
        action := [sampleNullifierA, sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "prior-pending-precedes-action-duplicate"
      { spent := [],
        pending := [sampleNullifierA],
        action := [sampleNullifierA, sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "pending-middle-precedes-later-duplicate"
      { spent := [],
        pending := [sampleNullifierB],
        action := [sampleNullifierA, sampleNullifierB, sampleNullifierA] } ++ ",\n"
    ++ transferNullifierRowsCaseJson "spent-after-fresh-prefix-rejects"
      { spent := [sampleNullifierA],
        pending := [],
        action := [sampleNullifierB, sampleNullifierA] } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
